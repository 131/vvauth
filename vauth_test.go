package vvauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	sshagentcrypt "github.com/131/ssh-agent-crypt"
	vauthlogin "github.com/131/vauth-login"
)

const hour = 60 * 60

// agentSocket is a throwaway ssh-agent holding one ed25519 key.
var agentSocket string

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "vvauth-agent-")
	if err != nil {
		panic(err)
	}
	key := filepath.Join(directory, "key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		panic(fmt.Sprintf("ssh-keygen: %v %s", err, out))
	}
	out, err := exec.Command("ssh-agent", "-s").Output()
	if err != nil {
		panic(err)
	}
	agentSocket = regexp.MustCompile(`SSH_AUTH_SOCK=([^;]+)`).FindStringSubmatch(string(out))[1]
	pid := regexp.MustCompile(`SSH_AGENT_PID=(\d+)`).FindStringSubmatch(string(out))[1]
	add := exec.Command("ssh-add", key)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+agentSocket)
	if out, err := add.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("ssh-add: %v %s", err, out))
	}
	// ssh-agent-crypt falls back to these for key selection; the real user's
	// identity is not in the throwaway agent.
	for _, name := range []string{"SSH_AGENT_CRYPT_KEY", "VAUTH_USER_IDENTITY", "VAUTH_USER_MAIL"} {
		os.Unsetenv(name)
	}
	code := m.Run()
	exec.Command("kill", pid).Run()
	os.RemoveAll(directory)
	os.Exit(code)
}

type request struct {
	Path, Method, Token, Body string
}

type fixtureOptions struct {
	ttl          *float64
	renewable    *bool
	creationTTL  *int64
	lookupStatus int
	renewStatus  int
	metadata     map[string]any
	database     map[string]any
	secrets      map[string]any
}

func seconds(value float64) *float64 { return &value }
func boolean(value bool) *bool       { return &value }

type fixture struct {
	t        *testing.T
	server   *httptest.Server
	dir      string
	requests []request
	options  fixtureOptions
}

func newFixture(t *testing.T, options fixtureOptions) *fixture {
	f := &fixture{t: t, dir: t.TempDir(), options: options}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.requests = append(f.requests, request{r.URL.Path, r.Method, r.Header.Get("X-Vault-Token"), string(body)})
		w.Header().Set("Content-Type", "application/json")
		status := func(code int) {
			if code != 0 {
				w.WriteHeader(code)
			}
		}
		switch r.URL.Path {
		case "/v1/auth/jwt/login":
			fmt.Fprintf(w, `{"auth":{"client_token":"fresh-token","lease_duration":%d,"renewable":true}}`, 24*hour)
		case "/v1/auth/token/lookup-self":
			status(options.lookupStatus)
			ttl, renewable, creation := float64(12*hour), true, int64(24*hour)
			if options.ttl != nil {
				ttl = *options.ttl
			}
			if options.renewable != nil {
				renewable = *options.renewable
			}
			if options.creationTTL != nil {
				creation = *options.creationTTL
			}
			fmt.Fprintf(w, `{"data":{"ttl":%v,"renewable":%v,"creation_ttl":%d,"entity_id":"test-entity"}}`, ttl, renewable, creation)
		case "/v1/auth/token/renew-self":
			status(options.renewStatus)
			fmt.Fprintf(w, `{"auth":{"client_token":%q,"lease_duration":%d,"renewable":true}}`, r.Header.Get("X-Vault-Token"), 24*hour)
		case "/v1/identity/entity/id/test-entity":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"metadata": options.metadata}})
		case "/v1/private/alice/data/.vauth_database":
			if r.Method == "POST" {
				var payload struct {
					Data map[string]any `json:"data"`
				}
				json.Unmarshal(body, &payload)
				f.options.database = payload.Data
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": f.options.database}})
		case "/v1/secrets/data/app":
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": options.secrets}})
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, `{}`)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

// client avoids the real user's environment, configuration and cache.
func (f *fixture) client() *Vauth {
	return &Vauth{Vauth: &vauthlogin.Vauth{
		RC:         vauthlogin.RC{JWTAuth: &vauthlogin.JWTAuth{Path: "jwt", JWT: "test-jwt", Role: "test-role"}},
		VaultAddr:  f.server.URL,
		Agent:      agentSocket,
		TokenCache: true,
		CacheDir:   filepath.Join(f.dir, ".vauth", "tokens"),
		Environ:    map[string]string{},
		Stderr:     io.Discard,
	}}
}

// Fixture data follows the shared cache format; the application owns no cache code.
type tokenCache struct {
	Token         string `json:"token"`
	LeaseDuration int64  `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
	ExpiresAt     *int64 `json:"expires_at"`
}

func testCacheKey(v *Vauth) string {
	key := `{"vault_addr":` + string(jsonString(strings.Trim(v.VaultAddr, "/")))
	if auth := v.RC.AuthKey(); auth != "" {
		key += "," + auth
	}
	return sha256Hex(key + "}")
}

func cacheFile(v *Vauth) string { return filepath.Join(v.CacheDir, testCacheKey(v)+".creds") }

func (f *fixture) paths() []string {
	var paths []string
	for _, r := range f.requests {
		paths = append(paths, r.Path)
	}
	return paths
}

func (f *fixture) read(v *Vauth) tokenCache {
	f.t.Helper()
	armor, err := os.ReadFile(cacheFile(v))
	if err != nil {
		f.t.Fatal(err)
	}
	body, err := sshagentcrypt.Decrypt(armor, "", &sshagentcrypt.Options{AgentSocket: agentSocket})
	if err != nil {
		f.t.Fatal(err)
	}
	var cache tokenCache
	if err := json.Unmarshal(body, &cache); err != nil {
		f.t.Fatal(err)
	}
	return cache
}

func (f *fixture) write(v *Vauth, cache tokenCache) {
	f.t.Helper()
	body, err := json.Marshal(cache)
	if err != nil {
		f.t.Fatal(err)
	}
	armor, err := sshagentcrypt.Encrypt(body, "", &sshagentcrypt.Options{AgentSocket: agentSocket})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.MkdirAll(v.CacheDir, 0700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(cacheFile(v), []byte(armor), 0600); err != nil {
		f.t.Fatal(err)
	}
}

// remaining rewrites the cached expiry so that ttl seconds remain (0: unlimited).
func (f *fixture) remaining(v *Vauth, ttl float64) {
	cache := f.read(v)
	cache.ExpiresAt = nil
	if ttl != 0 {
		expires := time.Now().UnixMilli() + int64(ttl*1000)
		cache.ExpiresAt = &expires
	}
	f.write(v, cache)
}

func (f *fixture) seed(v *Vauth, lease int64) {
	renewable := f.options.renewable == nil || *f.options.renewable
	expires := time.Now().UnixMilli() + lease*1000
	f.write(v, tokenCache{Token: "cached-token", LeaseDuration: lease, Renewable: renewable, ExpiresAt: &expires})
	if f.options.ttl != nil {
		f.remaining(v, *f.options.ttl)
	}
}

func connect(t *testing.T, v *Vauth, renew bool) string {
	t.Helper()
	token, err := v.Connect(renew)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func equal[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func equalPaths(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("requests %v, want %v", got, want)
	}
}

func TestLoginPersistsAndReuses(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	first := f.client()
	equal(t, connect(t, first, false), "fresh-token")
	cache := f.read(first)
	equal(t, cache.Token, "fresh-token")
	if cache.ExpiresAt == nil || *cache.ExpiresAt < time.Now().UnixMilli()+23*hour*1000 {
		t.Fatalf("expires_at %v", cache.ExpiresAt)
	}
	info, _ := os.Stat(cacheFile(first))
	equal(t, info.Mode().Perm(), 0o600)
	info, _ = os.Stat(filepath.Dir(cacheFile(first)))
	equal(t, info.Mode().Perm(), 0o700)
	second := f.client()
	equal(t, connect(t, second, false), "fresh-token")
	equalPaths(t, f.paths(), "/v1/auth/jwt/login")
	entries, _ := os.ReadDir(filepath.Dir(cacheFile(first)))
	equal(t, len(entries), 1)
}

func TestLastThirdRenewsAndSaves(t *testing.T) {
	f := newFixture(t, fixtureOptions{ttl: seconds(hour)})
	v := f.client()
	f.seed(v, 12*hour)
	equal(t, connect(t, v, false), "cached-token")
	equalPaths(t, f.paths(), "/v1/auth/token/renew-self")
	equal(t, f.requests[0].Method, "POST")
	equal(t, f.requests[0].Token, "cached-token")
	if *f.read(v).ExpiresAt < time.Now().UnixMilli()+23*hour*1000 {
		t.Fatal("renewed expiry not saved")
	}
}

func TestMoreThanOneThirdNoRenewal(t *testing.T) {
	f := newFixture(t, fixtureOptions{ttl: seconds(4*hour + 1)})
	v := f.client()
	f.seed(v, 12*hour)
	equal(t, connect(t, v, false), "cached-token")
	equal(t, len(f.requests), 0)
}

func TestExpiredCacheReplaced(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	f.seed(v, 12*hour)
	f.remaining(v, -1)
	equal(t, connect(t, v, false), "fresh-token")
	equal(t, f.read(v).Token, "fresh-token")
	equalPaths(t, f.paths(), "/v1/auth/jwt/login")
}

func TestCachedTokensReusedWithoutRevocationCheck(t *testing.T) {
	f := newFixture(t, fixtureOptions{lookupStatus: 403})
	v := f.client()
	f.seed(v, 12*hour)
	equal(t, connect(t, v, false), "cached-token")
	equal(t, len(f.requests), 0)
	if _, err := v.LookupSelf(v.VaultToken); err == nil {
		t.Fatal("lookup should fail")
	}
}

func TestNonRenewableNearingExpiryReauthenticates(t *testing.T) {
	f := newFixture(t, fixtureOptions{ttl: seconds(hour), renewable: boolean(false)})
	v := f.client()
	f.seed(v, 12*hour)
	equal(t, connect(t, v, false), "fresh-token")
	equalPaths(t, f.paths(), "/v1/auth/jwt/login")
}

func TestRejectedRenewalTriggersLogin(t *testing.T) {
	for _, status := range []int{400, 403} {
		f := newFixture(t, fixtureOptions{ttl: seconds(hour), renewStatus: status})
		v := f.client()
		f.seed(v, 12*hour)
		equal(t, connect(t, v, false), "fresh-token")
		equal(t, f.read(v).Token, "fresh-token")
		equalPaths(t, f.paths(), "/v1/auth/token/renew-self", "/v1/auth/jwt/login")
	}
}

func TestServerFailuresDoNotGenerateTokens(t *testing.T) {
	f := newFixture(t, fixtureOptions{lookupStatus: 500})
	v := f.client()
	f.seed(v, 12*hour)
	v.VaultToken = "uncached-token"
	for i := 0; i < 2; i++ {
		if _, err := v.LookupSelf(v.VaultToken); err == nil {
			t.Fatal("lookup should fail")
		}
	}
	equalPaths(t, f.paths(), "/v1/auth/token/lookup-self", "/v1/auth/token/lookup-self")

	f = newFixture(t, fixtureOptions{ttl: seconds(hour), renewStatus: 500})
	v = f.client()
	f.seed(v, 12*hour)
	if _, err := v.Connect(false); err == nil {
		t.Fatal("connect should fail")
	}
	equalPaths(t, f.paths(), "/v1/auth/token/renew-self")
}

func TestInheritedTokenIsOfflineAndNotCached(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	f.seed(v, 12*hour)
	v.VaultToken = "environment-token"
	equal(t, connect(t, v, false), "environment-token")
	equal(t, f.read(v).Token, "cached-token")
	equal(t, len(f.requests), 0)
}

func TestNonExpiringTokensReused(t *testing.T) {
	f := newFixture(t, fixtureOptions{ttl: seconds(0)})
	v := f.client()
	f.seed(v, 0)
	equal(t, connect(t, v, false), "cached-token")
	if f.read(v).ExpiresAt != nil {
		t.Fatal("expires_at should be null")
	}
	equal(t, len(f.requests), 0)
}

func TestCorruptCacheReplaced(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	os.MkdirAll(filepath.Dir(cacheFile(v)), 0o700)
	os.WriteFile(cacheFile(v), []byte("{broken"), 0o600)
	equal(t, connect(t, v, false), "fresh-token")
	equal(t, f.read(v).Token, "fresh-token")
}

func TestPlaintextCacheNotAccepted(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	os.MkdirAll(filepath.Dir(cacheFile(v)), 0o700)
	os.WriteFile(cacheFile(v), []byte(`{"token":"plain-token","lease_duration":43200,"renewable":true,"expires_at":null}`), 0o600)
	equal(t, connect(t, v, false), "fresh-token")
	equalPaths(t, f.paths(), "/v1/auth/jwt/login")
}

func TestCacheIsolation(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	first := f.client()
	f.seed(first, 12*hour)
	second := f.client()
	second.RC.JWTAuth.Role = "other-role"
	equal(t, connect(t, second, false), "fresh-token")
	if cacheFile(first) == cacheFile(second) {
		t.Fatal("cache files should differ")
	}
	equal(t, f.read(first).Token, "cached-token")
	equal(t, f.read(second).Token, "fresh-token")
	third := f.client()
	third.VaultAddr = "http://other-vault.test"
	if testCacheKey(third) == testCacheKey(first) {
		t.Fatal("cache keys should differ")
	}
	entries, _ := os.ReadDir(filepath.Dir(cacheFile(first)))
	equal(t, len(entries), 2)
	armor, _ := os.ReadFile(cacheFile(first))
	if bytes.Contains(armor, []byte("test-jwt")) || bytes.Contains(armor, []byte("cached-token")) {
		t.Fatal("cache leaks secrets")
	}
}

func TestTokenCacheKeyMatchesNode(t *testing.T) {
	// sha256 of JSON.stringify({vault_addr, ssh_auth, jwt_auth}) as the Node
	// implementation renders it (undefined members omitted).
	v := &Vauth{Vauth: &vauthlogin.Vauth{VaultAddr: "https://vault.example.test/", RC: vauthlogin.RC{SSHAuth: &vauthlogin.SSHAuth{Role: "alice"}}}}
	equal(t, testCacheKey(v), sha256Hex(`{"vault_addr":"https://vault.example.test","ssh_auth":{"role":"alice"}}`))
	v = &Vauth{Vauth: &vauthlogin.Vauth{VaultAddr: "https://vault.example.test", RC: vauthlogin.RC{JWTAuth: &vauthlogin.JWTAuth{Path: "jwt", JWT: "x", Role: "r"}}}}
	equal(t, testCacheKey(v), sha256Hex(`{"vault_addr":"https://vault.example.test","jwt_auth":{"path":"jwt","jwt":"x","role":"r"}}`))
	rc, err := vauthlogin.ParseRC([]byte("vault_addr: https://vault.example.test\nssh_auth:\n  role: $${env.USER}\n"), ".vauthrc", map[string]string{"USER": "bob"})
	if err != nil {
		t.Fatal(err)
	}
	v = &Vauth{Vauth: &vauthlogin.Vauth{VaultAddr: rc.VaultAddr, RC: *rc}}
	equal(t, testCacheKey(v), sha256Hex(`{"vault_addr":"https://vault.example.test","ssh_auth":{"role":"bob"}}`))
}

func TestRepeatedConnectReusesConnection(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	equal(t, connect(t, v, false), "fresh-token")
	equal(t, connect(t, v, false), "fresh-token")
	equal(t, len(f.requests), 1)
}

func TestUnwritableCacheDoesNotPreventLogin(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	os.MkdirAll(filepath.Dir(filepath.Dir(cacheFile(v))), 0o700)
	os.WriteFile(filepath.Dir(cacheFile(v)), []byte("not a directory"), 0o600)
	var stderr bytes.Buffer
	v.Stderr = &stderr
	equal(t, connect(t, v, false), "fresh-token")
	if !strings.Contains(stderr.String(), "token not persisted") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func TestWithoutAuthMethodInheritanceStillWorks(t *testing.T) {
	f := newFixture(t, fixtureOptions{lookupStatus: 403})
	v := f.client()
	f.seed(v, 12*hour)
	v.RC = vauthlogin.RC{}
	v.VaultToken = "uncached-token"
	equal(t, connect(t, v, false), "uncached-token")
	equal(t, v.VaultToken, "uncached-token")
	equal(t, connect(t, v, true), "")
	equal(t, len(f.requests), 0)
}

func TestRenewIgnoresTokensAndSaves(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	f.seed(v, 12*hour)
	v.VaultToken = "environment-token"
	equal(t, connect(t, v, true), "fresh-token")
	equalPaths(t, f.paths(), "/v1/auth/jwt/login")
	equal(t, f.read(v).Token, "fresh-token")

	f = newFixture(t, fixtureOptions{})
	v = f.client()
	f.seed(v, 12*hour)
	connect(t, v, false)
	equal(t, connect(t, v, true), "fresh-token")
	equal(t, connect(t, v, true), "fresh-token")
	equalPaths(t, f.paths(), "/v1/auth/jwt/login", "/v1/auth/jwt/login")
}

func TestProportionalThreshold(t *testing.T) {
	for _, c := range []struct {
		lease     int64
		remaining float64
		renew     bool
	}{
		{24 * hour, 8 * hour, true}, {24 * hour, 8*hour + 1, false},
		{hour, 20 * 60, true}, {hour, 20*60 + 1, false},
		{60, 20, true}, {60, 21, false},
	} {
		f := newFixture(t, fixtureOptions{ttl: seconds(c.remaining)})
		v := f.client()
		f.seed(v, c.lease)
		connect(t, v, false)
		renewed := strings.Contains(strings.Join(f.paths(), " "), "/renew-self")
		if renewed != c.renew {
			t.Fatalf("lease=%d remaining=%v renewed=%v", c.lease, c.remaining, renewed)
		}
		want := c.lease
		if c.renew {
			want = 24 * hour
		}
		equal(t, f.read(v).LeaseDuration, want)
	}
}

func TestLookupsNeverResetLease(t *testing.T) {
	f := newFixture(t, fixtureOptions{ttl: seconds(20 * hour)})
	v := f.client()
	f.seed(v, 24*hour)
	connect(t, v, false)
	equal(t, f.read(v).LeaseDuration, 24*hour)
	f.remaining(v, 12*hour)
	connect(t, f.client(), false)
	equal(t, f.read(v).LeaseDuration, 24*hour)
	f.remaining(v, 8*hour)
	connect(t, f.client(), false)
	equal(t, strings.Count(strings.Join(f.paths(), " "), "/renew-self"), 1)
}

func TestRenewalUpdatesLeaseBaseline(t *testing.T) {
	f := newFixture(t, fixtureOptions{ttl: seconds(20 * 60)})
	v := f.client()
	f.seed(v, hour)
	connect(t, v, false)
	equal(t, f.read(v).LeaseDuration, 24*hour)
	f.remaining(v, 8*hour)
	connect(t, f.client(), false)
	equal(t, strings.Count(strings.Join(f.paths(), " "), "/renew-self"), 2)
}

func TestNormalReuseNeverWrites(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	f.seed(v, 12*hour)
	v.VaultToken = "cached-token"
	before, _ := os.ReadFile(cacheFile(v))
	stat, _ := os.Stat(cacheFile(v))
	equal(t, connect(t, v, false), "cached-token")
	after, _ := os.ReadFile(cacheFile(v))
	if !bytes.Equal(before, after) {
		t.Fatal("cache rewritten")
	}
	again, _ := os.Stat(cacheFile(v))
	equal(t, again.ModTime(), stat.ModTime())
	equal(t, len(f.requests), 0)
}

func TestLookupReturnsLease(t *testing.T) {
	f := newFixture(t, fixtureOptions{ttl: seconds(hour)})
	v := f.client()
	info, err := v.LookupSelf("environment-token")
	if err != nil {
		t.Fatal(err)
	}
	equal(t, info.LeaseDuration, 24*hour)
	equal(t, info.TTL, float64(hour))
	equal(t, len(f.requests), 1)
}

func TestTokenCacheDisabled(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	v.TokenCache = false
	equal(t, connect(t, v, false), "fresh-token")
	if _, err := os.Stat(cacheFile(v)); err == nil {
		t.Fatal("cache written")
	}
	equalPaths(t, f.paths(), "/v1/auth/jwt/login")

	f = newFixture(t, fixtureOptions{})
	v = f.client()
	f.seed(v, 12*hour)
	before, _ := os.ReadFile(cacheFile(v))
	v.TokenCache = false
	equal(t, connect(t, v, false), "fresh-token")
	after, _ := os.ReadFile(cacheFile(v))
	if !bytes.Equal(before, after) {
		t.Fatal("disabled cache touched disk")
	}

	f = newFixture(t, fixtureOptions{})
	v = f.client()
	v.TokenCache = false
	v.VaultToken = "environment-token"
	equal(t, connect(t, v, false), "environment-token")
	equal(t, len(f.requests), 0)
	if _, err := os.Stat(cacheFile(v)); err == nil {
		t.Fatal("cache written")
	}
}

func TestTokenCacheFalseFromRC(t *testing.T) {
	rc, err := vauthlogin.ParseRC([]byte("vault_addr: https://vault.example.test\ntoken_cache: false\n"), ".vauthrc", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if rc.TokenCache == nil || *rc.TokenCache {
		t.Fatal("token_cache false not parsed")
	}
}

func TestCacheIsArmorOnly(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	connect(t, v, false)
	armor, _ := os.ReadFile(cacheFile(v))
	if !bytes.HasPrefix(armor, []byte("ssh-agent-crypt:")) || bytes.Contains(armor, []byte("fresh-token")) {
		t.Fatalf("not armored: %q", armor[:40])
	}
	// The ssh-agent-crypt CLI (Go) decrypts the same armor.
	cli := exec.Command("go", "run", "github.com/131/ssh-agent-crypt/cmd/ssh-agent-crypt", "-decrypt")
	cli.Stdin = bytes.NewReader(armor)
	cli.Env = append(os.Environ(), "SSH_AUTH_SOCK="+agentSocket)
	out, err := cli.Output()
	if err != nil {
		t.Skipf("ssh-agent-crypt CLI unavailable: %v", err)
	}
	var cache tokenCache
	if err := json.Unmarshal(out, &cache); err != nil || cache.Token != "fresh-token" {
		t.Fatalf("CLI output %q", out)
	}
}

func TestWithoutAgentCacheSkipped(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	f.seed(v, 12*hour)
	before, _ := os.ReadFile(cacheFile(v))
	v.Agent = ""
	v.TokenCache = false // as New() does when no agent is configured
	equal(t, connect(t, v, false), "fresh-token")
	after, _ := os.ReadFile(cacheFile(v))
	if !bytes.Equal(before, after) {
		t.Fatal("existing armor touched")
	}
}

func TestOneStatusPerConnection(t *testing.T) {
	for _, c := range []struct {
		options   fixtureOptions
		operation string
		duration  string
	}{
		{fixtureOptions{ttl: seconds(12 * hour)}, "reused", "12h"},
		{fixtureOptions{ttl: seconds(hour)}, "renewed", "1d"},
		{fixtureOptions{ttl: seconds(hour), renewStatus: 400}, "generated", "1d"},
		{fixtureOptions{ttl: seconds(hour), renewStatus: 403}, "generated", "1d"},
	} {
		f := newFixture(t, c.options)
		v := f.client()
		f.seed(v, 12*hour)
		var stderr bytes.Buffer
		v.Stderr = &stderr
		connect(t, v, false)
		equal(t, stderr.String(), fmt.Sprintf("Vauth token: %s · %s\n", c.operation, c.duration))
	}
	f := newFixture(t, fixtureOptions{ttl: seconds(hour), renewStatus: 500})
	v := f.client()
	f.seed(v, 12*hour)
	var stderr bytes.Buffer
	v.Stderr = &stderr
	if _, err := v.Connect(false); err == nil {
		t.Fatal("connect should fail")
	}
	equal(t, stderr.String(), "")
}

func TestReplaceEnv(t *testing.T) {
	dict := Lookup{"env": map[string]string{"USER": "alice"}, "profile": map[string]any{"TOKEN": "secret", "N": 3}}
	equal(t, ReplaceEnv("$${env.USER}", dict), "alice")
	equal(t, ReplaceEnv("x-$${profile.TOKEN}-$${profile.N}", dict), "x-secret-3")
	equal(t, ReplaceEnv("$${profile.MISSING}", dict), "$${profile.MISSING}") // unresolved macros are kept, like nyks
	equal(t, ReplaceEnv("plain", dict), "plain")
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func TestEnvMapKeysMustBeVariableNames(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	v.Config.Env = &EnvConfig{}
	v.Config.Env.Map.Set("SAFE; printf INJECTED >&2; #", "dummy")
	if _, err := v.Env(false); err == nil || !strings.Contains(err.Error(), "Invalid environment variable name") {
		t.Fatalf("hostile env.map key accepted: %v", err)
	}
	v.Config.Env = &EnvConfig{}
	v.Config.Env.Map.Set("TF_HTTP_USERNAME", "$${profile.VAUTH_USER_LOGIN}")
	if _, err := v.Env(false); err != nil {
		t.Fatal(err)
	}
}

func TestCheckProjectVersion(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	write := func(body string) { os.WriteFile(manifest, []byte(body), 0o644) }
	write(`{"dependencies":{"vvauth":"^2.5.0","yaml":"^2"}}`)
	if err := CheckProjectVersion(manifest, "v2.7.1"); err != nil {
		t.Fatal(err)
	}
	if err := CheckProjectVersion(manifest, "v3.0.0"); err == nil || !strings.Contains(err.Error(), "project requires ^2.5.0") {
		t.Fatalf("v3 accepted by ^2.5.0: %v", err)
	}
	if err := CheckProjectVersion(manifest, "(devel)"); err != nil {
		t.Fatal("devel builds must not be checked:", err)
	}
	write(`{"dependencies":{"yaml":"^2"}}`)
	if err := CheckProjectVersion(manifest, "v0.0.1"); err != nil {
		t.Fatal("unrelated dependencies must be ignored:", err)
	}
	if err := CheckProjectVersion(filepath.Join(dir, "missing.json"), "v1.0.0"); err != nil {
		t.Fatal(err)
	}
}

func TestProfileKVAndEnvironmentUseLoginTransport(t *testing.T) {
	f := newFixture(t, fixtureOptions{
		metadata: map[string]any{"VAUTH_USER_LOGIN": "alice", "VAUTH_USER_NAME": "Alice", "VAUTH_USER_MAIL": "alice@example.test"},
		database: map[string]any{"TEAM": "ops"}, secrets: map[string]any{"API_KEY": "fixture-secret"},
	})
	v := f.client()
	v.Config.Env = &EnvConfig{Git: true, Paths: []string{"app"}}
	v.Config.Env.Map.Set("LOGIN", "$${profile.VAUTH_USER_LOGIN}")
	v.Config.Env.Map.Set("TEAM", "$${profile.TEAM}")
	v.Config.Env.Map.Set("API_KEY", "$${secrets.API_KEY}")
	env, err := v.Env(true)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"VAULT_TOKEN": "fresh-token", "LOGIN": "alice", "TEAM": "ops", "API_KEY": "fixture-secret", "GIT_AUTHOR_NAME": "Alice"} {
		value, ok := env.Get(key)
		if !ok {
			t.Fatalf("missing %s", key)
		}
		equal(t, value, want)
	}
	equalPaths(t, f.paths(), "/v1/auth/jwt/login", "/v1/auth/token/lookup-self", "/v1/identity/entity/id/test-entity", "/v1/private/alice/data/.vauth_database", "/v1/secrets/data/app")
	for _, r := range f.requests[1:] {
		equal(t, r.Token, "fresh-token")
	}
	if err := v.Set("feature", "enabled"); err != nil {
		t.Fatal(err)
	}
	equal(t, f.options.database["FEATURE"], "enabled")
	if err := v.Unset("feature"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.options.database["FEATURE"]; ok {
		t.Fatal("unset key retained")
	}
	logins := 0
	for _, r := range f.requests {
		if strings.HasSuffix(r.Path, "/login") {
			logins++
		}
	}
	equal(t, logins, 1)
}

func TestEnvironmentConfigIsSeparateFromAuthentication(t *testing.T) {
	config, err := ParseConfig([]byte(`jwt_auth: ignored
env: {map: {LOGIN: '$${env.LOGIN}'}}
ssh-agent-crypt: {path: '$${env.FILE}'}
`), ".vauthrc", map[string]string{"LOGIN": "alice", "FILE": "fixture.creds"})
	if err != nil {
		t.Fatal(err)
	}
	value, _ := config.Env.Map.Get("LOGIN")
	equal(t, value, "alice")
	equal(t, config.AgentCrypt.Path, "fixture.creds")
}
