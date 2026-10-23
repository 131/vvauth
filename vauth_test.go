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
			fmt.Fprint(w, `{"data":{"metadata":{}}}`)
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
	return &Vauth{
		RC:         RC{JWTAuth: &JWTAuth{Path: "jwt", JWT: "test-jwt", Role: "test-role"}},
		VaultAddr:  f.server.URL,
		Agent:      agentSocket,
		TokenCache: true,
		CacheDir:   filepath.Join(f.dir, ".vauth", "tokens"),
		Environ:    map[string]string{},
		Stderr:     io.Discard,
	}
}

func (f *fixture) paths() []string {
	var paths []string
	for _, r := range f.requests {
		paths = append(paths, r.Path)
	}
	return paths
}

func (f *fixture) read(v *Vauth) tokenCache {
	f.t.Helper()
	armor, err := os.ReadFile(v.TokenCacheFile())
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
	if err := v.writeTokenCache(v.TokenCacheFile(), v.TokenCacheFile()+".next", &cache); err != nil {
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
	v.saveTokenCache(&token{Value: "cached-token", TTL: float64(lease), LeaseDuration: lease, Renewable: renewable})
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
	info, _ := os.Stat(first.TokenCacheFile())
	equal(t, info.Mode().Perm(), 0o600)
	info, _ = os.Stat(filepath.Dir(first.TokenCacheFile()))
	equal(t, info.Mode().Perm(), 0o700)
	second := f.client()
	equal(t, connect(t, second, false), "fresh-token")
	equalPaths(t, f.paths(), "/v1/auth/jwt/login")
	entries, _ := os.ReadDir(filepath.Dir(first.TokenCacheFile()))
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
	if _, _, err := v.lookupToken(v.VaultToken); err == nil {
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
		if _, err := v.Connect(false); err == nil {
			t.Fatal("connect should fail")
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

func TestEnvironmentTokenRespectedAndCached(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	f.seed(v, 12*hour)
	v.VaultToken = "environment-token"
	equal(t, connect(t, v, false), "environment-token")
	equal(t, f.read(v).Token, "environment-token")
	equal(t, f.requests[0].Token, "environment-token")
	equal(t, len(f.requests), 1)
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
	os.MkdirAll(filepath.Dir(v.TokenCacheFile()), 0o700)
	os.WriteFile(v.TokenCacheFile(), []byte("{broken"), 0o600)
	equal(t, connect(t, v, false), "fresh-token")
	equal(t, f.read(v).Token, "fresh-token")
}

func TestPlaintextCacheNotAccepted(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	os.MkdirAll(filepath.Dir(v.TokenCacheFile()), 0o700)
	os.WriteFile(v.TokenCacheFile(), []byte(`{"token":"plain-token","lease_duration":43200,"renewable":true,"expires_at":null}`), 0o600)
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
	if first.TokenCacheFile() == second.TokenCacheFile() {
		t.Fatal("cache files should differ")
	}
	equal(t, f.read(first).Token, "cached-token")
	equal(t, f.read(second).Token, "fresh-token")
	third := f.client()
	third.VaultAddr = "http://other-vault.test"
	if third.TokenCacheKey() == first.TokenCacheKey() {
		t.Fatal("cache keys should differ")
	}
	entries, _ := os.ReadDir(filepath.Dir(first.TokenCacheFile()))
	equal(t, len(entries), 2)
	armor, _ := os.ReadFile(first.TokenCacheFile())
	if bytes.Contains(armor, []byte("test-jwt")) || bytes.Contains(armor, []byte("cached-token")) {
		t.Fatal("cache leaks secrets")
	}
}

func TestTokenCacheKeyMatchesNode(t *testing.T) {
	// sha256 of JSON.stringify({vault_addr, ssh_auth, jwt_auth}) as the Node
	// implementation renders it (undefined members omitted).
	v := &Vauth{VaultAddr: "https://vault.example.test/", RC: RC{SSHAuth: &SSHAuth{Role: "alice"}}}
	equal(t, v.TokenCacheKey(), sha256Hex(`{"vault_addr":"https://vault.example.test","ssh_auth":{"role":"alice"}}`))
	v = &Vauth{VaultAddr: "https://vault.example.test", RC: RC{JWTAuth: &JWTAuth{Path: "jwt", JWT: "x", Role: "r"}}}
	equal(t, v.TokenCacheKey(), sha256Hex(`{"vault_addr":"https://vault.example.test","jwt_auth":{"path":"jwt","jwt":"x","role":"r"}}`))
	rc, err := ParseRC([]byte("vault_addr: https://vault.example.test\nssh_auth:\n  role: $${env.USER}\n"), ".vauthrc", map[string]string{"USER": "bob"})
	if err != nil {
		t.Fatal(err)
	}
	v = &Vauth{VaultAddr: rc.VaultAddr, RC: *rc}
	equal(t, v.TokenCacheKey(), sha256Hex(`{"vault_addr":"https://vault.example.test","ssh_auth":{"role":"bob"}}`))
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
	os.MkdirAll(filepath.Dir(filepath.Dir(v.TokenCacheFile())), 0o700)
	os.WriteFile(filepath.Dir(v.TokenCacheFile()), []byte("not a directory"), 0o600)
	var stderr bytes.Buffer
	v.Stderr = &stderr
	equal(t, connect(t, v, false), "fresh-token")
	if !strings.Contains(stderr.String(), "token not persisted") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func TestWithoutAuthMethodTokensIgnored(t *testing.T) {
	f := newFixture(t, fixtureOptions{lookupStatus: 403})
	v := f.client()
	f.seed(v, 12*hour)
	v.RC = RC{}
	v.VaultToken = "uncached-token"
	equal(t, connect(t, v, false), "")
	equal(t, v.VaultToken, "")
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
	before, _ := os.ReadFile(v.TokenCacheFile())
	stat, _ := os.Stat(v.TokenCacheFile())
	equal(t, connect(t, v, false), "cached-token")
	after, _ := os.ReadFile(v.TokenCacheFile())
	if !bytes.Equal(before, after) {
		t.Fatal("cache rewritten")
	}
	again, _ := os.Stat(v.TokenCacheFile())
	equal(t, again.ModTime(), stat.ModTime())
	equal(t, len(f.requests), 0)
}

func TestLookupReturnsLease(t *testing.T) {
	f := newFixture(t, fixtureOptions{ttl: seconds(hour)})
	v := f.client()
	info, lease, err := v.lookupToken("environment-token")
	if err != nil {
		t.Fatal(err)
	}
	equal(t, lease, 24*hour)
	equal(t, info.TTL, float64(hour))
	equal(t, len(f.requests), 1)
}

func TestTokenCacheDisabled(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	v.TokenCache = false
	equal(t, connect(t, v, false), "fresh-token")
	if _, err := os.Stat(v.TokenCacheFile()); err == nil {
		t.Fatal("cache written")
	}
	equalPaths(t, f.paths(), "/v1/auth/jwt/login")

	f = newFixture(t, fixtureOptions{})
	v = f.client()
	f.seed(v, 12*hour)
	before, _ := os.ReadFile(v.TokenCacheFile())
	v.TokenCache = false
	equal(t, connect(t, v, false), "fresh-token")
	after, _ := os.ReadFile(v.TokenCacheFile())
	if !bytes.Equal(before, after) {
		t.Fatal("disabled cache touched disk")
	}

	f = newFixture(t, fixtureOptions{})
	v = f.client()
	v.TokenCache = false
	v.VaultToken = "environment-token"
	equal(t, connect(t, v, false), "environment-token")
	equalPaths(t, f.paths(), "/v1/auth/token/lookup-self")
	if _, err := os.Stat(v.TokenCacheFile()); err == nil {
		t.Fatal("cache written")
	}
}

func TestTokenCacheFalseFromRC(t *testing.T) {
	rc, err := ParseRC([]byte("vault_addr: https://vault.example.test\ntoken_cache: false\n"), ".vauthrc", map[string]string{})
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
	armor, _ := os.ReadFile(v.TokenCacheFile())
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
	before, _ := os.ReadFile(v.TokenCacheFile())
	v.Agent = ""
	v.TokenCache = false // as New() does when no agent is configured
	equal(t, connect(t, v, false), "fresh-token")
	after, _ := os.ReadFile(v.TokenCacheFile())
	if !bytes.Equal(before, after) {
		t.Fatal("existing armor touched")
	}
}

func TestTokenStatus(t *testing.T) {
	v := &Vauth{VaultAddr: "https://vault.example.test"}
	for _, c := range []struct {
		ttl      float64
		duration string
	}{
		{2*86400 + 3*hour + 20*60 + 5, "2d 3h"}, {12*hour + 30*60 + 5, "12h 30m"}, {5*60 + 20, "5m 20s"},
		{86400, "1d"}, {30 * 60, "30m"}, {45, "45s"}, {86400 + 20, "1d 20s"}, {hour + 5, "1h 5s"},
		{400*86400 + 2*hour, "1y 1month"}, {60.9, "1m 1s"},
	} {
		var stderr bytes.Buffer
		v.Stderr = &stderr
		v.tokenStatus("reused", &token{TTL: c.ttl})
		equal(t, stderr.String(), "Vauth token: reused · https://vault.example.test · "+c.duration+"\n")
	}
	var stderr bytes.Buffer
	v.Stderr = &stderr
	v.tokenStatus("generated", &token{})
	equal(t, stderr.String(), "Vauth token: generated · https://vault.example.test · valid indefinitely\n")
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
		equal(t, stderr.String(), fmt.Sprintf("Vauth token: %s · %s · %s\n", c.operation, f.server.URL, c.duration))
	}
	f := newFixture(t, fixtureOptions{lookupStatus: 500})
	v := f.client()
	v.VaultToken = "uncached-token"
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

func TestHumanDiff(t *testing.T) {
	equal(t, HumanDiff(0, 2), "0s")
	equal(t, HumanDiff(59, 2), "59s")
	equal(t, HumanDiff(3600*24*31, 2), "1month 1d")
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func TestEnvMapKeysMustBeVariableNames(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	v := f.client()
	v.RC.Env = &EnvConfig{}
	v.RC.Env.Map.Set("SAFE; printf INJECTED >&2; #", "dummy")
	if _, err := v.Env(false); err == nil || !strings.Contains(err.Error(), "Invalid environment variable name") {
		t.Fatalf("hostile env.map key accepted: %v", err)
	}
	v.RC.Env = &EnvConfig{}
	v.RC.Env.Map.Set("TF_HTTP_USERNAME", "$${profile.VAUTH_USER_LOGIN}")
	if _, err := v.Env(false); err != nil {
		t.Fatal(err)
	}
}
