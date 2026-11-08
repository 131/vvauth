package vvauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sshagentcrypt "github.com/131/ssh-agent-crypt"
)

type delegateTransport func(*http.Request) (*http.Response, error)

func (f delegateTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type delegateFixture struct {
	lookupDeniedOnce bool
	creates          int
	lookups          int
	logins           int
	ttl              float64
	auth             any
	status           int
	payload          map[string]any
	routes           []string
}

func newDelegateClient(t *testing.T, f *delegateFixture, parent string) *Vauth {
	t.Helper()
	home := t.TempDir()
	rc := filepath.Join(home, ".vauthrc")
	body := `vault_addr: https://synthetic.invalid
jwt_auth:
  role: project
  jwt: synthetic-jwt
token_cache: false
delegate:
  - vauth-profile-ro
  - project-ro
env:
  map:
    VAULT_ROUTER_TOKEN: $${delegate.vauth-profile-ro}
    PROJECT_TOKEN: $$delegate.project-ro
`
	if err := os.WriteFile(rc, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"VAUTHRC": rc, "HOME": home, "VAULT_TOKEN": parent, "VAULT_ADDR": "", "SSH_AUTH_SOCK": "", "SSH_AGENT_CRYPT_KEY": "", "VAUTH_USER_IDENTITY": "", "VAUTH_USER_MAIL": ""} {
		t.Setenv(name, value)
	}
	v, err := New()
	if err != nil {
		t.Fatal(err)
	}
	v.Stderr = io.Discard
	v.Now = func() time.Time { return time.UnixMilli(100000) }
	v.HTTPClient = &http.Client{Transport: delegateTransport(func(r *http.Request) (*http.Response, error) {
		status := 200
		var response any
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self":
			f.lookups++
			if f.lookupDeniedOnce && f.lookups == 1 {
				status = 403
			}
			response = map[string]any{"data": map[string]any{"ttl": f.ttl, "entity_id": "synthetic-entity"}}
		case r.URL.Path == "/v1/auth/jwt/login":
			f.logins++
			response = map[string]any{"auth": map[string]any{"client_token": "synthetic-new-parent", "lease_duration": 2000}}
		case r.URL.Path == "/v1/identity/entity/id/synthetic-entity":
			response = map[string]any{"data": map[string]any{"metadata": map[string]any{}}}
		case strings.HasPrefix(r.URL.Path, "/v1/auth/token/create/"):
			f.creates++
			f.routes = append(f.routes, r.URL.Path)
			if r.Header.Get("X-Vault-Token") != v.VAULT_TOKEN() {
				t.Error("wrong parent")
			}
			if err := json.NewDecoder(r.Body).Decode(&f.payload); err != nil {
				t.Error(err)
			}
			auth := f.auth
			if auth == nil {
				auth = map[string]any{"client_token": fmt.Sprintf("synthetic-child-%d", f.creates), "lease_duration": 1000}
			}
			response = map[string]any{"auth": auth}
			if f.status != 0 {
				status = f.status
			}
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
		}
		body, err := json.Marshal(response)
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}, err
	})}
	return v
}

func TestDelegateNativeEnvironment(t *testing.T) {
	f := &delegateFixture{ttl: 1234.5}
	v := newDelegateClient(t, f, "synthetic-parent")
	env, err := v.Env(false)
	if err != nil {
		t.Fatal(err)
	}
	if env.Values["VAULT_TOKEN"] != "synthetic-parent" || env.Values["VAULT_ROUTER_TOKEN"] == "synthetic-parent" || env.Values["VAULT_ROUTER_TOKEN"] == env.Values["PROJECT_TOKEN"] {
		t.Fatal("incorrect delegation exports")
	}
	if env.Len() != 4 || f.creates != 2 || f.logins != 0 {
		t.Fatal("unexpected exports/login count")
	}
	if len(f.payload) != 4 || f.payload["ttl"] != "1234.5s" || f.payload["renewable"] != false || f.payload["no_default_policy"] != true || f.payload["type"] != "service" {
		t.Fatalf("incorrect creation payload: %v", f.payload)
	}
	v.Config.Env.Map = OrderedMap{}
	env, err = v.Env(false)
	if err != nil || env.Len() != 2 {
		t.Fatal("implicit delegation export")
	}
	if _, err := os.Stat(filepath.Join(v.HomeDir, ".vauth")); !os.IsNotExist(err) {
		t.Fatal("disk cache used when off")
	}
}

func TestDelegateFullTTLAndIsolation(t *testing.T) {
	f := &delegateFixture{ttl: 1234.5}
	v := newDelegateClient(t, f, "synthetic-parent")
	clock := time.UnixMilli(100000)
	v.Now = func() time.Time { return clock }
	first, err := v.Delegate("vauth-profile-ro", false)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(1000*time.Second - time.Millisecond)
	token, err := v.Delegate("vauth-profile-ro", false)
	if err != nil || token != first || f.creates != 1 || f.lookups != 1 {
		t.Fatal("cache hit did not use full TTL")
	}
	clock = clock.Add(time.Millisecond)
	token, err = v.Delegate("vauth-profile-ro", false)
	if err != nil || token == first {
		t.Fatal("expiry did not emit")
	}
	if _, err := v.Delegate("vauth-profile-ro", true); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Delegate("project-ro", false); err != nil {
		t.Fatal(err)
	}
	if f.creates != 4 || f.logins != 0 {
		t.Fatal("renew must not login parent")
	}
	if _, err := v.Connect(true); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Delegate("vauth-profile-ro", false); err != nil {
		t.Fatal(err)
	}
	if f.creates != 5 || f.logins != 1 {
		t.Fatal("parent change did not isolate cache")
	}
	for key, cache := range v.delegates {
		body, _ := json.Marshal(cache)
		if strings.Contains(key, "synthetic") || strings.Contains(string(body), "parent") {
			t.Fatal("parent in cache")
		}
	}
	if delegateKey("https://other.invalid", "synthetic-parent", "vauth-profile-ro") == delegateKey(v.VAULT_ADDR(), "synthetic-parent", "vauth-profile-ro") {
		t.Fatal("address not isolated")
	}
}

func TestDelegateErrorsAndNoPartialOutput(t *testing.T) {
	for _, auth := range []any{false, map[string]any{}, map[string]any{"client_token": "synthetic-parent", "lease_duration": 10}, map[string]any{"client_token": "child", "lease_duration": 0}, map[string]any{"client_token": "child", "lease_duration": 11}, map[string]any{"client_token": "child", "lease_duration": -1}, map[string]any{"client_token": "child", "lease_duration": "10"}} {
		f := &delegateFixture{ttl: 10, auth: auth}
		v := newDelegateClient(t, f, "synthetic-parent")
		var output bytes.Buffer
		v.Stdout = &output
		if err := v.Dotenv(); err == nil || output.Len() != 0 {
			t.Fatal("invalid response published")
		}
	}
	for _, ttl := range []float64{0, -1} {
		v := newDelegateClient(t, &delegateFixture{ttl: ttl}, "synthetic-parent")
		if _, err := v.Delegate("role", false); err == nil {
			t.Fatal("invalid parent TTL accepted")
		}
	}
	v := newDelegateClient(t, &delegateFixture{ttl: 10, status: 403}, "synthetic-parent")
	if _, err := v.Env(false); err == nil {
		t.Fatal("issuance error ignored")
	}
	for _, macro := range []string{"$${delegate.unknown}", "$$delegate.unknown", "$${delegate}"} {
		v := newDelegateClient(t, &delegateFixture{ttl: 1234.5}, "synthetic-parent")
		v.Config.Env.Map.Set("OK", "value")
		v.Config.Env.Map.Set("BAD", macro)
		var output bytes.Buffer
		v.Stdout = &output
		if err := v.Dotenv(); err == nil || !strings.Contains(err.Error(), "Unknown Vault delegation") || output.Len() != 0 {
			t.Fatal("unknown macro published")
		}
	}
	v = newDelegateClient(t, &delegateFixture{ttl: 10}, "synthetic-parent")
	for _, role := range []string{"", "../other", ".", ".."} {
		if _, err := v.Delegate(role, false); err == nil {
			t.Fatal("invalid role accepted")
		}
	}
	for _, roles := range []string{"null", "{}", "[{}]"} {
		if _, err := ParseConfig([]byte("delegate: "+roles), "test", nil); err == nil {
			t.Fatal("invalid role config accepted")
		}
	}
}

// Runs under the existing TestMain agent, or skips in the socket-free recipe.
func TestDelegateEncryptedInterop(t *testing.T) {
	agent := exec.Command("ssh-agent", "-s")
	out, err := agent.Output()
	if err != nil {
		t.Skip("sandbox cannot start a synthetic ssh-agent")
	}
	socketMatch := strings.Split(strings.Split(string(out), "SSH_AUTH_SOCK=")[1], ";")[0]
	pid := strings.Split(strings.Split(string(out), "SSH_AGENT_PID=")[1], ";")[0]
	defer exec.Command("kill", pid).Run()
	directory := t.TempDir()
	key := filepath.Join(directory, "key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("keygen: %v %s", err, out)
	}
	f := &delegateFixture{ttl: 1234.5}
	v := newDelegateClient(t, f, "synthetic-parent")
	t.Setenv("SSH_AUTH_SOCK", socketMatch)
	add := exec.Command("ssh-add", key)
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v %s", err, out)
	}
	v.Agent = socketMatch
	v.TokenCache = true
	v.Now = time.Now
	token, err := v.Delegate("vauth-profile-ro", false)
	if err != nil {
		t.Fatal(err)
	}
	file := v.delegateFile(delegateKey(v.VAULT_ADDR(), v.VAULT_TOKEN(), "vauth-profile-ro"))
	armor, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(armor, []byte("ssh-agent-crypt:v3:")) || bytes.Contains(armor, []byte(token)) || bytes.Contains(armor, []byte(v.VAULT_TOKEN())) {
		t.Fatal("cache not encrypted")
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0600 {
		t.Fatal("cache permissions")
	}
	// Node reads Go's cache through the public Delegate API, then forces a new
	// encrypted child; Go consumes that child without a Vault lookup.
	script := `const fs=require('fs');const V=require('./index');const v=Object.create(V.prototype);
Object.defineProperties(v,{VAULT_ADDR:{value:'https://synthetic.invalid'},VAULT_TOKEN:{value:'synthetic-parent'},RC:{value:{token_cache:true}}});
v.Connect=async()=>v.VAULT_TOKEN;v.LookupSelf=async()=>({ttl:1234.5});
v.Request=async()=>({body:JSON.stringify({auth:{client_token:'synthetic-node-child',lease_duration:1000}})});
(async()=>{const t=await v.Delegate('vauth-profile-ro');if(t!==process.argv[1])throw Error('interop cache miss');await v.Delegate('vauth-profile-ro',true)})().catch(()=>process.exit(1));`
	node := exec.Command("node", "-e", script, token)
	node.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + v.HomeDir, "SSH_AUTH_SOCK=" + socketMatch}
	if out, err := node.CombinedOutput(); err != nil {
		t.Fatalf("Node interop: %v %s", err, out)
	}
	v.delegates = nil
	before := f.lookups
	next, err := v.Delegate("vauth-profile-ro", false)
	if err != nil || next != "synthetic-node-child" || f.lookups != before {
		t.Fatal("Node cache not reused by Go")
	}
	armor, _ = os.ReadFile(file)
	clear, err := sshagentcrypt.Decrypt(armor, "", &sshagentcrypt.Options{AgentSocket: socketMatch})
	if err != nil || bytes.Contains(clear, []byte("synthetic-parent")) {
		t.Fatal("parent in decrypted cache")
	}
}

func TestDelegateCacheKeyInterop(t *testing.T) {
	script := `Date.now=()=>100000;const V=require('./index');const v=Object.create(V.prototype);
Object.defineProperties(v,{VAULT_ADDR:{value:process.argv[1]},VAULT_TOKEN:{value:'synthetic-parent'},RC:{value:{token_cache:false}}});
v.Connect=async()=>{};v.LookupSelf=async()=>({ttl:100});v.Request=async()=>({body:JSON.stringify({auth:{client_token:'child',lease_duration:100}})});
v.Delegate('role.with-dots').then(()=>process.stdout.write([...v._delegates.keys()][0])).catch(()=>process.exit(1));`
	for _, address := range []string{"https://synthetic.invalid/", "https://synthetic.invalid/<é>&"} {
		node := exec.Command("node", "-e", script, address)
		node.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
		out, err := node.Output()
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != delegateKey(address, "synthetic-parent", "role.with-dots") {
			t.Fatal("Node/Go cache hash mismatch")
		}
	}
}

func TestDelegateApprovedConfig(t *testing.T) {
	config, err := ParseConfig([]byte(`vault_addr: https://vault.elipsdev.net
ssh_auth:
  role: $${env.VAUTH_USER_LOGIN}
delegate:
  - vauth-profile-ro
env:
  map:
    VAULT_ROUTER_TOKEN: $${delegate.vauth-profile-ro}
`), "test", map[string]string{"VAUTH_USER_LOGIN": "synthetic-user"})
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Delegate) != 1 || config.Delegate[0] != "vauth-profile-ro" || config.Env.Map.Values["VAULT_ROUTER_TOKEN"] != "$${delegate.vauth-profile-ro}" {
		t.Fatal("native config not preserved")
	}
}

func TestDelegateExpiredParentLogin(t *testing.T) {
	f := &delegateFixture{ttl: 1000, lookupDeniedOnce: true}
	v := newDelegateClient(t, f, "synthetic-parent")
	if _, err := v.Delegate("vauth-profile-ro", true); err != nil {
		t.Fatal(err)
	}
	if f.lookups != 2 || f.logins != 1 || f.creates != 1 || v.VAULT_TOKEN() != "synthetic-new-parent" {
		t.Fatal("invalid parent was not replaced exactly once")
	}
}

func delayDelegateResponses(v *Vauth, clock *time.Time, lookupDelay, createDelay time.Duration) {
	transport := v.HTTPClient.Transport
	v.HTTPClient.Transport = delegateTransport(func(r *http.Request) (*http.Response, error) {
		response, err := transport.RoundTrip(r)
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self":
			*clock = clock.Add(lookupDelay)
		case strings.HasPrefix(r.URL.Path, "/v1/auth/token/create/"):
			*clock = clock.Add(createDelay)
		}
		return response, err
	})
}

func TestDelegateDelayedResponseDeadline(t *testing.T) {
	f := &delegateFixture{ttl: 10, auth: map[string]any{"client_token": "synthetic-delayed-child", "lease_duration": 5}}
	v := newDelegateClient(t, f, "synthetic-parent")
	clock := time.UnixMilli(100000)
	v.Now = func() time.Time { return clock }
	delayDelegateResponses(v, &clock, 2*time.Second, 3*time.Second)
	token, err := v.Delegate("role", false)
	if err != nil {
		t.Fatal(err)
	}
	if f.payload["ttl"] != "8s" {
		t.Fatal("elapsed lookup time not deducted")
	}
	key := delegateKey(v.VAULT_ADDR(), v.VAULT_TOKEN(), "role")
	if v.delegates[key].ExpiresAt != 107000 {
		t.Fatal("response time extended the child deadline")
	}
	clock = time.UnixMilli(106999)
	hit, err := v.Delegate("role", false)
	if err != nil || hit != token || f.creates != 1 || f.lookups != 1 {
		t.Fatal("child not reusable until its deadline")
	}
	clock = time.UnixMilli(107000)
	if _, err := v.Delegate("role", false); err != nil {
		t.Fatal(err)
	}
	if f.creates != 2 || f.logins != 0 {
		t.Fatal("deadline did not trigger child-only issuance")
	}
}

func TestDelegateExpiredOnArrival(t *testing.T) {
	for _, delay := range []time.Duration{5 * time.Second, 6 * time.Second} {
		f := &delegateFixture{ttl: 10, auth: map[string]any{"client_token": "synthetic-delayed-child", "lease_duration": 5}}
		v := newDelegateClient(t, f, "synthetic-parent")
		clock := time.UnixMilli(100000)
		v.Now = func() time.Time { return clock }
		delayDelegateResponses(v, &clock, 0, delay)
		var output bytes.Buffer
		v.Stdout = &output
		if err := v.Dotenv(); err == nil {
			t.Fatal("expired child returned")
		}
		if len(v.delegates) != 0 || output.Len() != 0 {
			t.Fatal("expired child cached or published")
		}
	}
}

func TestDelegateParentTTLConsumedByLookup(t *testing.T) {
	for _, delay := range []time.Duration{10 * time.Second, 11 * time.Second} {
		f := &delegateFixture{ttl: 10}
		v := newDelegateClient(t, f, "synthetic-parent")
		clock := time.UnixMilli(100000)
		v.Now = func() time.Time { return clock }
		delayDelegateResponses(v, &clock, delay, 0)
		if _, err := v.Delegate("role", false); err == nil {
			t.Fatal("exhausted parent TTL accepted")
		}
		if f.creates != 0 || f.logins != 0 {
			t.Fatal("exhausted TTL caused issuance or login")
		}
	}
}

func TestDelegateRetryResetsLookupAnchor(t *testing.T) {
	f := &delegateFixture{ttl: 10, lookupDeniedOnce: true, auth: map[string]any{"client_token": "synthetic-child", "lease_duration": 5}}
	v := newDelegateClient(t, f, "synthetic-parent")
	clock := time.UnixMilli(100000)
	v.Now = func() time.Time { return clock }
	transport := v.HTTPClient.Transport
	v.HTTPClient.Transport = delegateTransport(func(r *http.Request) (*http.Response, error) {
		response, err := transport.RoundTrip(r)
		if r.URL.Path == "/v1/auth/token/lookup-self" && f.lookups == 2 {
			clock = clock.Add(2 * time.Second)
		} else if r.URL.Path == "/v1/auth/token/lookup-self" || r.URL.Path == "/v1/auth/jwt/login" {
			clock = clock.Add(100 * time.Second)
		}
		return response, err
	})
	if _, err := v.Delegate("role", false); err != nil {
		t.Fatal(err)
	}
	if f.payload["ttl"] != "8s" || f.logins != 1 {
		t.Fatal("lookup anchor not reset after normal login retry")
	}
}
