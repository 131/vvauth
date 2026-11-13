package vvauth

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func memoryHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestNewFromRCExportsToParent(t *testing.T) {
	home := memoryHome(t)
	f := newFixture(t, fixtureOptions{
		metadata: map[string]any{"VAUTH_USER_LOGIN": "alice", "WHO": "profile"},
		database: map[string]any{"KEY": "private"},
		secrets:  map[string]any{"APP_KEY": "fixture-secret"},
	})
	body := []byte(`vault_addr: $${env.SELECTED_VAULT}
jwt_auth: {jwt: fixture-jwt, role: fixture-role}
token_cache: false
env:
  paths: [app]
  map:
    WHO: $${profile.WHO}
    KEY: $${profile.KEY}
    APP_KEY: $${secrets.APP_KEY}
    INPUT: $${env.INPUT}
    BOOL: true
`)
	environ := map[string]string{"SELECTED_VAULT": f.server.URL, "VAULT_ADDR": f.server.URL, "INPUT": "caller-value", "SSH_AUTH_SOCK": agentSocket}
	v, err := NewFromRC(body, environ)
	if err != nil {
		t.Fatal(err)
	}
	v.Stderr = io.Discard
	var output bytes.Buffer
	v.Stdout = &output
	environ["INPUT"] = "changed"
	exports, err := v.Env(false)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"VAULT_ADDR": f.server.URL, "VAULT_TOKEN": "fresh-token", "WHO": "profile",
		"KEY": "private", "APP_KEY": "fixture-secret", "INPUT": "caller-value", "BOOL": "true",
	} {
		got, ok := exports.Get(key)
		if !ok || got != want {
			t.Fatalf("incorrect export %s", key)
		}
	}
	equal(t, output.Len(), 0)
	equal(t, v.HomeDir, home)
	equal(t, v.RC()["vault_addr"], "$${env.SELECTED_VAULT}")
	equal(t, v.RC()["env"].(map[string]any)["map"].(map[string]any)["INPUT"], "$${env.INPUT}")
	equal(t, v.RC()["env"].(map[string]any)["map"].(map[string]any)["BOOL"], true)
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	equal(t, len(entries), 0)
}

func TestNewFromRCUsesHomeVaultTrust(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "known"}[trusted], func(t *testing.T) {
			home := memoryHome(t)
			f := newFixture(t, fixtureOptions{})
			if trusted {
				if err := os.WriteFile(filepath.Join(home, ".vauthrc"), []byte("known_vaults: ['"+f.server.URL+"']"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			body := []byte("vault_addr: " + f.server.URL + "\nknown_vaults: ['" + f.server.URL + "']\nenv: {map: {VALUE: local}}")
			v, err := NewFromRC(body, map[string]string{"VAULT_TOKEN": "inherited-fixture-token"})
			if err != nil {
				t.Fatal(err)
			}
			v.Stderr = io.Discard
			exports, err := v.Env(false)
			if trusted {
				if err != nil {
					t.Fatal(err)
				}
				value, _ := exports.Get("VALUE")
				equal(t, value, "local")
			} else {
				if err == nil || !strings.Contains(err.Error(), "known_vaults") || exports != nil {
					t.Fatalf("unknown inline Vault accepted: %v", err)
				}
				equal(t, len(f.requests), 0)
			}
		})
	}
}

func TestNewFromRCValidatesParentSections(t *testing.T) {
	memoryHome(t)
	for _, body := range []string{"vault_addr: [", "delegate: [invalid/role]", "env: {map: {VALUE: [not-a-scalar]}}"} {
		if v, err := NewFromRC([]byte(body), map[string]string{}); err == nil || v != nil {
			t.Fatal("invalid inline RC accepted")
		}
	}
	body := []byte("env: {gitlab: true, map: {PROJECT: '$${env.CI_PROJECT_PATH}'}}")
	if v, err := NewFromRC(body, map[string]string{}); err == nil || v != nil || !strings.Contains(err.Error(), "CI_PROJECT_PATH") {
		t.Fatalf("GitLab prerequisite not checked: %v", err)
	}
	environ := map[string]string{"CI_PROJECT_PATH": "team/project", "CI_PROJECT_NAME": "project", "CI_PROJECT_NAMESPACE": "team", "CI_PROJECT_PATH_SLUG": "team-project"}
	v, err := NewFromRC(body, environ)
	if err != nil {
		t.Fatal(err)
	}
	v.Stderr = io.Discard
	exports, err := v.Env(false)
	if err != nil {
		t.Fatal(err)
	}
	value, _ := exports.Get("PROJECT")
	equal(t, value, "team/project")
}

func TestNewFromRCDelegatedExports(t *testing.T) {
	memoryHome(t)
	body := []byte(`vault_addr: https://synthetic.invalid
token_cache: false
delegate: [client-ro]
env:
  map:
    ROUTER_TOKEN: $${delegate.client-ro}
`)
	v, err := NewFromRC(body, map[string]string{"VAULT_ADDR": "https://synthetic.invalid", "VAULT_TOKEN": "fixture-parent"})
	if err != nil {
		t.Fatal(err)
	}
	v.Stderr = io.Discard
	creates := 0
	v.HTTPClient = &http.Client{Transport: delegateTransport(func(r *http.Request) (*http.Response, error) {
		response := `{"data":{"ttl":2000,"entity_id":"synthetic-entity"}}`
		switch r.URL.Path {
		case "/v1/identity/entity/id/synthetic-entity":
			response = `{"data":{"metadata":{}}}`
		case "/v1/auth/token/create/client-ro":
			creates++
			response = `{"auth":{"client_token":"fixture-child","lease_duration":1000}}`
		case "/v1/auth/token/lookup-self":
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response))}, nil
	})}
	for i := 0; i < 2; i++ {
		exports, err := v.Env(false)
		if err != nil {
			t.Fatal(err)
		}
		equal(t, exports.Values["VAULT_TOKEN"], "fixture-parent")
		equal(t, exports.Values["ROUTER_TOKEN"], "fixture-child")
	}
	equal(t, creates, 1) // In-memory delegation reuse remains available without disk cache.
}
