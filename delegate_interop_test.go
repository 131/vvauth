package vvauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	sshagentcrypt "github.com/131/ssh-agent-crypt"
)

// Fresh clients exercise encrypted disk hits; each issuer also repeats a late
// hit through its established parent. TestMain owns the disposable SSH agent.
const delegateInteropNode = `
const assert = require('assert/strict');
const fs = require('fs');
const Vauth = require('./index');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
let clock = input.now, lookups = 0, creates = 0;
Date.now = () => clock;
const v = new Vauth();
v.LookupSelf = async parent => {
  assert.equal(parent, input.parent);
  lookups++;
  clock += 2000;
  return {ttl: 10};
};
v.Request = async (method, route, parent, payload, status) => {
  assert.equal(method, 'POST');
  assert.equal(route, 'auth/token/create/' + input.role);
  assert.equal(parent, input.parent);
  assert.equal(status, 200);
  assert.deepEqual(payload, {ttl: '8s', renewable: false, no_default_policy: true, type: 'service'});
  creates++;
  clock += 3000;
  return {body: JSON.stringify({auth: {client_token: input.issued, lease_duration: 5}})};
};
(async () => {
  const token = await v.Delegate(input.role, input.renew);
  if(creates) {
    clock = input.now + 6999;
    assert.equal(await v.Delegate(input.role, false), token);
  }
  assert.equal(v.VAULT_TOKEN, input.parent);
  process.stdout.write(JSON.stringify({token, lookups, creates}));
})().catch(err => { console.error(err.message); process.exitCode = 1; });
`

func TestDelegateEncryptedTTLInterop(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal("encrypted Node/Go interop requires Node")
	}
	for _, direction := range []string{"Go-to-Node", "Node-to-Go"} {
		t.Run(direction, func(t *testing.T) {
			home := t.TempDir()
			rc := filepath.Join(home, ".vauthrc")
			for name, value := range map[string]string{
				"HOME": home, "USERPROFILE": home, "VAUTHRC": rc,
				"SSH_AUTH_SOCK": agentSocket, "VAULT_ADDR": "",
				"SSH_AGENT_CRYPT_KEY": "", "VAUTH_USER_IDENTITY": "", "VAUTH_USER_MAIL": "",
			} {
				t.Setenv(name, value)
			}
			type namespace struct{ address, parent, role string }
			base := namespace{"https://synthetic.invalid", "synthetic-parent", "vauth-profile-ro"}
			type result struct {
				Token   string `json:"token"`
				Lookups int    `json:"lookups"`
				Creates int    `json:"creates"`
			}
			call := func(language string, ns namespace, now int64, issued string, renew bool, expected string, misses int) {
				t.Helper()
				document, err := json.Marshal(map[string]any{"vault_addr": ns.address, "token_cache": true})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(rc, document, 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("VAULT_TOKEN", ns.parent)
				var got result
				if language == "Node" {
					input, err := json.Marshal(map[string]any{
						"parent": ns.parent, "role": ns.role, "now": now, "issued": issued, "renew": renew,
					})
					if err != nil {
						t.Fatal(err)
					}
					node := exec.Command("node", "-e", delegateInteropNode)
					node.Env = []string{
						"PATH=" + os.Getenv("PATH"), "HOME=" + home, "USERPROFILE=" + home,
						"VAUTHRC=" + rc, "VAULT_TOKEN=" + ns.parent, "SSH_AUTH_SOCK=" + agentSocket,
					}
					node.Stdin = bytes.NewReader(input)
					var diagnostics bytes.Buffer
					node.Stderr = &diagnostics
					out, err := node.Output()
					if err != nil {
						t.Fatalf("Node interop failed: %v: %s", err, &diagnostics)
					}
					if err := json.Unmarshal(out, &got); err != nil {
						t.Fatal(err)
					}
				} else {
					v, err := New()
					if err != nil {
						t.Fatal(err)
					}
					clock := time.UnixMilli(now)
					v.Now = func() time.Time { return clock }
					v.Stderr = io.Discard
					v.HTTPClient = &http.Client{Transport: delegateTransport(func(r *http.Request) (*http.Response, error) {
						if r.Header.Get("X-Vault-Token") != ns.parent {
							t.Error("wrong parent in request")
						}
						var body string
						switch r.URL.Path {
						case "/v1/auth/token/lookup-self":
							got.Lookups++
							clock = clock.Add(2 * time.Second)
							body = `{"data":{"ttl":10}}`
						case "/v1/auth/token/create/" + ns.role:
							got.Creates++
							var payload map[string]any
							if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
								t.Fatal(err)
							}
							if r.Method != "POST" || len(payload) != 4 || payload["ttl"] != "8s" || payload["renewable"] != false || payload["no_default_policy"] != true || payload["type"] != "service" {
								t.Error("incorrect child creation request")
							}
							clock = clock.Add(3 * time.Second)
							body = `{"auth":{"client_token":"` + issued + `","lease_duration":5}}`
						default:
							t.Fatalf("unexpected route %s", r.URL.Path)
						}
						return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewBufferString(body))}, nil
					})}
					got.Token, err = v.Delegate(ns.role, renew)
					if err != nil {
						t.Fatal(err)
					}
					if got.Creates > 0 {
						clock = time.UnixMilli(now + 6999)
						hit, err := v.Delegate(ns.role, false)
						if err != nil || hit != got.Token {
							t.Fatal("established client did not reuse the full child TTL")
						}
					}
					if v.VAULT_TOKEN() != ns.parent {
						t.Fatal("delegation changed the parent")
					}
				}
				if got.Token != expected || got.Lookups != misses || got.Creates != misses {
					t.Fatalf("%s: incorrect token or lookup/create count at %d (renew=%v)", language, now, renew)
				}
			}
			checkCache := func(ns namespace, token string, deadline float64) []byte {
				t.Helper()
				directory := filepath.Join(home, ".vauth", "delegates")
				file := filepath.Join(directory, delegateKey(ns.address, ns.parent, ns.role)+".creds")
				armor, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.HasPrefix(armor, []byte("ssh-agent-crypt:v3:")) || bytes.Contains(armor, []byte(token)) || bytes.Contains(armor, []byte(ns.parent)) {
					t.Fatal("cache must be encrypted without plaintext credentials")
				}
				for name, mode := range map[string]os.FileMode{directory: 0700, file: 0600} {
					info, err := os.Stat(name)
					if err != nil || info.Mode().Perm() != mode {
						t.Fatal("incorrect delegation cache permissions")
					}
				}
				clear, err := sshagentcrypt.Decrypt(armor, "", &sshagentcrypt.Options{AgentSocket: agentSocket})
				if err != nil {
					t.Fatal(err)
				}
				var cache map[string]any
				if err := json.Unmarshal(clear, &cache); err != nil {
					t.Fatal(err)
				}
				if len(cache) != 2 || cache["token"] != token || cache["expires_at"] != deadline || bytes.Contains(clear, []byte(ns.parent)) {
					t.Fatal("incorrect shared cache format or request-time deadline")
				}
				return armor
			}
			writer, reader := "Go", "Node"
			if direction == "Node-to-Go" {
				writer, reader = reader, writer
			}
			call(writer, base, 100000, "synthetic-writer-child", false, "synthetic-writer-child", 1)
			original := checkCache(base, "synthetic-writer-child", 107000)
			call(reader, base, 106999, "synthetic-unused", false, "synthetic-writer-child", 0)
			slashes := base
			slashes.address += "///"
			call(reader, slashes, 106999, "synthetic-unused", false, "synthetic-writer-child", 0)
			if !bytes.Equal(original, checkCache(base, "synthetic-writer-child", 107000)) {
				t.Fatal("cache hits rewrote the encrypted cache")
			}

			// Each changed tuple component misses; the opposite language then
			// finds its new encrypted entry under exactly the same namespace.
			for name, ns := range map[string]namespace{
				"parent":  {base.address, "synthetic-other-parent", base.role},
				"role":    {base.address, base.parent, "project-ro"},
				"address": {"https://other.invalid", base.parent, base.role},
			} {
				token := "synthetic-" + name + "-child"
				call(reader, ns, 106999, token, false, token, 1)
				checkCache(ns, token, 113999)
				call(writer, ns, 113998, "synthetic-unused", false, token, 0)
			}
			call(reader, base, 107000, "synthetic-expiry-child", false, "synthetic-expiry-child", 1)
			checkCache(base, "synthetic-expiry-child", 114000)
			call(writer, base, 113999, "synthetic-unused", false, "synthetic-expiry-child", 0)
			call(reader, base, 113999, "synthetic-renew-child", true, "synthetic-renew-child", 1)
			checkCache(base, "synthetic-renew-child", 120999)
			call(writer, base, 120998, "synthetic-unused", false, "synthetic-renew-child", 0)
			entries, err := os.ReadDir(filepath.Join(home, ".vauth", "delegates"))
			if err != nil || len(entries) != 4 {
				t.Fatal("expected four isolated cache files, without temporary leftovers")
			}
		})
	}
}
