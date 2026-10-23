# vvauth: CLI contract, API and tests

Back to the [README](README.md). Node (`npm install -g vvauth`) and Go
(`go install github.com/131/vvauth/v2/cmd/vauth@latest`, release binaries)
expose the same `vauth` command; everything below holds for both.

## CLI contract

```
vauth <command> [positional...] [--flag[=value]] [--ir://json]
```

`env.map` names must match `^[A-Za-z_][A-Za-z0-9_]*$`; any other key is an
error, since names reach `export KEY=` unescaped. Flags may replace positionals (`vauth set GITLAB_TOKEN x` ≡
`vauth set --k=GITLAB_TOKEN --v=x`). `--flag` alone means `true`; `--flag=`,
`--flag=false` and `--flag=0` mean `false`. `--` ends flag parsing.

| Command | Effect | stdout |
| --- | --- | --- |
| `env [--source] [--renew]` | Resolve the `.vauthrc` environment (`env.map`, `env.paths`, `env.git`, `ssh-agent-crypt`) | JSON object with `--ir://json`; `export K='v'` lines with `--source`; JSON otherwise |
| `login [--source] [--renew]` | Authenticate, cache the token | `export VAULT_TOKEN='…'` with `--source`; nothing otherwise |
| `connect [--renew]` | Authenticate, print the token | raw token, no trailing newline (`--ir://json`: JSON string) |
| `run <command> [args...]` | Run a command with the resolved environment merged over the current one | the command's; exit code propagated |
| `dotenv` | Resolved environment as `K=v` lines | one `K=v` per line |
| `show` | Identity metadata merged over `.vauth_database` | JSON object |
| `set <key> <value>` | Store `KEY` (upper-cased) in `private/<login>/.vauth_database` | nothing |
| `unset <key>` | Remove a key from `.vauth_database` | nothing |
| `install` | Append the `venv` shell function to `~/.bashrc` | nothing |
| `version` (`--version`) | Build version | one line |

Diagnostics (`Vauth token: generated · https://vault · 12h`, `export K=[redacted]`,
errors) go to stderr; stdout is machine-readable for every command. Exit code is
`0` on success, `1` on error (or the child's code for `run`). `--renew` discards
the cached token and authenticates again.

```bash
vauth env --ir://json            # {"VAULT_TOKEN":"…","VAULT_ADDR":"…","TF_HTTP_USERNAME":"…"}
source <(vauth env --source)     # what the `venv` function does
vauth run -- terraform plan
```

## Environment

| Variable | Role |
| --- | --- |
| `VAUTHRC` | Explicit `.vauthrc` path; else `./.vauthrc`, then `~/.vauthrc` |
| `VAULT_ADDR` | Fallback when `.vauthrc` has no `vault_addr` |
| `VAULT_TOKEN` | Used as is when set (looked up, renewed in the last third of its lease) |
| `SSH_AUTH_SOCK` | Agent for `ssh_auth` and for the token cache; on Windows, else Pageant (≥ 0.75), else the OpenSSH pipe |
| `VAUTH_USER_IDENTITY`, `VAUTH_USER_MAIL` | Agent key selector for the token cache (first key otherwise) |
| `CI` | When set, `env.gitlab` does not derive `CI_PROJECT_*` from `git remote get-url origin` |

Tokens are cached in `~/.vauth/tokens/<sha256(vault_addr, ssh_auth, jwt_auth)>.creds`,
armored with [ssh-agent-crypt](https://github.com/131/ssh-agent-crypt);
`token_cache: false` disables the cache. Without an agent, nothing is written.

## Node module

```js
const Vauth = require('vvauth');
const vauth = new Vauth();             // reads .vauthrc and process.env
const token = await vauth.connect();   // connect(renew = false)
const env   = await vauth.env();       // env(source = false, renew = false) → object
await vauth.login(false, true);        // login(source, renew)
const profile = await vauth.show();    // {...database, ...metadata}
await vauth.set('KEY', 'value'); await vauth.unset('KEY');
```

`env(true)`, `login(true)` and `dotenv()` write to stdout and exit the
process; `run()` reads `process.argv`. Failures reject.

## Go module

```go
import vvauth "github.com/131/vvauth/v2"

v, err := vvauth.New()                 // .vauthrc + os.Environ()
token, err := v.Connect(false)         // renew bool
env, err := v.Env(false)               // *OrderedMap, document order
profile, err := v.GetProfile(false)    // EntityID, Metadata, Database; Merged()
err = v.Login(source, renew)
err = v.Set("KEY", "value"); err = v.Unset("KEY")
code, err := v.Run("terraform", "plan")
v.PublishEnv(env)                      // export lines on stdout, redacted echo on stderr
```

`Vauth` fields are public for embedding: `RC`, `VaultAddr`, `VaultToken`,
`Agent` (agent address, `sshagentcrypt.DefaultAgentAddress()` by default),
`TokenCache`, `CacheDir`, `HomeDir`, `Environ`, `Stdout`/`Stderr`/`Stdin`,
`Now`, `HTTPClient`. `LocateRC`, `ParseRC`, `ReplaceEnv`, `TokenCacheKey`,
`TokenCacheFile`, `ShellEscape` and `FunctionExists` are exported for tools
sharing the contract.

## Tests

Node and Go are tested against an in-process fake Vault (nonce, login, lookup,
renew, identity, KV) and a throwaway `ssh-agent`; both suites cover token reuse,
renewal in the final third, expiry, isolation of the cache by Vault and auth,
corrupt or plaintext cache rejection, identity selection and the interoperability
of the armored cache with the `ssh-agent-crypt` CLI.

```bash
npm install && npm run eslint && npm test
gofmt -l . && go vet ./... && go test ./...
```

CI (`test.yml`) runs both on Linux and Windows runners; `release.yml` builds the
static binaries on `v*` tags, signs the Windows one when `SIGNING_SERVER` is
set, and attaches `SHA256SUMS`.
