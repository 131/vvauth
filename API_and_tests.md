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
| `gitlab` (`--gitlab`, `venv --gitlab`) | Read `origin`; no authentication or configuration write | Only `CI_PROJECT_*` exports |
| `install` | Append the `venv` shell function to `~/.bashrc` | nothing |
| `version` (`--version`) | Build version | one line |

Diagnostics (`Vauth token: generated · 12h`, `export K=[redacted]`,
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
| `VAULT_TOKEN` | Returned offline by Connect without renewal/persistence; LookupSelf validates online when the profile is requested |
| `SSH_AUTH_SOCK` | Agent for `ssh_auth` and for the token cache; on Windows, else Pageant (≥ 0.75), else the OpenSSH pipe |
| `VAUTH_USER_IDENTITY`, `VAUTH_USER_MAIL` | Agent key selector for the token cache (first key otherwise) |

Tokens are cached in `~/.vauth/tokens/<sha256(vault_addr, ssh_auth, jwt_auth)>.creds`,
armored with [ssh-agent-crypt](https://github.com/131/ssh-agent-crypt);
`token_cache: false` disables the cache. Without an agent, nothing is written.

## Node module

```js
const Vauth = require('vvauth');
const vauth = new Vauth();             // reads .vauthrc and process.env
const token = await vauth.Connect();   // Connect(renew = false)
const env   = await vauth.Env();       // Env(source = false, renew = false) → object
await vauth.Login(false, true);        // login(source, renew)
const profile = await vauth.Show();    // {...database, ...metadata}
await vauth.Set('KEY', 'value'); await vauth.Unset('KEY');
```

Node extends the vauth-login client directly. `Connect`, `LookupSelf` and
`Request` are inherited, not forwarded through compatibility wrappers.
`GetProfile`, `Env`, `Show`, `Set`, `Unset`, `Login`, `Dotenv`, `Run`,
`Gitlab` and `PublishEnv` own the environment/profile behavior. `Version()` is static.
`RC`, `VAULT_ADDR` and `VAULT_TOKEN` are the inherited read-only getters.
`config` contains a mutable copy of only `env` and `ssh-agent-crypt`, with local
`env` macros expanded; the full frozen RC retains original values/macros.
vvauth does not reopen the selected configuration file.

`Env(true)`, `Login(true)`, `Dotenv()` and `PublishEnv()` write to stdout but do
not exit the SDK caller. `Run(command, ...args)` returns the child's exit code;
launch/authentication errors reject. Public methods use PascalCase without old
SDK aliases. The CLI independently keeps its lowercase commands and flags,
without reflecting inherited HTTP methods into CLI commands.

## Go module

```go
import vvauth "github.com/131/vvauth/v2"

v, err := vvauth.New()                 // .vauthrc + os.Environ()
token, err := v.Connect(false)         // renew bool
env, err := v.Env(false)               // *OrderedMap, deterministic output order
profile, err := v.GetProfile(false)    // EntityID, Metadata, Database; Merged()
err = v.Login(source, renew)
err = v.Set("KEY", "value"); err = v.Unset("KEY")
code, err := v.Run("terraform", "plan")
v.PublishEnv(env)                      // export lines on stdout, redacted echo on stderr
```

`Vauth` embeds `*vauthlogin.Vauth`; `Connect`, `LookupSelf` and `Request`,
the read-only `RC()`, `VAULT_ADDR()` and `VAULT_TOKEN()` readers, plus mutable
`Agent`, `TokenCache`, `CacheDir`, `HomeDir`, `Environ`, `Stderr`, `Now` and
`HTTPClient` settings, are owned by that client.
Use `New()` or supply the embedded client explicitly for isolated programmatic
use. `Config` holds only `Env`/`AgentCrypt`; `Stdout`/`Stdin` belong to vvauth.
`ParseConfig`, `ReplaceEnv`, `ShellEscape` and `FunctionExists` support environment and shell operations.
Construction consumes `RC()` directly: an independent JSON snapshot is decoded
into vvauth's own configuration, without reopening its file. The JSON map does
not retain YAML key order; `env.map` keys from this path have deterministic sorted
order. Explicit `OrderedMap.Set` calls and standalone `ParseConfig` keep their
insertion/YAML order. There is no second auth parser, token lifecycle, cache
implementation or HTTP transport in vvauth.

Node and Go consume vauth-login 1.1.5 and ssh-agent-crypt 1.4.2; Node uses nyks
6.17.0. `Gitlab()` asynchronously reads `origin` and publishes only `CI_PROJECT_PATH`,
`CI_PROJECT_NAME`, `CI_PROJECT_NAMESPACE` and `CI_PROJECT_PATH_SLUG` as shell exports.
`env.gitlab: true` makes `Env()` refuse missing project variables before any Vault
call, with a request to run `venv --gitlab` first. There is no Git inference at
construction, authentication in `Gitlab()`, or configuration-file update.

The SDK keeps language-native conventions: promises/throws in Node,
values plus errors in Go. Node `Env(source, renew)` can publish directly;
Go `Env(renew)` returns an ordered map for `PublishEnv`. CLI `--ir://json`
outputs JSON without a trailing newline in both implementations. JSON object
key order is not part of the profile (`show`) contract.

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
