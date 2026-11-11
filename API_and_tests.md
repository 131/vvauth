# API, CLI and verification

Node and Go implement the same authentication/profile/environment behavior.
Constructors, errors and return types stay native to each language. Their CLI
contracts differ except for the shared calls below.

## Shared calls

```bash
vauth env --ir://json
venv
venv --renew
venv --gitlab
```

`env --ir://json` writes one JSON object to stdout, with diagnostics on stderr.
JSON key order and final whitespace are not significant. `venv` sources
`vauth env --source "$@"`; renewal forces authentication.
On ordinary configuration/authentication/profile/macro errors, `env --source`
writes exactly `return 1\n` to stdout, preserves diagnostics on stderr and exits
nonzero. Sourcing that output returns 1 without exiting the caller or publishing
partial exports. Successful output and non-source error output are unchanged;
this does not cover crashes or a missing executable.

## Node CLI — cnyks

```text
vauth <command> [--parameter=value] [--ir://json | --ir://raw]
```

The first positional selects the command; remaining method arguments are named
flags, not positional remapping. Aliases expose `env`, `login`, `show`, `set`,
`unset`, `dotenv`, `install`, `version` and `gitlab`. `Connect` remains a hidden
SDK operation; cnyks retains its namespaced `vauth:Connect` entry, not a
short `Connect`/`connect` alias. cnyks also reflects other public
methods; its interactive rendering is not the Go CLI contract.

| Command | Parameters | Effect |
| --- | --- | --- |
| `env` | `--source`, `--renew`, `--gitlab` | Resolve environment, export it, or initialize GitLab variables |
| `login` | `--source`, `--renew` | Authentication only; optionally export only VAULT_TOKEN |
| `show` | — | Merged profile/private database |
| `set` | `--k=KEY --v=VALUE` | Store an upper-cased private key |
| `unset` | `--k=KEY` | Remove a private key |
| `dotenv` | — | Resolved K=v output |
| `install` | — | Install the venv shell function |
| `version` | — | Package version |
| `gitlab` | — | Only CI_PROJECT_* exports |

The executable is `cmd/vauth.js`; `index.js` only exports the SDK. Use
`--ir://json` for machine-readable return values. `env` selects raw cnyks output
when JSON was not requested, so sourcing does not show the runner menu.

## Go CLI — native

```text
vauth <command> [positionals...] [--flag=value] [--ir://json]
```

Commands are `env`, `login`, `show`, `set`, `unset`, `dotenv`, `install`, `version`
and `gitlab`. `set KEY VALUE` / `unset KEY` also accept `--k` / `--v`. Boolean
flags accept true, false, 0 and empty forms. `env` supports source, renew and
gitlab flags; `login` supports source and renew. Hidden `connect` remains
available for token-only callers. No command runner is part of this API.

Objects are JSON, strings are raw without JSON mode, and version is one line.
Exit is zero on success and one on failure; errors go to stderr.

## SDK

```js
const Vauth = require('vvauth');
const client = new Vauth();
const token = await client.Connect(renew);
const env = await client.Env(source, renew, gitlab);
await client.Login(source, renew);
const profile = await client.Show();
await client.Set(key, value);
await client.Unset(key);
await client.Gitlab();
```

```go
client, err := vvauth.New()
token, err := client.Connect(renew)
env, err := client.Env(renew)
err = client.Login(source, renew)
profile, err := client.Show()
err = client.Set(key, value)
err = client.Unset(key)
err = client.Gitlab()
```

`Connect`, `LookupSelf`, `Request`, immutable `RC` and address/token readers
belong to vauth-login. vvauth owns `Config`/`config`, profiles, KV operations,
macro expansion, shell publication and GitLab initialization. Constructors
check required CI variables when `env.gitlab` is true; explicit initialization
bypasses that prerequisite. There is no Git inference at construction.

RC is the complete raw configuration; environment sections are copied before
macro expansion. Both support
SSH-agent-backed local secret decryption, inherited tokens and forced renewal.
`env.map` names must be valid environment names. Values become strings; null
becomes empty, and objects/arrays are rejected, including macro results. Raw RC
values retain their JSON types. Missing Git identity fields export empty values.

## Configuration trust boundary

The selected configuration controls exported variable names/values and which
local armored files are decrypted. Name validation enforces shell syntax,
not a variable allowlist. Review and trust a project configuration before
sourcing it with `venv`; this tool is not a sandbox for hostile configurations.
The Vault-origin guard checks authentication destinations, not every effect
of the environment exported into the calling shell.

## Verification

```bash
npm install
npm run eslint
npm test
go vet ./...
go test -race ./...
GOOS=windows GOARCH=amd64 go build ./cmd/vauth
```

`test/env-source.js` checks exact failure stdout, nonzero CLI status, Bash
process-substitution sourcing and continued execution, plus successful exports,
renewal flags and non-source failures. It uses temporary homes/configurations
and a loopback Vault. `cmd/vauth/main_test.go` builds the native Go CLI and runs
the same checks against that executable (requires Node and Bash).

Tests use disposable SSH keys/agents, temporary configuration and loopback
Vault fixtures; they do not require real credentials. Differential checks cover
profile/KV operations, renewal, trust refusal, local secrets, configuration,
JSON environment output and the shared armor/cache. Linux/Windows builds and
Node 16 parsing/loading are checked separately. Release CI publishes npm,
Go tags and Linux/signed Windows binaries; verify asset checksums independently.

## Delegation verification

The public SDK operation is `Delegate(role, renew)`: Node returns a promise of a
string; Go returns `(string, error)`. `renew` forces only the child. `Env` keeps
its existing parent-renew flag behavior and passes the flag to child issuance
without logging in the parent again. No new CLI flag is needed.

`test/delegate.js` and `delegate_test.go` use synthetic parent/child credentials
and in-memory transport for roles, macros, TTL boundary reuse, renewal, parent
changes, invalid responses, unknown references, disk-off memory reuse and
failure-before-output. Go also verifies cache-key composition against Node.
SSH-agent tests verify encrypted persistence and bidirectional Node/Go cache
reuse; they need a throwaway SSH agent, not a real Vault or personal key.
`delegate_interop_test.go` exercises both languages' real parent `Connect`,
fresh-client disk reuse through the full TTL, exact expiry, request latency,
renewal and parent/role/address isolation. It runs in `go test ./...`.

Run the new tests without network or dependency changes:

```bash
node test/delegate.js
GOPROXY=off GOFLAGS=-mod=readonly go test -v delegate.go delegate_test.go vauth.go rc.go vault.go gitlab.go
```

The explicit Go file list avoids the historical suite's unconditional agent
`TestMain`; encrypted-cache tests skip if a synthetic agent cannot start. Full
regressions remain `npm test` and `GOPROXY=off GOFLAGS=-mod=readonly go test ./...`.
A restricted host that cannot bind SSH-agent sockets cannot validate the full
suite or encrypted interop. The socket-free recipe does not establish that
those skipped checks passed.

Server role ACLs, entity/group grants and JWT/OIDC authority configuration are
not simulated or applied here. `Env` needs its parent's existing profile-read
grants; `Delegate` does not. These tests do not establish production grants or
permission to issue a child under a particular authentication method.
