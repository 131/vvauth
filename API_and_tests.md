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
`vauth env --source "$@"`; renewal forces authentication. GitLab initialization
publishes only four `CI_PROJECT_*` exports, without login, cache or file writes.

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
macro expansion. Go snapshot maps do not retain YAML key order. Both support
SSH-agent-backed local secret decryption, inherited tokens and forced renewal.
`env.map` names must be valid environment names. Values become strings; null
becomes empty, and objects/arrays are rejected, including macro results. Raw RC
values retain their JSON types. Missing Git identity fields export empty values.

Go macro expansion and value walking come from `github.com/131/nyks/v6`.
Configuration operates on JSON-compatible values rather than round-tripping
RC through a YAML tree. Walking preserves keys and the raw RC snapshot;
`env.map` validation and scalar-to-string conversion remain in vvauth.

## Verification

```bash
npm install
npm run eslint
npm test
go vet ./...
go test -race ./...
GOOS=windows GOARCH=amd64 go build ./cmd/vauth
```

Tests use disposable SSH keys/agents, temporary configuration and loopback
Vault fixtures; they do not require real credentials. Differential checks cover
profile/KV operations, renewal, trust refusal, local secrets, configuration,
JSON environment output and the shared armor/cache. Linux/Windows builds and
Node 16 parsing/loading are checked separately. Release CI publishes npm,
Go tags and signed Windows/Linux binaries; verify asset checksums independently.
