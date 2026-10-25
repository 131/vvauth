# API and CLI

## Shared calls

```bash
vauth env --ir://json
venv
venv --renew
venv --gitlab
```

JSON output is one object on stdout; order and final whitespace are insignificant.
Diagnostics stay on stderr. GitLab initialization exports four `CI_PROJECT_*`
variables without authenticating.

## Node CLI — cnyks

```text
vauth <command> [--parameter=value] [--ir://json | --ir://raw]
```

Arguments are named flags after the command. `env` uses raw output by default.

| Command | Parameters | Result |
| --- | --- | --- |
| `env` | `--source`, `--renew`, `--gitlab` | Environment/export or GitLab initialization |
| `login` | `--source`, `--renew` | Token or VAULT_TOKEN export |
| `show` | — | Merged profile/private database |
| `set` | `--k=KEY --v=VALUE` | Store an upper-cased private key |
| `unset` | `--k=KEY` | Remove a private key |
| `dotenv` | — | K=v output |
| `install` | — | Install the venv shell function |
| `version` | — | Version |
| `gitlab` | — | CI_PROJECT_* exports |

cnyks also reflects public SDK methods. Hidden `Connect` is callable through
`vauth:Connect` without a short alias.

## Go CLI

```text
vauth <command> [positionals...] [--flag=value] [--ir://json]
```

The same commands are available. `set KEY VALUE` / `unset KEY` also accept
`--k` / `--v`. Boolean flags accept true, false, 0 and empty forms. Hidden
`connect` returns only a token. Strings are raw outside JSON mode; errors
are stderr with exit 1.

## SDK

```js
const Vauth = require('vvauth');
const client = new Vauth();
const env = await client.Env(source, renew, gitlab);
const profile = await client.Show();
await client.Set(key, value);
await client.Unset(key);
await client.Login(source, renew);
await client.Gitlab();
```

```go
client, err := vvauth.New()
// Check err before using client.
env, err := client.Env(renew)
profile, err := client.Show()
err = client.Set(key, value)
err = client.Unset(key)
err = client.Login(source, renew)
err = client.Gitlab()
```

Authentication methods/readers are inherited from
[vauth-login](https://github.com/131/vauth-login). `Config`/`config` holds environment
settings. Constructors require CI variables when `env.gitlab` is true;
explicit GitLab initialization bypasses that prerequisite.

RC keeps the original configuration; expansion does not mutate it. `env.map`
names must be valid environment names. Scalars become strings, null becomes
empty, objects/arrays are rejected, including macro results. Missing Git
identity fields export empty strings.

## Tests

```bash
npm install
npm run eslint
npm test
go vet ./...
go test -race ./...
```

Disposable agents, temporary configuration and loopback Vault fixtures cover
profiles/KV, environment output, renewal, local secrets, trust refusal and CLI.
