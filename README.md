# vvauth

Resolve a shell environment from your Vault identity, private settings and
secrets. [vauth-login](https://github.com/131/vauth-login) owns authentication,
HTTP and token caching; [ssh-agent-crypt](https://github.com/131/ssh-agent-crypt)
protects local secrets. Node and Go are canonical implementations.

## Install

```bash
npm install -g vvauth
go install github.com/131/vvauth/v2/cmd/vauth@latest
```

Native Linux and signed Windows binaries, with checksums, are available from
[GitHub Releases](https://github.com/131/vvauth/releases).

## Load the environment

```bash
vauth install
source ~/.bashrc
venv
venv --renew
```

`vauth install` defines the Bash function `venv` in `~/.bashrc`:

```bash
function venv() { source <(/usr/bin/env vauth env --source "$@"); }
```

`source ~/.bashrc` loads it in the current shell. `--renew` forces fresh
authentication. For a machine-readable result:

```bash
vauth env --ir://json
```

Both implementations write one JSON object to stdout; diagnostics remain on
stderr. Node uses cnyks for its CLI; Go has a native command interface.
[API_and_tests.md](API_and_tests.md) defines both contracts.

## Configuration

The first existing configuration is selected: `VAUTHRC`, `./.vauthrc`, then
`~/.vauthrc`. It is YAML; `VAULT_ADDR` supplies the address fallback.
The resolved SSH role is normalized to lowercase by vauth-login in both
implementations; the source configuration, other fields and JWT roles are unchanged.

```yaml
vault_addr: https://vault.example.test
ssh_auth:
  role: $${env.VAUTH_USER_LOGIN}
env:
  map:
    TF_HTTP_USERNAME: $${profile.VAUTH_USER_LOGIN}
    TF_HTTP_PASSWORD: $${profile.GITLAB_API_TOKEN}
    AWS_SECRET_ACCESS_KEY: $${secrets.AWS_SECRET_ACCESS_KEY}
  path: secrets
  paths:
    - /some/backend.creds
```

Macros read local `env`, Vault `profile` (entity metadata and the user's
`.vauth_database`), or collected `secrets`. `env.git` supplies Git author and
committer fields. A `ssh-agent-crypt` section can supply local encrypted secrets
without contacting Vault when no SSH/JWT authentication is configured.

With `env.gitlab: true`, project variables must already exist in the shell.
Initialize them explicitly from `origin`:

```bash
venv --gitlab
```

## Tokens and trust

An inherited `VAULT_TOKEN` is reused offline. Otherwise, vauth-login handles
login and the SSH-agent-encrypted cache in `~/.vauth/tokens`. `token_cache: false`
disables disk caching. SSH uses `SSH_AUTH_SOCK`, or native Windows Pageant/OpenSSH
pipe discovery. Review a project-selected Vault before vouching for it in the
home configuration or environment.

Review and trust the project configuration before sourcing it. It controls
the exported environment and local file decryption; the Vault-address check
is not a sandbox for hostile configuration files.

Tokens and resolved secrets are credentials: do not log them or store plaintext
exports. Neither implementation prompts to trust an unknown project Vault.

## Role-scoped delegation

Declare Vault token roles at the root and export their children only where needed:

```yaml
vault_addr: https://vault.elipsdev.net
ssh_auth:
  role: $${env.VAUTH_USER_LOGIN}
delegate:
  - vauth-profile-ro
env:
  map:
    VAULT_ROUTER_TOKEN: $${delegate.vauth-profile-ro}
```

Each entry names a server token role directly. `$${delegate.<role>}` resolves to
its child token string. Multiple roles are supported; declaring a role does not
export it automatically. `VAULT_TOKEN` remains the human/login token.

Node `await client.Delegate(role, renew = false)` and Go
`client.Delegate(role, renew)` return a token string (with native errors).
They reuse the established parent and call `auth/token/create/<role>` on a miss.
The request asks for a non-renewable service child without the default policy;
the role must be non-orphan and owns the ACL. No policies or entity alias are
overridden or checked by the client. A new child requests the parent's current
positive, finite remaining TTL, obtained from lookup-self, not its original
lease duration. A parent with TTL zero has no usable bounded delegation lifetime
and is rejected. A child TTL exceeding that requested remaining lifetime is
also rejected rather than capped. A rejected parent lookup (400/403) permits one normal login
retry; issuance errors never cause a human-token fallback.

The separate SSH-agent-encrypted cache lives in `~/.vauth/delegates`, using the
same encryption dependency in Node and Go. Its filename hashes the JSON tuple
`[Vault address without surrounding slashes, parent token, role]`; plaintext
cache content contains only the child and its expiration time in Unix
milliseconds. The parent lookup and child creation TTLs are anchored at each
request start: elapsed lookup time is deducted from the requested parent
lifetime, and response/processing time never extends the child deadline. A child
already expired on arrival is rejected. Children remain reusable until that
deadline, without online lookup on a cache hit. Expiry, a changed
parent/role/address or explicit child renewal emits a new child. `token_cache: false` disables disk access, not in-memory reuse.
Unavailable persistence leaves the child usable in memory; it never substitutes
the human token. An unknown delegation macro, invalid response or issuance error
fails environment resolution before any exports are published.

`Env` calls `GetProfile`: entity metadata and, when a login metadata field
exists, the personal `.vauth_database`. Its parent therefore needs those read
permissions. `Delegate` itself performs neither profile read; its parent only
needs permission to use the selected token role. JWT/SSH/OIDC grants and child
issuance permissions are decided by the Vault authority, not by this client.
Delegation does not add permissions to the parent.

## Security assessments

[Claude](SECURITY_AUDIT_claude-opus-5-5.md) and
[Sol](SECURITY_AUDIT_gpt-6.1-sol.md) reports identify their exact source commit,
checks and limitations. They are independent source reviews, not certification.
[Coordination and open risks](SECURITY_AUDIT_COORDINATION.md) distinguish
reviewer limitations from host validation; [provenance](SECURITY_AUDIT_PROVENANCE.json)
records the exact source, models and prompt/report hashes.

| Criterion | Claude Opus 5.5 | GPT 6.1 Sol |
| --- | ---: | ---: |
| ✨ **Coolness** | 15/20 | 17/20 |
| Robustness | 13/20 | 13/20 |
| Safety | 13/20 | 12/20 |

## Credits

- [Francois Leurent](https://github.com/131)
- OpenAI Codex and Anthropic Claude, in collaboration
- Code signing, courtesy of Essilor International
