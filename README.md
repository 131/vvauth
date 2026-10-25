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

`venv` sources the exports produced by `vauth env --source`. `--renew` forces
fresh authentication. For a machine-readable result:

```bash
vauth env --ir://json
```

Both implementations write one JSON object to stdout; diagnostics remain on
stderr. Node uses cnyks for its CLI; Go has a native command interface.
[API_and_tests.md](API_and_tests.md) defines both contracts.

## Configuration

The first existing configuration is selected: `VAUTHRC`, `./.vauthrc`, then
`~/.vauthrc`. It is YAML; `VAULT_ADDR` supplies the address fallback.

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

This exports only `CI_PROJECT_PATH`, `CI_PROJECT_NAME`, `CI_PROJECT_NAMESPACE`
and `CI_PROJECT_PATH_SLUG`. It does not authenticate or modify configuration.

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

## Security assessments

[Claude](SECURITY_AUDIT_claude-opus-5-5.md) and
[Sol](SECURITY_AUDIT_gpt-6.1-sol.md) reports identify their exact source commit,
checks and limitations. They are independent source reviews, not certification.
[Coordination and open risks](SECURITY_AUDIT_COORDINATION.md) distinguish
reviewer limitations from host validation; [provenance](SECURITY_AUDIT_PROVENANCE.json)
records the exact source, models and prompt/report hashes.

## Credits

- [Francois Leurent](https://github.com/131)
- OpenAI Codex and Anthropic Claude, in collaboration
- Code signing, courtesy of Essilor International
