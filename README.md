# vvauth

Resolve a shell environment from your Vault identity, private settings and
secrets. Available as Node/Go modules and the `vauth` CLI.

## Install

```bash
npm install -g vvauth
go install github.com/131/vvauth/v2/cmd/vauth@latest
```

[Releases](https://github.com/131/vvauth/releases) provide Linux binaries and
signed Windows binaries with checksums.

## Load the environment

```bash
vauth install
source ~/.bashrc
venv
venv --renew
```

`venv` sources `vauth env --source`. `--renew` forces fresh authentication.
For JSON output:

```bash
vauth env --ir://json
```

Diagnostics stay on stderr. [API and CLI details](API_and_tests.md).

## Configuration

The first existing file wins: `VAUTHRC`, `./.vauthrc`, then `~/.vauthrc`.
`VAULT_ADDR` supplies the address fallback.

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

Macros read local `env`, Vault `profile` or collected `secrets`. `env.git`
supplies Git identity fields; `ssh-agent-crypt` can provide local encrypted data.

With `env.gitlab: true`, initialize the four `CI_PROJECT_*` variables from origin:

```bash
venv --gitlab
```

This does not authenticate or modify configuration.

## Trust and credentials

Review and trust project configuration before sourcing it: it controls the
exported environment and local decryption. The Vault-address check is not a
sandbox for hostile configuration files. Review a project-selected Vault
before vouching for it in home configuration or the environment.

Inherited tokens are reused offline. `token_cache: false` disables encrypted
disk caching. Keep tokens and exports out of logs, shell traces and plaintext files.

## Assessments

[Claude](SECURITY_AUDIT_claude-opus-5-5.md), [Sol](SECURITY_AUDIT_gpt-6.1-sol.md),
[open risks](SECURITY_AUDIT_COORDINATION.md) and [provenance](SECURITY_AUDIT_PROVENANCE.json).
Reports identify their exact source and limits; they are not certification.

## Credits

François Leurent/131, OpenAI Codex and Anthropic Claude.
Code signing courtesy of Essilor International.
