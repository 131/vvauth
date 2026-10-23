Vault Creds manager

This projects helps you log yourself in a HCL vault and retrieve VAULT_TOKEN through different auth methods
* jwt login
* ssh (through ssh-agent) login


# Installation

```bash
# node
npm install -g vvauth

# go
go install github.com/131/vvauth/v2/cmd/vauth@latest

# static binary, linux
wget -O vauth https://github.com/131/vvauth/releases/latest/download/vauth-linux-amd64
chmod +x vauth

# static binary, windows (curl.exe ships with every supported Windows, cmd or PowerShell)
curl.exe -fsSL -o vauth.exe https://github.com/131/vvauth/releases/latest/download/vauth-windows-amd64.exe
```

The [npm](https://www.npmjs.com/package/vvauth) module and the Go module ship
the same `vauth` command, flags and `.vauthrc`, and share the token cache.
Binaries are static, signed on Windows, with `SHA256SUMS` on every
[release](https://github.com/131/vvauth/releases); `vauth version` prints the
build version. On Windows, the SSH agent is `SSH_AUTH_SOCK` when set, else
Pageant (≥ 0.75, named pipe autodiscovery), else the OpenSSH agent pipe.

## The `venv` shell function

A program cannot change the environment of the shell that started it, so the
`VAULT_TOKEN`, credentials and `env.map` variables that `vauth` resolves have
to be *sourced*. `vauth install` appends this one-liner to `~/.bashrc`:

```bash
function venv() { source <(/usr/bin/env vauth env --source "$@"); }
```

`venv` then loads the resolved environment into the current shell (`venv
--renew` forces a fresh token); the exported names are echoed to stderr with
their values redacted. In scripts or CI, without a shell to source into, use
`vauth run <command>`, `vauth env --ir://json` or `vauth dotenv` instead.


# Vauth configuration
## Vauth configuration file location
vauth configuration file lies on a `.vauthrc` file (this name can be controlled by the VAUTHRC env var).
vauth will try to find
* if specified, the VAUTHRC file
* fallback to a .vauthrc file in the current directory
* fallback to a .vauthrc file in the current user home directory

##  Vauth configuration format
vauth configuration file is a simple yaml file with a specific macro expansion syntax for dynamic parts.
The configuration file should abide the following schema

### configuration macro expansion set
* $${profile.XXX} expand to vault entity metadata and user `.vauth_database` vars
* $${env.XXX} expand to local environement vars
* $${secrets.XXX} expand to remote scrapped secrets (see the env.paths)

```
# vauth URL
vault_addr: https://vauth.myserver.org

# for vauth-auth-plugin-ssh, configure the binding role here
ssh_auth:
  role: $${env.VAUTH_USER_LOGIN}
env:
  map:
    TF_HTTP_USERNAME: $${profile.VAUTH_USER_LOGIN}
    TF_HTTP_PASSWORD: $${profile.GITLAB_API_TOKEN}
    AWS_ACCESS_KEY_ID: $${secrets.AWS_ACCESS_KEY_ID}
    AWS_SECRET_ACCESS_KEY: $${secrets.AWS_SECRET_ACCESS_KEY}

  # remote secrets mecanism
  # set the secrets mount point - default to secrets
  [path: secrets]
  # list extra secrets to be reached and populated into the $${secrets.XXX} macro
  paths:
    - /some/pa4-backend.creds

```


# Machine-readable environment

`vauth env --ir://json` writes the resolved environment as one JSON object on
stdout; diagnostics stay on stderr, so a caller can parse stdout directly.
Every command, flag, output and the Node/Go module signatures are in
[API_and_tests.md](API_and_tests.md).

```bash
vauth env --ir://json
```


# Token cache

Tokens are cached in `~/.vauth/tokens/<session>.creds`, isolated by Vault and
authentication. Tokens are reused, renewed within their lease’s final third, or
replaced when expired. Existing `VAULT_TOKEN` takes precedence over cached tokens.

Each session file is armored using
[ssh-agent-crypt](https://github.com/131/ssh-agent-crypt) and your SSH agent’s
first key (`VAUTH_USER_IDENTITY`, then `VAUTH_USER_MAIL`, select another one).
Without an SSH agent, disk caching is disabled.

Set `token_cache: false` in `.vauthrc` to disable disk cache reads and writes.

## Force reauthentication

`venv --renew` forces authentication, generates and caches a new token.


# Credits
* [Francois Leurent](https://github.com/131)
* [OpenAI](https://openai.com) Codex (GPT 6.1-sol), in collaboration
* [Anthropic](https://www.anthropic.com) Claude (Fable 5.1), in collaboration
* Code signing, courtesy of Essilor International
