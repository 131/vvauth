Vault Creds manager

This projects helps you log yourself in a HCL vault and retrieve VAULT_TOKEN through different auth methods
* jwt login
* ssh (with agent) login


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


# Credits
* [Francois Leurent](https://github.com/131)


# Machine-readable environment

`vauth env --ir://json` resolves the same environment as `vauth env --source`
and asks the `cnyks` runner to write one JSON object to stdout. Diagnostic
messages remain on stderr, so a caller can parse stdout directly.

```bash
vauth env --ir://json
```


# Token cache

Tokens are cached in `~/.vauth/tokens/<session>.creds`, isolated by Vault and
authentication. Tokens are reused, renewed within their lease’s final third, or
replaced when expired. Existing `VAULT_TOKEN` takes precedence over cached tokens.

Each session file is armored using `ssh-agent-crypt` and your SSH agent’s first
key. Without an SSH agent, disk caching is disabled.

Set `token_cache: false` in `.vauthrc` to disable disk cache reads and writes.

## Force reauthentication

`venv --renew` forces authentication, generates and caches a new token.
