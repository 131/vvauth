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
* $${profile.XXX} expand to vault entity metadata/custom_metadata vars
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

