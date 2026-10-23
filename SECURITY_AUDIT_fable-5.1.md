# vvauth: design review by Codex (Claude Fable 5.1)

Independent review of the design and of the Node and Go implementations of
[vvauth](README.md), scoring Coolness, Robustness and Safety out of 20. The
companion review is [SECURITY_AUDIT_gpt-6.1-sol.md](SECURITY_AUDIT_gpt-6.1-sol.md).

## The design, as read

`vauth` turns a `.vauthrc` (YAML with `$${env.X}`, `$${profile.X}`,
`$${secrets.X}` macros) into a Vault token and a resolved environment. Two
authentication flows: `jwt_auth` (CI) and `ssh_auth`, where the agent signs a
nonce fetched from `auth/<path>/nonce`, so the user's SSH key is the identity
and nothing else is stored. The token is cached in
`~/.vauth/tokens/<sha256(vault_addr, ssh_auth, jwt_auth)>.creds`, armored with
ssh-agent-crypt (key derived from an agent signature), reused while valid,
renewed in the last third of its lease, replaced when expired or rejected.
`env --source` prints `export K='v'` lines for the `venv` shell function;
`--ir://json` prints one JSON object for automation. Node and Go share the
contract byte for byte (cache key, armor, outputs) and are cross-tested.

## Strengths

- No long-lived secret on disk besides a Vault token that is itself encrypted
  under the agent, with `0700`/`0600` modes, write-to-temp-then-rename, and a
  cache that degrades to "not persisted" rather than "stored in clear".
- Correct lease handling: renewal only in the final third, `lookup-self` TTL
  trusted over the local clock when the token is foreign, reauthentication only
  on `400`/`403`, never on network failures (no accidental token storm).
- Secret values never reach stdout unescaped in `--source` mode
  (`ShellEscape` single-quotes), `env.map` names are checked against
  `^[A-Za-z_][A-Za-z0-9_]*$` before they reach `export`, and the shell echoes
  `[redacted]`.
- The nonce is fetched fresh for every key tried; the agent only ever signs
  server-provided data, no private key is handled by the tool.
- Two implementations with the same fake-Vault test matrix catch divergence;
  the Go binary is static, signed, with `SHA256SUMS`; release runs the tests.

## Weaknesses and remedies

1. **`vault_addr` from the current directory redirects authentication.** A
   hostile `.vauthrc` points to an attacker-controlled "Vault"; the tool then
   fetches a nonce from it and has the agent sign it. The signature is over
   attacker-chosen bytes (bounded to valid UTF-8 by the JSON transport, which
   keeps it away from SSHSIG and SSH-userauth encodings, so no direct
   cross-protocol reuse today), and the public key and role name are sent to
   the attacker. *Remedy:* wrap the nonce in a vauth-specific preamble before
   signing (as SSHSIG does), or require `https` plus a pinned allow-list of
   Vault hosts in `~/.vauthrc`; at least surface the Vault address in the
   `Vauth token:` status line on first contact. More generally, a
   `./.vauthrc` from a cloned repository is trusted for everything; a cleaner
   model would let it carry only the project part (`env.map`, `env.paths`,
   `env.gitlab`) and keep `vault_addr`, `ssh_auth`, `jwt_auth` and
   `ssh-agent-crypt` to `~/.vauthrc` or `VAUTHRC`.
2. **Whoever reaches the agent socket reads the token cache.** By design of
   ssh-agent-crypt; nothing in vvauth adds a second factor. *Remedy:* document
   it next to `token_cache` and recommend `ssh-add -c` on the cache key
   (`SSH_AGENT_CRYPT_KEY` lets a dedicated, confirmed key be chosen).
3. **Macro expansion parity.** Go caps recursive expansion at 16 rounds; Node
   (`nyks/string/replaceEnv`) recurses until the stack overflows on a
   self-referencing value, and `$&`-style replacement patterns behave
   differently. *Remedy:* port the bounded loop to Node or fix it upstream, and
   add a cross-implementation fixture for pathological macros.
4. **Node constructor validates the current directory's `package.json`.** It
   `require`s `<dep>/package.json` for every dependency of whatever project the
   user is standing in and aborts on a semver mismatch. Unrelated to vauth,
   surprising, and a divergence from Go. *Remedy:* drop it, or scope it to
   vvauth's own manifest.
5. **Error swallowing.** `_read_token_cache` and the GitLab remote probe use
   bare `catch(err) {}`; Go returns `nil` from `readTokenCache` for any cause.
   A corrupt cache, a wrong key or a missing agent all look alike. *Remedy:* a
   `--debug`-visible reason (the `vvauth:debug` logger exists in Node).
6. **HTTP hygiene.** Node uses `url.parse` (deprecated, lenient) and a 60 s
   default timeout; Go uses `http.DefaultClient` with no timeout. Neither pins
   or restricts TLS. *Remedy:* `url.URL`, an explicit `http.Client{Timeout}`,
   and reject `http://` Vault addresses unless loopback.
7. **`install` rewrites `~/.bashrc` wholesale** (`0644`, trimmed, re-written),
   and `FunctionExists` runs `bash -lc`, executing the user's whole login
   profile. *Remedy:* append-only, and grep the file instead of spawning a
   login shell.
8. **Release integrity.** `SHA256SUMS` is unsigned and the Linux binary is
   unsigned; `release.yml` pulls `131/gh-actions@v1` by mutable tag. *Remedy:*
   sign the checksum file (or publish build provenance) and pin the action by
   commit.

## Scores

| Criterion | Score | Why |
| --- | ---: | --- |
| Coolness | 15/20 | One `.vauthrc`, one `venv`, and a Vault token appears from the SSH key you already carry, cached safely, identical from Node or a signed static binary. The macro language and the GitLab `CI_PROJECT_*` derivation make it a genuinely pleasant developer tool; what a repository's `./.vauthrc` may decide is the open question. |
| Robustness | 15/20 | Lease logic, cache isolation and Node/Go parity are tested and solid; loses on unbounded macro recursion in Node, the cwd `package.json` check, swallowed errors and the absence of HTTP timeouts in Go. |
| Safety | 14/20 | Good secret handling: encrypted cache, escaped values, validated variable names, no clear-text fallbacks. Loses on the blanket trust in `./.vauthrc` (a cloned repository picks the Vault and gets a raw agent signature), on the agent-socket exposure of the cache, and on HTTP without timeouts or transport constraints. |

Codex (Claude Fable 5.1)
