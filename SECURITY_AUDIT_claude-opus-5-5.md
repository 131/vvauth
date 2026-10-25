# Security Audit: vvauth (claude-opus-5-5)

- **Repository:** `github.com/131/vvauth` (canonical remote `git@github.com:131/vvauth.git`, branch `master`)
- **Assessed commit:** `f368802700f03c8b632bbacefbfc71dbfaae04f4`. This is pre-release functional source with manifests at 2.6.0. The upcoming patch release is not published and was not assessed.
- **Date:** 2026-10-25
- **Provenance:** The host configured this run as **claude-opus-5-5** (`codex exec --ephemeral --sandbox read-only`, web search disabled). The agent cannot look up its own model identity apart from that configuration and knows of no difference from it. The host verifies execution metadata separately. The review used source only: it read the repository and selected installed dependency sources from the local filesystem, with no network access.
- **Excluded inputs (contents never read, searched or diffed):**
  - every `SECURITY_AUDIT*.md` file at any depth, including the ones listed in this repository and in the module cache
  - `README.md` at any depth
  - prior assessment content in Git history, including commit messages
  - README, audit and advisory Markdown in dependencies
  - the `Verification` section of `API_and_tests.md`, which could not be safely ruled free of assessment content and was skipped
  - client configuration, environment values (except `AGENT_WORKSPACE`, used only to locate the instructions file), credentials and real Vault services

  No excluded assessment content entered the inputs.

---

## 1. Scope and method

### 1.1 Input inventory

The full file list came from `git ls-files`. Filenames are metadata only.

`.eslintignore`, `.eslintrc`, `.github/workflows/{publish-npm,release,test}.yml`, `.gitignore`, `.goreleaser.yaml`, `.npmrc`, `API_and_tests.md`, `README.md` *(excluded)*, `SECURITY_AUDIT_fable-5.1.md` *(excluded)*, `SECURITY_AUDIT_gpt-6.1-sol.md` *(excluded)*, `cmd/vauth.js`, `cmd/vauth/main.go`, `gitlab.go`, `gitlab_test.go`, `go.mod`, `go.sum`, `index.js`, `package.json`, `rc.go`, `test/token-cache.js`, `vault.go`, `vauth.go`, `vauth_test.go`.

**Repository files selected and read:**
- `index.js`, `cmd/vauth.js`
- `vauth.go`, `rc.go`, `vault.go`, `gitlab.go`, `cmd/vauth/main.go`
- `test/token-cache.js` (selected ranges plus the test list), `vauth_test.go` and `gitlab_test.go` (test list plus selected ranges)
- `package.json`, `go.mod`, `go.sum` (selected lines), `.npmrc`, `.gitignore`, `.goreleaser.yaml`, the three workflows
- `API_and_tests.md`: headings were listed first, then only lines 1–116 were printed (sections *Shared calls*, *Node CLI*, *Go CLI*, *SDK*, *Configuration trust boundary*). The *Verification* section (line 117 onward) was not read.

**Dependency sources selected and read:**

| Module | Files read |
| --- | --- |
| `vauth-login` 1.1.7, Node | `node_modules/vauth-login/index.js` |
| `vauth-login` v1.1.7, Go (module cache) | `rc.go`, `cache.go`, `vault.go`, `vauth.go` |
| `nyks` 6.18.0, Node | `http/request.js`, `string/replaceEnv.js` |
| `nyks/v6` v6.18.0, Go | `string/replaceEnv.go` |
| `ssh-agent-crypt` 1.4.4, Node | `index.js` (grep-level) |
| `ssh-agent-crypt` v1.4.4, Go | `sshagentcrypt.go` (key derivation and decrypt sections) |

Installed versions match the stated pins: vauth-login 1.1.7, ssh-agent-crypt 1.4.4, nyks 6.18.0, cnyks 3.2.4. Workspace instructions came from `$AGENT_WORKSPACE/AGENTS.md`. The repository is unmapped and has no project `AGENTS.md`, `STYLE.md`, `.vauthrc` or `.ai/memory`, so no neighboring rules were borrowed.

### 1.2 Safe local checks

All checks ran offline with `GOPROXY=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local`.

| Check | Result |
| --- | --- |
| `gofmt -l .` | Clean (no output) |
| `go vet ./...` | **Could not run.** The Go build cache (`/root/.cache/go-build`) is on a read-only filesystem. |
| `go test ./...` | **Not run**, for the same reason. |
| `node --test test/token-cache.js` | **Ran but failed.** The test fixtures need a writable `os.tmpdir()` (`mkdtempSync`) to create disposable keys, agents and HOMEs, and `/tmp` is read-only. This says nothing about the code under test. |
| Targeted `node -e` probes of `nyks/string/replaceEnv` | Pure functions, synthetic dictionaries only, no I/O. Used to confirm finding F-1. |
| Toolchain | Local Go 1.24.0 and Node 22.22.2 (the CI uses Node 24 / 16 and Go from `go.mod`). |

### 1.3 Checks not run, and why

- **`npm install`, `npm audit`, `go mod download`, `govulncheck`, OSV/GHSA lookups:** all need network access, which is out of scope.
- **Go build, vet and test:** the build cache is read-only.
- **Node tests:** the temporary directory is read-only.
- **Real Vault, agent or credential flows:** prohibited.
- **Windows runtime behavior:** no Windows host.

---

## 2. Prioritized findings

Each finding is labeled either a **verified observation** (confirmed by reading source and/or a local probe) or a **hypothesis** (plausible, but not demonstrated end to end).

### F-1: Macro expansion corrupts values, allows second-order expansion, and can recurse without bound
**Severity: Medium. Verified observation (Node probe; Go by source reading).**

**Evidence:**
- `index.js:197` and `vauth.go:318` pass every `env.map` value through `replaceEnv` with `{env, profile, secrets}`.
- Node `nyks/string/replaceEnv.js:20` does `str = str.replace(match[0], v)` with a *string* replacement, so JavaScript replacement patterns inside the substituted value (`$$`, `$&`, `` $` ``, `$'`) are interpreted.
- `replaceEnv.js:23-24` then calls itself again on the result.
- Go `nyks/v6/string/replaceEnv.go:73-95` deliberately emulates the same replacement semantics. Lines 15–16 and 50 say: "no artificial pass limit or cycle guard".

**Local probe (synthetic values, substituted via `$${secrets.X}`):**

| Secret value | Result |
| --- | --- |
| `ab$$cd` | `ab$cd` (silently altered) |
| `pa$$word` | `pa$word` |
| `` p$`q `` | `ppre-q` (prefix duplicated) |
| `x$&y` | `RangeError: Maximum call stack size exceeded` (crash) |
| `$$$${secrets.D}` | the value of **another** secret `D` (second-order expansion) |
| `prefix-$${secrets.N}` with `N: null` | whole value becomes `null`, so the export is empty and the prefix is lost |

**Impact:**
- Passwords and tokens containing `$` sequences can be exported with wrong values, without any warning. This is a correctness and availability problem for real secrets.
- A value containing `$&` crashes Node. Go recurses the same way without a guard; that it ends in stack exhaustion there is inferred from the code.
- Whoever can write a Vault KV value, an identity-metadata field, a `.vauth_database` entry (`vauth set`) or an environment variable can make another variable expand into data that the configuration did not reference. Everything stays in the same user's shell, so the confidentiality impact is limited, but the configuration's intent is not honored.

**Suggested fix:**
- Expand in a single pass over the template only, substituting with a replacer *function* (`str.replace(re, (_, a, b) => ...)`) or the Go equivalent, and never re-scan substituted text.
- If recursion must stay, add a depth or cycle guard.
- Add regression tests for values containing `$$`, `$&`, `` $` ``, `$'` and self-references, on both runtimes.
- This belongs in `nyks`. vvauth could also pre-escape secrets or substitute without nyks.

### F-2: npm publication depends on unlocked, script-executing dependencies while holding an OIDC publish credential, with no approval gate
**Severity: Medium. Verified observation (configuration); exploitation is a hypothesis.**

**Evidence:**
- `.github/workflows/publish-npm.yml:2` triggers `on: create` and filters on tag refs at line 9, with `permissions: id-token: write` at lines 4–6.
- It runs plain `npm install` (line 19, which runs install scripts) and then `npm publish` (line 25). There is no `environment:` protection; `release.yml:13` uses `environment: production`, but the npm job does not.
- `.npmrc` sets `package-lock=false`, and `.gitignore` ignores `package-lock.json`. Every publish therefore resolves a fresh dependency tree from caret ranges, including devDependencies (`eslint`, `nyc`, and `mocha ^3.1.2` / `expect.js` that the `node --test` suite does not appear to use).
- No step checks that the tag matches `package.json`'s `version`.

**Impact:**
- A compromised or typosquatted transitive dependency's install script runs in the same job that can mint the npm trusted-publishing OIDC token, and could publish a malicious `vvauth` to external users.
- Anyone who can push a `v*` tag can publish without review.
- A tag/manifest mismatch (for example tag `v2.6.1` while `package.json` says 2.6.0) gives inconsistent artifacts: the native binaries take the tag version, while npm publishes the manifest version or fails.

**Suggested fix:**
- Split the job. Test in a job without `id-token`, then publish from a minimal job that runs `npm install --omit=dev --ignore-scripts` (or `npm ci` against a committed lockfile).
- Put that publish job behind a protected `environment` with required reviewers, and use explicit `npm publish --provenance`.
- Add a tag == `package.json` version == `go.mod` comment check.
- Remove unused devDependencies (`mocha`, `expect.js`, possibly `nyc`).

### F-3: Release and signing pipeline uses mutable third-party references
**Severity: Medium. Verified observation (configuration).**

**Evidence:**
- Every action is referenced by a mutable major tag: `actions/checkout@v4`, `actions/setup-node@v4`, `actions/setup-go@v5`, `goreleaser/goreleaser-action@v6`.
- `release.yml:22-26` checks out `131/gh-actions` at mutable `ref: v1` into `.gh-actions`. `.goreleaser.yaml:19` executes `.gh-actions/sign-binaries/sign {{ .Path }}` with `SIGNING_SERVER` in the environment (`release.yml:33`), and `GITHUB_TOKEN` has `contents: write`.
- GoReleaser itself floats (`version: '~> v2'`).
- Native Linux binaries are not code-signed. `SHA256SUMS` is produced but not signed, and no build-provenance attestation is generated.

**Impact:** Whoever controls those tags (or compromises them) can run code with signing-server access and release write permission. Users can only check the Linux binary against an unsigned checksum file published from the same location.

**Suggested fix:**
- Pin actions and `131/gh-actions` to full commit SHAs and pin the GoReleaser version.
- Sign `SHA256SUMS` (for example cosign or minisign) and/or add `actions/attest-build-provenance`.
- Consider publishing SBOMs.

### F-4: The Go toolchain pin points at an end-of-life release line, x/crypto is stale, and no vulnerability scan runs
**Severity: Medium. Hypothesis about concrete CVEs; the pins themselves are verified.**

**Evidence:**
- `go.mod:5` says `go 1.22` with no `toolchain` line. `setup-go` with `go-version-file: go.mod` (`release.yml:18-20`, `test.yml`) will therefore build release binaries with the latest Go 1.22.x patch.
- The Go 1.22 line stopped receiving security fixes in early 2025.
- `go.mod` and `go.sum:11` pin `golang.org/x/crypto v0.31.0` (December 2024), which supplies `ssh` and `ssh/agent` to the agent-signing path. `x/sys` is at v0.28.0.
- No `govulncheck` or `npm audit` step exists in CI.

**Impact:** Shipped native binaries may contain unpatched standard-library (net/http, crypto/tls, x509) and x/crypto/ssh issues fixed in later releases. This could not be confirmed offline.

**Suggested fix:**
- Add `toolchain go1.<supported>` (or raise `go`) so releases build with a supported patch line.
- Bump `x/crypto` and `x/sys`.
- Add `govulncheck ./...` and a Node dependency audit to CI, gated before release.

### F-5: Sourcing a project `.vauthrc` amounts to running shell code; only names are validated
**Severity: Low–Medium. Verified observation; the trust boundary is documented.**

**Evidence:**
- `index.js:195` and `vauth.go:315,329` enforce only `^[A-Za-z_][A-Za-z0-9_]*$` on `env.map` keys. Values are single-quoted correctly (`index.js:268-271`, `vauth.go:356-358`).
- The installed function `source <(vauth env --source "$@")` (`index.js:26`, `vauth.go:36`) therefore lets a cwd `.vauthrc` export `PROMPT_COMMAND`, `BASH_ENV`, `ENV`, `PS0`–`PS4`, `PATH`, `LD_PRELOAD`, `GIT_SSH_COMMAND` and similar variables.
- In bash, `PROMPT_COMMAND` executes at the next prompt, so a cloned hostile repository plus `venv` gives arbitrary code execution with access to the exported `VAULT_TOKEN`.
- `API_and_tests.md` ("Configuration trust boundary") states that the tool is not a sandbox. The Vault-origin guard (vauth-login `index.js:101-106,312-314`; Go `vauth.go:156-158`, `vault.go:44-46`) protects only authentication destinations.

**Impact:** `venv` in an untrusted checkout can lead to token theft or code execution. This is the dominant real-world risk for this tool's usage pattern.

**Suggested fix:**
- Apply the `known_vaults` model to configurations: trust-on-first-use by content hash of `./.vauthrc` recorded in `~/.vauthrc`, or an interactive confirmation.
- In addition, deny or require opt-in for known execution-affecting names (`PROMPT_COMMAND`, `BASH_ENV`, `ENV`, `PS*`, `PATH`, `LD_*`, `DYLD_*`, `*_COMMAND`, `IFS`, `SHELLOPTS`, `BASHOPTS`).

### F-6: Local-credential mode exports an untrusted `VAULT_ADDR` together with the inherited token without passing the origin guard
**Severity: Low. Verified observation by source reading; exploitation preconditions are a hypothesis.**

**Evidence:**
- When `ssh-agent-crypt` is configured and neither `ssh_auth` nor `jwt_auth` is (`index.js:155-157`; `vauth.go:244-248`), `Env` only calls `Connect`. With an inherited `VAULT_TOKEN`, `Connect` returns it offline (vauth-login `index.js:183-187`; Go `vauth.go:211-215`) and never calls `Request`, so the unknown-vault check is never reached.
- `Env` then exports `VAULT_TOKEN` and `VAULT_ADDR`, with the latter taken from the project `vault_addr` (`index.js:163-166`; `vauth.go:257-262`).
- The Node test `local .creds environment works offline` (`test/token-cache.js:786-803`) confirms that no request occurs. The unknown-vault test (`:887-916`) covers only `env` and `show` without local credentials.
- Precondition: `ssh-agent-crypt.path` must point to a file the victim's agent can decrypt, for example another project's armored file referenced through `$${env.HOME}`. Otherwise decryption fails before anything is published.

**Impact:** Later `vault` CLI calls in that shell would send the user's inherited token to an address the user never approved.

**Suggested fix:** Run the known-vault check whenever `VAULT_ADDR` is *exported*, not only when a request is made. Either refuse, or omit `VAULT_ADDR`/`VAULT_TOKEN`, when `_safe_vault` / `unknownVault` is set. Add a test for that combination.

### F-7: Arguments forwarded by `venv` can turn off `--source`, so the token-bearing JSON is sourced as a command
**Severity: Low. Verified observation (Go); Node behavior is a hypothesis.**

**Evidence:**
- `venv` forwards `"$@"` after `--source`.
- In Go, `param()` gives positionals priority over flags (`cmd/vauth/main.go:291-297`), and `env` reads `source` from the first positional (`:338`). `venv 0`, `venv false`, `venv ""` or `venv --source=false` (the last flag value wins in `parseArgs`, `:268-274`) therefore makes `source` false.
- `respond` then prints the environment JSON, including `VAULT_TOKEN`, to stdout (`:347`, `:408-410`), and bash executes it. The resulting `command not found` diagnostic echoes the JSON, token included, to the terminal and any stderr log.
- Node: cnyks probably resolves `--source=false` the same way; not confirmed.

**Impact:** Token disclosure to stderr after a user typo.

**Suggested fix:** Give `env --source` its own internal entry point that ignores user overrides, or have the shell function call a distinct `vauth publish-env "$@"`. Reject positional booleans for `source`. Never print token-bearing JSON when stdout is consumed by `source`; in that case, fail closed and print nothing.

### F-8: `dotenv` output is not escaped
**Severity: Low. Verified observation.**

**Evidence:** `index.js:212-214` and `vauth.go:366-368` write `K=v` verbatim.

**Impact:** A value containing a newline produces extra `KEY=…` lines. A secret or profile value (see F-1) can inject variables into consumers such as docker `--env-file` or dotenv loaders, or break parsing.

**Suggested fix:** Reject control characters or quote and escape per a defined dotenv dialect, and document that dialect.

### F-9: `install` rewrites `~/.bashrc` non-atomically
**Severity: Low. Verified observation.**

**Evidence:**
- `index.js:241-253` and `vauth.go:382-396` read, trim and rewrite the whole file (Go uses mode `0o644` for new files), with no temporary file and rename and no backup.
- The function is appended again whenever `bash -lc 'declare -F venv'` does not see it. That command also executes the user's login profile (`index.js:233-236`, `vauth.go:374-376`).

**Impact:** A crash or full disk can truncate `.bashrc`. Repeated runs can duplicate the declaration. Login-profile side effects run during detection.

**Suggested fix:** Write to a temporary file in the same directory, `fsync`, then rename while preserving the original mode. Detect an existing declaration by a marker line in the file rather than by spawning a login shell.

### F-10: Legacy ssh-agent-crypt v1/v2 armor is accepted silently, and its signing namespace collides with `ssh-keygen -Y sign`'s default
**Severity: Low. The code path is verified; exploitability is a hypothesis.**

**Evidence:**
- `ssh-agent-crypt/sshagentcrypt.go:36-40,334-346` decrypts the legacy v1 and v2 formats with SSHSIG namespace `"file"`, which is the default namespace of `ssh-keygen -Y sign`. v1 does not authenticate its header.
- vvauth calls `decrypt` / `Decrypt` on configured paths (`index.js:172`, `vauth.go:266-273`) and on the token cache with no format policy.
- Current v3 armor is namespaced (`ssh-agent-crypt`) and uses encrypt-then-MAC with a constant-time comparison before CBC decryption. That part is sound.

**Impact:** For files still in legacy format, an `-n file` signature over a known salt, which a user could be socially engineered into producing, would yield the decryption key.

**Suggested fix:** Warn on legacy formats, offer re-encryption to v3, and add an option (on by default for the token cache) that refuses legacy formats.

### F-11: Test-coverage gaps and Node/Go divergences
**Severity: Informational. Verified observation.**

**Coverage gaps:**
- `test.yml` runs `go test` on Linux only; Windows builds but runs no tests, so the named-pipe agent path and the signed Windows CLI behavior go untested.
- `cmd/vauth` has no tests for CLI parsing (see F-7).

**Divergences between runtimes:**
- A malformed `./package.json` makes the Node constructor throw (`index.js:34-40`, which repeats the vauth-login check), while Go ignores it (`vauth.go:58-60`). A hostile or broken checkout can therefore make Node vauth unusable there.
- A `git remote` that is a local path makes `new URL()` throw in Node (`index.js:71`), while Go accepts it (`gitlab.go:469-473`).

**Fix:** Add Windows `go test` jobs (or targeted tests), CLI table tests, and parity tests for these edge cases.

### F-12: Transport hardening
**Severity: Informational. Verified observation; impact is a hypothesis.**

**Evidence:**
- Go disables redirects (`vauth-login/vault.go:80-83`), which is good because `X-Vault-Token` is not stripped on cross-host redirects. Node `nyks/http/request` follows redirects only with `followRedirect`, which vauth-login does not set.
- Neither runtime bounds response size (`io.ReadAll`, `drain`).
- Neither refuses `http://` `vault_addr` values.
- KV and identity paths interpolate `entity_id`, the `VAUTH_USER_LOGIN` metadata value and configured `paths` without encoding (`index.js:135,141,220`; `vauth.go:171,188`; `vault.go:412-413`). Node's `new URL` normalizes `../` segments, so a configured path can reach other API paths on the trusted Vault with the user's token.

**Fix:**
- Cap response bodies.
- Warn on or refuse non-TLS addresses other than loopback.
- `encodeURIComponent` / `url.PathEscape` each dynamic segment and reject `..`.

---

## 3. Strengths

- **Shell publication is mostly sound.** Values are single-quoted with a correct `'"'"'` escape in both runtimes. Keys are restricted to POSIX-like names, and the reason is explained in code comments. Redacted `echo … >&2` lines keep token values off the terminal. Output is written in one block at the end, so a failure does not leave partially sourced exports.
- **The Vault-origin guard exists and is tested.** A project `./.vauthrc` that selects an unlisted Vault cannot receive the inherited token through `env`, `show`, `Request` or `LookupSelf` (`test/token-cache.js:887-916`). The error mentions only the address, not the token.
- **The token cache is designed with care.** It is encrypted at rest with agent-derived keys (v3: SSHSIG namespace separation, random salt and IV, HMAC-SHA256 over the header plus constant-time comparison before decryption), written atomically with `0600` / `0700`, and keyed by SHA-256 of Vault address plus auth configuration with byte-identical Node/Go keys. Plaintext or corrupt caches are rejected. Caching is disabled without an agent. Cache failures are non-fatal and do not reveal the token.
- **Inherited tokens are handled conservatively.** They are never persisted, renewed or looked up implicitly. Renewal and re-login logic distinguishes invalid-token statuses (400/403) from server failures, so network or server errors do not mint extra tokens.
- **Error hygiene is good.** `HTTPError` messages show only the status, with the body kept as a non-enumerable property in Node. The Go CLI prints `err`, which shows only the status.
- **Configuration handling is careful.** The RC is a frozen JSON snapshot. Macro expansion is limited to selected sections. `env.map` values are restricted to scalars. The Go HTTP client has a 60-second timeout and no redirects.
- **Node and Go parity is strong**, backed by an extensive synthetic-fixture test suite using disposable `ssh-agent`, `ssh-keygen` and local HTTP servers. Releases build with `-trimpath`, and Windows binaries are Authenticode-signed.

---

## 4. Limitations

- **No live vulnerability-database scanning** (no OSV, GHSA, `govulncheck` or `npm audit`) and **no network access**. Dependency-CVE statements (F-4) are hypotheses from version age and support status only.
- `go vet`, `go build` and `go test` could not run (read-only build cache), and the Node test suite could not run (read-only temporary directory). Behavior claims rest on source reading plus pure-function probes of `replaceEnv`.
- Only selected dependency sources were inspected. `cnyks` CLI argument resolution, `ssh2`'s agent client, `yaml`, `mout`, Masterminds/semver and `go-winio` were not reviewed in depth. The `131/gh-actions` signing hook is not part of this checkout and was not inspected.
- No real Vault, ssh-agent, Pageant or Windows environment was exercised. Runtime behavior on Windows (named pipes, Pageant fallback) was not checked.
- The *Verification* section of `API_and_tests.md` was deliberately skipped (see the provenance note).
- The upcoming, unpublished patch release and the already published npm, Go module and binary artifacts were not compared with this commit.

---

## 5. Scores

| Dimension | Score | Justification |
| --- | --- | --- |
| **Coolness** | **15 / 20** | Two complete implementations (Node and Go) of the same behavior, with documented Node/Go behavior and byte-for-byte cache compatibility. Agent-derived encryption of the token cache with no extra secrets. One-line `venv` workflow, GitLab bootstrap, and signed native binaries. The JS-replace emulation in Go is impressively exact, but it reproduces a defect (F-1). |
| **Robustness** | **13 / 20** | Strong test suite, careful lease and renewal logic, atomic cache writes, timeouts. Lost points: unbounded recursion and value corruption in macro expansion; `--source` can be overridden by forwarded arguments; non-atomic `.bashrc` rewrite; unescaped dotenv output; Node/Go edge-case divergences; no Windows or Go CLI tests. |
| **Safety** | **13 / 20** | Good token hygiene, an origin guard, authenticated encryption and redirect suppression. Lost points: the publish pipeline runs unlocked install scripts with an OIDC credential and no approval gate; release and signing references are mutable; the Go toolchain pin is end-of-life and nothing scans for vulnerabilities. In use, sourcing a hostile project `.vauthrc` still runs code (it is documented, but there is no trust prompt), and local-credential mode skips the origin guard when it exports `VAULT_ADDR`. |