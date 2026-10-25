# Security Audit — vvauth

- **Assessed commit:** `f368802700f03c8b632bbacefbfc71dbfaae04f4`
- **Assessment date:** October 25, 2026
- **Source state:** `master`, pre-release functional source; current Node and Go manifests declare `2.6.0`
- **Checkout:** `/var/monolith/3rd/github.com/131/vvauth`
- **Canonical remote:** `git@github.com:131/vvauth.git`
- **Execution model:** `gpt-6.1-sol_codeassist`, as declared by the host. The tools available to this review do not independently expose the execution-model identifier; no differing model was disclosed or selected. Client configuration and environment values were not inspected to identify the model.

## 1. Provenance

This is an independent, source-only assessment of the current implementation, selected installed dependency sources, tests, manifests, and release workflows. Findings were derived from those inputs, not from an intended design.

The following inputs were excluded:

- Every `SECURITY_AUDIT*.md` file, including the existing file bearing this report’s intended filename.
- Every `README.md`, at every depth.
- Previous assessments, scores, reports, conversations, and handoffs.
- Assessment content in Git history and assessment-related commit messages.
- Dependency Markdown containing advisories or audits.
- Personal context, task indexes, and neighboring project documentation.
- Real credentials, user configuration files, real Vault services, and network resources.

Excluded filenames were visible in the initial filename inventory; their contents were not read or searched. Only heading line numbers and titles were inspected in `API_and_tests.md`; its entire body was omitted.

The applicable `$AGENT_WORKSPACE/AGENTS.md` was read. The checkout is unmapped in the internal monolith, and no neighboring project rules were adopted.

No repository files were modified. Git metadata confirmed the assessed commit, branch, canonical remote, and clean tracked working tree.

The public upstream, existing npm/Go/native releases, and authorization for a future patch release are operator-provided context, not independently network-verified facts in this review. This assessment does not certify an unpublished patch or authorize publication.

## 2. Scope and Method

### 2.1 Explicit input inventory

#### Project implementation

- `index.js`
- `cmd/vauth.js`
- `vauth.go`
- `vault.go`
- `rc.go`
- `gitlab.go`
- `cmd/vauth/main.go`

These cover profile resolution, private KV updates, environment mapping, shell publication, local encrypted credentials, Git remote interpretation, construction, and CLI dispatch.

#### Repository tests

- `test/token-cache.js`
- `vauth_test.go`
- `gitlab_test.go`

The test-case indexes and selected bodies were inspected, particularly fixture construction, disposable-agent setup, cache lifecycle, shell forwarding, transport inheritance, unknown-Vault rejection, local decryption, scalar validation, configuration snapshots, and GitLab publication. This was not an exhaustive assertion-by-assertion review of every test body.

#### Manifests and supporting configuration

- `package.json`
- `package-lock.json` — selected metadata and dependency entries
- `go.mod`
- `go.sum`
- `.npmrc`
- `.gitignore`
- `.eslintrc`
- `.eslintignore`

The local `package-lock.json` is ignored and untracked. Its stale contents were treated as local metadata, not as the canonical dependency specification.

`package.json` declares **ISC**. No standalone project license text was independently verified.

#### Release and CI configuration

- `.github/workflows/test.yml`
- `.github/workflows/publish-npm.yml`
- `.github/workflows/release.yml`
- `.goreleaser.yaml`

#### Selected installed Node dependency inputs

Under `node_modules/`:

- `vauth-login/index.js`
- `ssh-agent-crypt/index.js`
- `nyks/http/request.js`
- `nyks/stream/drain.js`
- `nyks/string/replaceEnv.js`
- `nyks/string/stripStart.js`
- `nyks/object/jqdive.js`
- `nyks/object/walk.js`
- `nyks/object/structuredClone.js`
- `nyks/object/freeze.js`
- `nyks/child_process/exec.js`
- `nyks/process/parseArgs.js`
- `nyks/function/promiser.js`
- `nyks/async/eachLimit.js`
- `nyks/date/humanDiff.js`

Selected manifest fields were read from the installed `nyks`, `vauth-login`, `ssh-agent-crypt`, `cnyks`, `mout`, and `semver` packages. The installed versions of the three principal shared dependencies matched the supplied context:

| Dependency | Node installed version | Go requirement |
|---|---:|---:|
| nyks | 6.18.0 | v6.18.0 |
| vauth-login | 1.1.7 | v1.1.7 |
| ssh-agent-crypt | 1.4.4 | v1.4.4 |

#### Selected cached Go dependency inputs

Under `/root/go/pkg/mod/`:

- `github.com/131/vauth-login@v1.1.7/{go.mod,vauth.go,rc.go,cache.go,vault.go}`
- `github.com/131/ssh-agent-crypt@v1.4.4/{go.mod,sshagentcrypt.go,agent_unix.go,agent_windows.go}`
- `github.com/131/nyks/v6@v6.18.0/go.mod`
- `github.com/131/nyks/v6@v6.18.0/string/replaceEnv.go`
- `github.com/131/nyks/v6@v6.18.0/object/{jqdive.go,walk.go}`
- `github.com/131/nyks/v6@v6.18.0/date/humanDiff.go`
- `github.com/131/nyks/v6@v6.18.0/internal/js/string.go`

Dependency paths in findings below refer to these installed versions.

### 2.2 Safe local checks performed

| Check | Result |
|---|---|
| Git commit, branch, remote, and tracked status inspection | Matched the stated checkout; tracked tree remained clean |
| `node --version` | v22.22.2 |
| `GOTOOLCHAIN=local go version` | go1.24.0, Linux/amd64 |
| `node --check` on `index.js`, `cmd/vauth.js`, and `test/token-cache.js` | Passed |
| `gofmt -l` on all seven project Go source/test files | No formatting differences reported |
| ESLint on the three selected project JavaScript files, with `--no-cache`, no fixes, and a minimal environment | Passed |
| `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly go list -m all` | Passed using available local module metadata; no replacements reported |
| Local JSON parsing of manifest and selected lockfile metadata | Completed; an initial URL-only formatter rejected a relative lockfile entry and was corrected |

These checks do not establish runtime correctness or absence of vulnerabilities.

### 2.3 Checks not performed

- **`node --test`, `npm test`, and `go test`:** repository fixtures create temporary directories, SSH keys, disposable agents, and loopback HTTP listeners. They were not executed under this strictly read-only, no-network review.
- **`go vet` and native builds:** these can require compiler work directories and cache writes. They were not attempted under the filesystem restriction.
- **Windows runtime tests:** no Windows execution environment was available.
- **npm installation, Go module downloads, npm audit, and live vulnerability scanning:** prohibited by the source-only and no-network scope.
- **Release execution, signing, artifact installation, and Vault integration:** outside reviewer authorization.
- **Published-package or binary comparison:** no network retrieval was permitted.

No real credentials, token caches, SSH agents, or Vault endpoints were accessed.

## 3. Prioritized Findings

“Verified observation” below means directly established from the inspected source or local metadata. It does **not** imply that an exploit was dynamically reproduced.

### F1 — High: Vault destination trust does not establish trust in the environment being sourced

**Classification:** Verified observation; downstream exploitation is conditional on sourcing an attacker-controlled project configuration.

**Evidence**

- `node_modules/vauth-login/index.js:62–105` selects project configuration and checks whether its Vault address is known.
- `index.js:193–197` validates environment-key syntax but does not restrict sensitive names.
- `vauth.go:313–322` implements the same unrestricted mapping behavior.
- `index.js:26` and `vauth.go:35–36` install a function that sources the generated exports.
- `index.js:163–166,193–197` and `vauth.go:256–262,314–322` allow mapped values to replace initially selected `VAULT_TOKEN` and `VAULT_ADDR`.

**Impact**

A syntactically valid key can still change security-sensitive behavior. A project configuration can export `PATH`, `BASH_ENV`, `NODE_OPTIONS`, loader-related variables, or replacement Vault credentials and addresses.

Shell quoting prevents a value from becoming an immediate shell command during assignment. It does not prevent subsequent commands or runtimes from acting on that value. A malicious `PATH`, for example, can redirect later command execution.

The known-Vault check protects requests to the selected endpoint; it is not an approval mechanism for the rest of `.vauthrc`. Configurations that require no Vault request can also reach environment publication.

**Suggested fix**

Treat approval of a configuration’s environment effects separately from approval of its Vault endpoint. Require explicit trust before sourcing an untrusted project configuration, preferably tied to its contents. Offer a restricted mode that blocks execution-controlling variables and credential/address overrides unless separately authorized. Preserve unrestricted behavior only as an explicit trusted-config choice.

### F2 — Medium: The installed shell wrapper can hide environment-generation failure

**Classification:** Verified observation based on the generated Bash function.

**Evidence**

- `index.js:26`
- `vauth.go:35–36`

Both define:

```bash
function venv() { source <(/usr/bin/env vauth env --source "$@"); }
```

The forwarding test at `test/token-cache.js:372–410` exercises successful operation.

**Impact**

Bash returns the status of `source`, not reliably the exit status of the process-substitution producer. If the CLI fails without producing exports, sourcing an empty stream can succeed.

Scripts using `venv && ...` may therefore continue with stale credentials or an old environment after authentication, configuration, or decryption failure. The CLI can correctly reject an operation while its installed shell integration obscures that rejection.

**Suggested fix**

Capture generated output, check the CLI’s exit status, and source it only after successful completion. Add repository tests covering failed authentication, malformed configuration, and decryption failure through the installed function. Define the expected handling of stale credentials.

### F3 — Medium: Macro replacement interprets secret values as replacement syntax and has no recursion bound

**Classification:** Verified observation; resource-exhaustion consequences were not dynamically reproduced.

**Evidence**

- `node_modules/nyks/string/replaceEnv.js:20–24` uses `String.replace` with the resolved value as a replacement string, then recursively expands again.
- Cached Go `nyks/string/replaceEnv.go:45–50,72–99` reproduces JavaScript replacement-string semantics and recursive expansion.
- Call sites include `index.js:46,197` and `rc.go:196–198`, plus authentication configuration expansion in both `vauth-login` implementations.

**Impact**

Resolved values containing replacement metacharacters are not inserted literally. Examples include:

- `$$`, which becomes a single dollar sign.
- `$&`, which substitutes the matched macro.
- Prefix/suffix replacement forms, which introduce surrounding template text.

This can corrupt passwords, tokens, connection strings, and configuration values. A replacement that recreates the original macro can also cause repeated recursion rather than a bounded error.

Cross-language agreement does not eliminate the defect: both implementations deliberately share these semantics.

**Suggested fix**

Insert resolved values literally. In Node, use a replacement callback; in Go, concatenate the intended segments without interpreting replacement metacharacters. Add cycle detection, expansion-count limits, and output-size limits. Add shared regression fixtures for dollar-containing credentials and non-progressing expansion.

### F4 — Medium: Node release dependencies are not reproducibly locked

**Classification:** Verified observation.

**Evidence**

- `package.json:15–21` uses caret ranges for runtime dependencies.
- `.npmrc:1` disables package-lock handling.
- `.gitignore:2` excludes `package-lock.json`.
- `.github/workflows/publish-npm.yml:21` and `.github/workflows/test.yml:18` use `npm install`.
- The ignored local lockfile declares `2.5.0` at lines `3` and `9` and contains older dependency entries.

**Impact**

The dependency graph tested and published can change without a source-commit change. Future compatible dependency releases can alter authentication, cryptography, or transport behavior in CI.

The local lockfile is not evidence of current development replacements: its stale links and versions do not describe the inspected installed dependency versions. It nevertheless cannot serve as a reproducible release input.

**Suggested fix**

Adopt a committed, current lockfile and `npm ci` for CI and publication, with reviewed dependency updates. Record the actual release dependency graph. Keep consumer-facing ranges if desired, but make the publisher’s build and test environment reproducible.

### F5 — Medium: Release execution relies on mutable external references, including the signing helper

**Classification:** Verified observation; compromise of those upstream references is a hypothesis, not an observed event.

**Evidence**

- `.github/workflows/release.yml:15–30` uses major-version action references, checks out `131/gh-actions` at `v1`, and selects a GoReleaser version range.
- `.goreleaser.yaml:18–19` executes the externally checked-out signing helper.
- `.github/workflows/release.yml:31–33` supplies release and signing-related values to the release step.
- Publication and test workflows also use major-version action references.

**Impact**

The same source tag can execute different third-party or shared workflow code over time. The signing helper is particularly sensitive because it participates in creating a trusted executable and runs within the release credential boundary.

This checkout does not contain the helper implementation, so its behavior and protection of signing access were not verified.

**Suggested fix**

Pin actions and the signing-helper checkout to reviewed commit hashes; pin the GoReleaser version. Update them through review. Minimize credential exposure across steps and verify the signed artifact after the hook. Retain an explicit record of the workflow and helper revisions used for each release.

### F6 — Medium: Trusted endpoints may still use plaintext HTTP

**Classification:** Verified observation; exposure depends on deployment configuration and network position.

**Evidence**

- `node_modules/vauth-login/index.js:308–324` accepts the configured URL without requiring HTTPS.
- `node_modules/nyks/http/request.js:63` selects HTTPS only for `https:`.
- Cached Go `vauth-login/vault.go:55–65` creates a request and attaches `X-Vault-Token` without enforcing HTTPS.

**Impact**

An explicitly trusted non-loopback HTTP endpoint can receive JWT login payloads, bearer tokens, and secret responses without transport encryption. Destination approval is not equivalent to transport protection.

No real deployment was inspected, and this finding does not assert that production currently uses HTTP. Repository loopback HTTP fixtures are appropriate for synthetic tests.

**Suggested fix**

Require HTTPS for non-loopback destinations by default. Provide an explicit insecure-development exception rather than silently accepting plaintext transport. Validate the URL scheme early and retain normal certificate verification.

### F7 — Medium: HTTP response buffering is unbounded

**Classification:** Verified observation.

**Evidence**

- `node_modules/vauth-login/index.js:324–325` drains the full response.
- `node_modules/nyks/stream/drain.js:12,21–26` accumulates every chunk before concatenation.
- Cached Go `vauth-login/vault.go:69–70` calls `io.ReadAll` without a size limit.

**Impact**

An oversized response from an approved, compromised, malfunctioning, or intercepted endpoint can exhaust client memory. This applies to error responses as well as successful JSON responses.

The 60-second transport timeouts are useful but do not bound the number of bytes received within that period.

**Suggested fix**

Enforce response-size limits suitable for authentication, identity, and KV operations. Abort oversized streams before buffering completes, and return a sanitized error. Apply related bounds to local encrypted payloads where appropriate.

### F8 — Medium: Dotenv output does not encode multiline or parser-sensitive values

**Classification:** Verified observation.

**Evidence**

- `index.js:207–215` prints `${k}=${String(v)}\n`.
- `vauth.go:360–368` prints `%s=%s\n`.
- Scalar validation in `index.js:260–265` and `rc.go:129–154` does not reject line breaks.

**Impact**

A value containing a newline can become additional dotenv records when consumed by another tool. Quote, comment, and whitespace interpretation also depends on the downstream dotenv parser.

The output therefore cannot reliably preserve every accepted environment value. This is a dotenv serialization problem, not a failure of the separately implemented shell quoting.

**Suggested fix**

Define a supported dotenv grammar and encode values accordingly, with round-trip tests against supported consumers. If portability cannot be guaranteed, reject unsupported multiline or parser-sensitive values and recommend JSON or shell-export output.

### F9 — Low: Public publication helpers do not enforce their own key-safety invariant

**Classification:** Verified observation; exposure through arbitrary reflective CLI dispatch was not independently verified.

**Evidence**

- `index.js:94–100` interpolates supplied keys into both export and echo commands.
- `vauth.go:346–352` does the same for `OrderedMap.Keys`.
- The key validation exists in `Env`, at `index.js:193–196` and `vauth.go:314–316`, rather than in `PublishEnv`.

**Impact**

Normal environment resolution validates mapped keys, and internal login/GitLab callers use fixed keys. However, SDK callers can invoke the public publication helper directly with an unsafe key and obtain executable shell syntax.

The helper’s safety depends on a precondition that its implementation does not enforce.

**Suggested fix**

Validate every key at the publication boundary before writing any output. Return an error for invalid keys. Keep caller-side validation for useful diagnostics, but make the shell emitter safe independently.

### F10 — Low: Private KV updates can overwrite concurrent changes

**Classification:** Verified observation of the update algorithm; concurrent loss was not dynamically reproduced.

**Evidence**

- `index.js:104–112` reads the profile/database, modifies one key, and writes the complete database.
- `vauth.go:209–223` implements the same read-modify-write sequence.
- `index.js:228–230` and `vault.go:35–45` send complete KV data without a compare-and-set option.

**Impact**

Two clients updating different keys can read the same version and then overwrite one another’s changes. An `unset` can likewise restore unrelated stale data through the full-object write.

Vault ACLs still control access; this is an integrity/concurrency issue rather than an authorization bypass.

**Suggested fix**

Use KV-v2 version metadata and compare-and-set writes, with bounded retries after conflicts. Add concurrent update and delete regression tests.

## 4. Strengths

- **Clear separation of responsibilities.** Authentication, cache lifecycle, and HTTP requests are delegated to `vauth-login`; vvauth concentrates on profile, KV, and environment resolution.
- **Destination checks occur before requests.** Both inspected authentication implementations reject unknown project-selected Vault endpoints at the transport boundary.
- **Default redirects are not followed.** Node does not enable redirect following; the Go default client explicitly returns the last redirect response. This reduces credential-forwarding risk.
- **Useful transport deadlines.** Both implementations default to approximately 60 seconds.
- **Encrypted persistence.** New cache writes contain armor rather than plaintext tokens. Node uses exclusive temporary-file creation and rename; Go uses a temporary file and rename. New Unix directories/files request restrictive modes.
- **Authenticated encryption construction.** The selected cryptographic implementation uses randomized salt/IV, separated encryption/MAC keys, authenticates v3 framing, and checks the MAC before decrypting. This is a positive source observation, not a formal cryptographic proof.
- **Namespace separation.** New v3 key derivation uses the `ssh-agent-crypt` SSHSIG namespace rather than the generic legacy `file` namespace.
- **Credential-conscious diagnostics.** Token status messages do not print token values; HTTP error messages expose status rather than automatically rendering response bodies.
- **Inherited-token ownership is respected.** Ordinary connection does not automatically renew or persist an inherited token.
- **Failure behavior distinguishes invalid tokens from server failures.** Renewal failures with 400/403 can trigger reauthentication; other failures are propagated rather than blindly generating more tokens.
- **Shell values are quoted correctly for assignment.** Single-quote escaping and map-key syntax checks address direct shell-syntax injection in the normal `Env` path.
- **Configuration snapshots are preserved.** Node retains a frozen raw snapshot; Go returns independent snapshots and clones selected configuration before expansion.
- **Substantial synthetic fixtures exist.** Tests cover disposable agents, loopback services, cache lifecycle, transport trust, scalar validation, and CLI behavior without requiring production Vault access.
- **Release controls are visible.** CI permissions are declared, the native release job uses a production environment, GoReleaser emits checksums, and Windows builds have a signing hook.

Cached-token reuse without a revocation lookup is an explicit behavior represented in the tests. It improves offline reuse but can delay discovery of revocation. It does not bypass Vault’s server-side authorization.

## 5. Limitations

1. **No network access and no live vulnerability-database scanning were performed.** Dependency versions were inspected, but no claim is made that they are free of known vulnerabilities.
2. **Runtime suites were not executed.** Syntax, lint, formatting, and local module-graph success must not be confused with passing integration tests.
3. **Dependency review was selective.** It did not exhaustively cover `cnyks` reflection, SSH protocol internals, YAML parsing, Node/Go standard libraries, or all transitive dependencies.
4. **Cryptography was inspected, not formally audited.** Legacy v1/v2 reading remains supported. Agent compromise, memory scraping, filesystem rollback, and local same-user attacks were not experimentally evaluated.
5. **Agent operations do not inherit the HTTP timeout.** Agent blocking and Windows pipe behavior remain runtime verification gaps.
6. **No production policy was assessed.** Vault ACLs, roles, token TTL policies, endpoint configuration, GitHub environment approvals, tag protections, and npm trusted-publishing configuration were not inspected.
7. **Signing and installation were not verified.** The configuration establishes a Windows signing hook, not proof of a valid signature. The Linux build has checksum generation, but this checkout does not show an equivalent Linux signing hook.
8. **Published artifacts were not compared with source.** No npm tarball, module archive, release binary, checksum, or provenance attestation was retrieved.
9. **The upcoming patch remains outside this assessment.** Findings apply to the identified functional source and selected installed dependency versions.
10. **Execution-model identity is host-declared.** It was not independently verified through client or environment inspection.

This report is not a release approval or a guarantee of safety. The highest-priority improvements are explicit configuration trust, reliable shell failure propagation, and literal, bounded interpolation.

## 6. Scores

| Category | Score | Justification |
|---|---:|---|
| **Coolness** | **17/20** | A compact, useful dual-language credentials helper combining Vault profiles, encrypted local data, environment resolution, native CLI distribution, and shared behavior. |
| **Robustness** | **13/20** | Strong synthetic fixtures, configuration snapshots, cache lifecycle handling, and transport deadlines; deductions for shell failure masking, interpolation semantics, serialization gaps, unbounded buffering, and lost-update risk. Runtime verification remains incomplete. |
| **Safety** | **12/20** | Meaningful destination checks, encrypted persistence, redacted diagnostics, and shell quoting; deductions for the untrusted-configuration boundary, optional plaintext transport, publication-helper preconditions, and mutable release inputs. This score is not a vulnerability-database clearance. |