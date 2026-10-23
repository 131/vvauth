# vvauth — Architecture, Code Quality, and Security Review

**Review date:** October 23, 2026  
**Reviewer:** Codex (GPT 6.1-sol)

## Scope and evidence

This is a read-only review of the current checkout. I read `README.md`, `API_and_tests.md`, both canonical implementations (`index.js`; `vauth.go`, `vault.go`, `cache.go`, `rc.go`, `humandiff.go`, and `cmd/vauth/main.go`), both test files, the three workflows, and the package/build manifests. I also inspected locally installed dependency source where necessary to understand Node HTTP, CLI, macro, child-process, and encryption delegation, Go agent selection, and Go HTTP redirect handling. I did not read the other audit as evidence, examine project history, modify the repository, craft inputs, or perform behavioral probes.

Authorized verification:

- `npm test`: **64 passed, 0 failed, 0 skipped**.
- `go test ./...`: **passed** for the library; `cmd/vauth` reports **no test files**. The normal Go output does not establish whether individual tests skipped optional checks.
- The Git working tree was clean before and after the test runs.

Findings below distinguish observed source behavior from inferred consequences. Severity reflects the likely impact under the stated conditions, not a demonstrated exploit. This is not an independent cryptographic certification, dependency-vulnerability scan, live Vault integration test, or Windows execution test.

## Design as understood

vvauth combines an authentication client, a credential/profile resolver, and an environment publisher. Node exposes a class and a reflection-based CLI; Go separates configuration, cache, Vault transport, orchestration, and the command entry point.

Both locate `.vauthrc` through `VAUTHRC`, the working directory, then the home directory, and perform environment macro expansion. With an authentication configuration, connection precedence is the inherited `VAULT_TOKEN`, then the encrypted session cache, then SSH challenge signing or JWT login. Cached expiry drives reuse, renewal in the final third of the recorded lease, or replacement. `--renew` means fresh authentication, not merely renewal of the existing token. Without an auth block, inherited Vault tokens are deliberately ignored, allowing local armored credentials to work offline.

The shared disk contract is a hash-addressed `.creds` file beneath `~/.vauth/tokens`, containing armored JSON with the token, lease duration, renewable flag, and absolute expiry. `ssh-agent-crypt` performs encryption/decryption using an agent-backed key; new cache writes select a key through identity/mail settings, while decryption generally selects the armor's embedded fingerprint.

Environment resolution combines Vault entity metadata, the user's private KV-v2 `.vauth_database`, optional local encrypted JSON, and ordered remote secret reads. Metadata overrides private database entries; later secret sources override earlier ones. `env.map` publishes selected values through JSON, Bash exports, raw dotenv lines, or a child process. `set`/`unset` replace the private database document after a read.

**Overall assessment:** a useful, compact design with thoughtful cache hygiene and substantial lifecycle regression coverage. The principal weaknesses are implicit trust in working-directory configuration, incomplete lifecycle validation, unsafe transport defaults in Go, and a parity promise broader than the implementation and tests support.

## Strengths

- **No plaintext token-cache fallback.** Encryption precedes writing, unreadable/plaintext armor is treated as a miss, and cache write failure does not fail authentication or print the token. Both request private creation modes and rename the completed temporary file into place (`index.js:121–152`, `cache.go:43–101`).
- **Well-covered lease decisions.** Tests exercise expiry, proportional renewal thresholds, lease-baseline preservation, nonrenewable replacement, forced reauthentication, environment-token precedence, disabled caching, and ordinary reuse without rewriting the cache.
- **Reasonable failure classification in token lookup/renewal.** HTTP 400/403 can trigger reauthentication, whereas server/network failures are propagated instead of creating extra tokens (`index.js:178–202`, `vauth.go:181–215,255–263`).
- **Good shell-value quoting and key checks on the normal environment path.** Bash values are single-quoted with embedded quotes escaped; `env.map` names are validated in both implementations. Resolution completes before export output begins (`index.js:330–335,489–492`, `vauth.go:419–431,448–459`).
- **Secrets are not printed in ordinary success diagnostics.** Token status and sourced export echoes are redacted; JSON output can be separated from stderr diagnostics.
- **Go has useful architectural seams.** Typed configuration, injectable HTTP client/clock/streams/environment, and separate transport/cache files make the library more maintainable and testable than a single CLI-bound implementation.
- **CI has basic quality gates and restrained permissions.** Linting, formatting, vetting, and tests are present; regular CI has read-only repository permissions. Go release configuration includes trimmed builds, version injection, checksums, and a Windows signing hook.

## Weaknesses and correctness risks

### 1. High — Configuration discovery is also an implicit credential trust decision

**Evidence:** `index.js:39,64–95,330–335`; `rc.go:322–373`; `vault.go:57–67`; `vauth.go:419–425`.

A working-directory `.vauthrc` can select the Vault destination and auth parameters, reference local encrypted credentials, and map arbitrary syntactically valid environment names. The code checks names against shell injection, but does not establish whether the configuration is trusted. In a malicious checkout, invoking the helper can therefore send an inherited token or JWT to a chosen endpoint, request agent signatures, decrypt available local material, or export values affecting command execution. This is a configuration-authority boundary, not a claim that correctly quoted values execute as Bash code.

A nonexistent explicit `VAUTHRC` also silently falls through to another configuration. That matches the README's fallback wording but can select an unintended security context.

**Remedy:** make explicit configuration selection fail closed; add an opt-in/trust mechanism for project configurations and display the selected configuration and destination without credentials. Bind inherited tokens to a trusted Vault origin, restrict sensitive environment overrides, and document that approving a configuration authorizes credential resolution and agent use.

### 2. High — Transport policy is insufficient, particularly Go redirects

**Evidence:** `vault.go:42–86`; Node request construction throughout `index.js`; locally installed `nyks/http/request.js`; local Go `net/http/client.go` redirect-header copying.

Neither implementation requires HTTPS for credential-bearing requests. Go uses `http.DefaultClient` unless overridden, with no helper-level deadline, and reads complete response bodies without a size cap. Its default redirect behavior copies the custom `X-Vault-Token` header; that header is not among the standard headers receiving sensitive-header filtering. A redirect to another origin can consequently disclose a token. This is a static conclusion from the local HTTP implementation, not a redirect experiment.

Node does not enable redirects in these requests. Its dependency supplies a 60-second response-header timer, but that is not a total deadline: the timer is cleared when headers arrive, and timeout rejection does not explicitly destroy the request. Body draining remains unbounded.

**Remedy:** default to HTTPS, with explicit local-development exceptions; reject redirects for Vault calls or enforce an exact trusted origin and prohibit downgrade. Use bounded total deadlines, cancellation, response-size limits, and proper request/response cleanup in both runtimes. Preserve normal certificate verification.

### 3. Medium — Cached validity and in-memory validity are conflated with actual token usability

**Evidence:** `index.js:161–226,276–288`; `vauth.go:159–252,289–319`; the explicit cached-revocation tests in both suites.

Cache reuse intentionally skips lookup until renewal is due. Revoked cached tokens can be returned successfully by `connect`/`login`; the subsequent profile lookup used by `env` can fail without retrying authentication. Moreover, once an instance is marked connected, ordinary calls bypass expiry and renewal altogether. A long-lived library client can keep returning an expired token. Absolute wall-clock expiry also assumes a stable clock and does not subtract network latency or a safety margin.

**Remedy:** retain in-memory lease metadata and reevaluate expiry on every connection request. Decide and document the freshness policy for cached tokens; offer validation, and implement one bounded reauthentication retry for token-invalid responses on safe reads. Add conservative expiry skew and keep network/server failures distinct from invalid credentials.

### 4. Medium — Token persistence and replacement do not fully define ownership or cleanup

**Evidence:** `index.js:175,205–221`; `vauth.go:177,218–246`; environment-token and repeated-force-login tests.

An inherited token is persisted under the configured auth session even though it may belong to a different identity or carry different privileges. A later invocation without that environment variable can reuse it. Fresh authentication overwrites the local cache but does not revoke the previous token. Cache disabling leaves files intact; changing JWT content creates another filename; there is no logout, expiry cleanup, or retention policy. Replacement is therefore not revocation or credential erasure.

**Remedy:** distinguish externally supplied tokens from helper-owned tokens and make persistence of inherited tokens explicit. Bind persisted sessions to the intended principal/policy context. Add local cache cleanup and a documented logout path, with revocation limited to tokens the helper owns so that unrelated inherited credentials are not accidentally revoked.

### 5. Medium — The decrypted cache lacks a validated, context-bound schema

**Evidence:** `index.js:121–141,175–187`; `cache.go:15–20,43–59`; `vault.go:89–96,161–176`.

Node accepts any successfully decrypted JSON without checking token type, lease duration, expiry, or renewable shape. Go checks a nonempty token and JSON types, but omitted/null expiry becomes unlimited and lease invariants are not checked. Go login parsing also accepts an omitted lease duration as zero; lookup accepts an omitted TTL as zero. Encryption authenticates bytes, not application meaning.

Neither payload contains a format version or session digest. Thus a valid armor copied into another session filename is not rejected for context mismatch if the corresponding key remains available. This requires local cache manipulation or another source of valid armor; it is not an unauthenticated bypass of encryption.

**Remedy:** define a shared versioned schema with required fields, finite/nonnegative durations, explicit unlimited-token semantics, and consistency checks. Embed and verify the session digest and relevant principal context. Treat malformed or mismatched payloads as misses with redacted diagnostics.

### 6. Medium — Fixed cache staging names are unsafe under concurrency

**Evidence:** `index.js:134–151`; `cache.go:66–100`.

Both writers use exactly `<session>.creds.next`, overwrite it without exclusive creation, rename it, and unconditionally attempt cleanup. Concurrent Node/Go invocations can overwrite or remove each other's staging file, lose an update, or persist a different process's token. The read/renew/login/write sequence is also unlocked, so simultaneous callers may issue redundant logins or renewals.

Creation modes do not repair existing permissive files/directories, prevent following a preexisting symlink, or establish Windows ACL isolation. These are hardening gaps, not evidence that plaintext tokens are written.

**Remedy:** use unique exclusively created temporary files in a verified private directory, close and optionally sync before rename, and clean up only the writer's own file. Coordinate the session lifecycle with a cross-runtime lock and re-read inside the lock. Check ownership/permissions, avoid symlink traversal, and implement/test the Windows ACL equivalent.

### 7. Medium — Cache identity selection is not authentication identity selection

**Evidence:** `index.js:143,390–419`; `cache.go:89–94`; `vault.go:110–158`; identity-selection tests in `test/token-cache.js`.

Identity/mail settings select new cache encryption, not the SSH login key: login tries all agent identities in order. Cache reads use the embedded fingerprint, so changing selectors does not isolate users when the old key remains loaded. Multiple identities sharing the same Vault/role configuration also share the cache filename. Agent ordering can therefore determine the authenticated principal independently of the advertised cache selector.

Both SSH loops swallow all login failures and continue, including transport/server failures. Node signing failures escape the loop, whereas Go signing refusals skip to another key. There is no JWT fallback after an attempted SSH login fails. On Windows, Node explicitly selects `pageant`; Go's dependency discovers a Pageant pipe and otherwise selects OpenSSH, so the documented fallback is not implemented identically.

**Remedy:** expose an explicit authentication-key fingerprint separate from, or intentionally coupled to, cache encryption selection. Include principal selection in session identity. Define fallback and error-classification rules, constrain agent access/signing, and harmonize Windows agent selection. Document that access to a loaded key's signing service can enable cache decryption; armor is not protection against an already-compromised session with agent access.

### 8. Medium — Configuration and macro semantics diverge and can silently preserve mistakes

**Evidence:** `index.js:67–88,293–335`; `rc.go:121–136,155–245,247–301,340–371`; locally installed `nyks/string/replaceEnv.js` and `nyks/object/walk.js`.

Unknown macros remain literal, including in authentication and required credential fields. Node's recursive replacement has no cycle/depth guard; cyclic references can overflow recursion or grow output. Go stops after 16 passes without reporting incomplete resolution and stringifies structured values, whereas Node can return a structured value directly. Go's YAML walk processes mapping keys as well as values; Node's object walk processes values only. Alias handling and YAML coercion further complicate parity. Unknown configuration fields are not comprehensively rejected.

**Remedy:** publish a constrained schema and deterministic macro specification covering types, missing values, recursion, keys, and aliases. Reject unresolved required fields, detect cycles, and bound expansion depth and output size with errors rather than partial success. Treat secret values as literal data by default instead of automatically interpreting embedded macros.

### 9. Medium — Cache hashing is order-sensitive, and Go can retain a stale auth hash

**Evidence:** `index.js:110–115`; `rc.go:27–45,247–301,358–371`; `cache.go:23–31`; `vauth_test.go:TestTokenCacheKeyMatchesNode`.

The cache key hashes serialized auth objects rather than a normalized semantic session. Reordering nested YAML auth fields can create another cache entry for the same session. Raw JWT inclusion also causes cache fragmentation as JWTs rotate. Go reimplements Node-style serialization and tests only a small number of expected strings, not a real Node-to-Go session exchange.

More importantly, `ParseRC` stores `authKey`, and `AuthKey()` prefers it over the public auth structs. If an embedding caller changes a parsed role or JWT, the runtime auth configuration changes but the cached hash does not. That can reuse or overwrite a token associated with the earlier configuration.

**Remedy:** derive a versioned canonical session identity from immutable validated configuration, or invalidate/recompute it whenever public auth settings change. Normalize ordering/defaults and define JWT rotation semantics deliberately. Add bidirectional cross-runtime cache tests using the same parsed configuration and principal settings.

### 10. Medium — Environment publication has stale-state and data-format hazards

**Evidence:** `index.js:248–255,300–335,340–345`; `vauth.go:366–424,448–470,475–487`; `FunctionDecl` in both implementations.

Valid names such as `VAULT_TOKEN`, `VAULT_ADDR`, `PATH`, and runtime loader options remain unrestricted in `env.map`; mapping happens after the helper adds its own Vault values. A trusted authenticated session can thus publish a different token/address pair. Missing profile values differ by runtime: Node can retain `undefined`, while Go can retain a macro literal. Raw dotenv output does not escape multiline, quote, or comment-sensitive values.

The installed `venv` function sources process-substitution output without propagating the producer's exit status. A failed resolver can leave old credentials in the shell while the sourcing operation appears successful. Successful output also does not unset credentials absent from the newly resolved environment. Public Go `PublishEnv` assumes callers supply validated names and ignores output errors.

**Remedy:** reserve or explicitly authorize sensitive overrides, validate environment values at publication, and define missing/null behavior. Use a specified dotenv encoder or reject values outside its supported format. Make the shell wrapper check producer success before sourcing and manage previously exported variables explicitly. Validate names at exported sinks and return write errors.

### 11. Medium — Private database updates can lose concurrent changes

**Evidence:** `index.js:258–268,362–386`; `vauth.go:333–347`; `vault.go:203–237`.

`set` and `unset` read the complete `.vauth_database`, edit it, then replace the complete KV-v2 document without a version/CAS condition. Concurrent updates can overwrite each other. Secret paths, mounts, login metadata, and entity IDs are concatenated into URLs without a shared validation/encoding policy. Vault remains the authorization boundary, but ambiguous path characters or missing identity fields can target unintended paths or produce confusing errors. Later secret documents also silently override earlier fields.

**Remedy:** retain KV-v2 version metadata, use CAS and bounded conflict retries, validate identity/path components, and construct URLs safely. Specify duplicate-secret precedence and provide a strict collision mode. Treat tokens without entity metadata as an explicit supported case or reject profile-dependent operations with a precise error.

### 12. Medium — Error handling can expose sensitive response content or hide the real failure

**Evidence:** `index.js:362–386,410–419,472–483`; `vault.go:17–24,99–107,151–158,203–235`; `vauth.go:508–521`; local Node runner error handling.

Several errors include complete remote response bodies; the Node runner also prints the error and stack. A server or proxy can return sensitive or attacker-controlled text. Cache read failures are all swallowed, obscuring permission, integrity, and unavailable-agent failures. Missing auth capability can yield successful empty connection results on the first attempt. Go's installer ignores a `.bashrc` read error before writing; Node's function check has no child-spawn error handling. Interactive installation prompts also contradict the blanket machine-readable-stdout claim.

**Remedy:** use typed, contextual, redacted errors with bounded/sanitized remote messages, and make diagnostics distinguish expected cache misses from operational failures without secrets. Separate offline mode from required authentication. Preserve existing shell files on read failure, handle process-start errors, return output errors, and document interactive commands as exceptions to machine-readable output.

### 13. Medium — The Node/Go CLI parity contract is currently false in important cases

**Evidence:** `index.js:103–107,495–498`; `cmd/vauth/main.go:98–114,175–201`; locally installed `cnyks/lib/index.js`, `nyks/process/parseArgs.js`, and child-process helpers.

Static dispatch analysis identifies concrete mismatches not exercised by the current suites:

- Node selects raw output unless JSON is requested; its runner stringifies ordinary objects as raw strings. Bare `env`/`show` therefore do not receive the JSON-object formatting promised for both runtimes. Go explicitly JSON-encodes objects.
- Go implements `version`/`--version`; the Node class and inspected runner contain no corresponding version command.
- Node's runner leaves the textual flag value `false` as a truthy string, contrary to the documented boolean rule; Go interprets it as false. Node also coerces numeric-looking `set` arguments, unlike Go's string-preserving CLI.
- Node's child helper turns any nonzero child status into a generic rejection and exits 1; Go propagates the child's exit code.
- The documented `vauth run -- <command>` form passes `--` as the executable in both dedicated run paths, which forward original arguments rather than consuming that separator.

**Remedy:** use explicit command dispatch and shared argument/output rules rather than reflection as the Node contract boundary. Add version handling, preserve `set` strings, normalize booleans and separators, and propagate child statuses. Exercise both actual CLIs against the same contract fixtures, including default output and failure cases.

### 14. Medium — Testing and release gates do not establish the advertised assurance

**Evidence:** both test files; `.github/workflows/test.yml`, `publish-npm.yml`, `release.yml`; `.goreleaser.yaml`; `.gitignore:2`; package manifests.

Tests are strong for JWT/cache lifecycle but neither fake Vault implements SSH nonce/login or meaningful KV/profile operations. Go lacks CLI tests and identity-selection coverage comparable to Node. Armor interoperability checks use each runtime's corresponding crypto CLI, not a bidirectional Node/Go vvauth cache exchange; Go can skip its CLI check when unavailable.

The Node CI job runs only on Linux. The Windows Go job builds instead of running tests, despite `API_and_tests.md` saying both suites run on Linux and Windows. Existing test harnesses assume Unix-style `ssh-agent -s`, Bash, and process cleanup. No race/concurrency, hostile transport, or broad configuration-contract coverage is present.

Node workflows run `npm install`, while `package-lock.json` is ignored and untracked in this checkout, so CI dependency resolution is not tied to a committed lock. The Node package declares no engine requirement although CI tests only Node 24. Publishing uses a different event (`create`) from binary releases (`push` with tag filtering), has no explicit tag-type guard or production environment in the job, and does not validate package/module/tag version agreement. Release actions, GoReleaser selection, and the trusted external signing helper use movable refs/ranges. Checksums and an external signing hook do not alone prove that every Windows artifact is signed, and the README download commands do not verify downloaded artifacts.

**Remedy:** add common CLI, SSH/profile/KV, and real cross-runtime cache fixtures; make optional interop mandatory in release CI. Run platform-appropriate tests on Windows and declare the supported Node range. Commit a lockfile and use reproducible dependency installation. Align publication triggers, protect release environments/tags, and validate version agreement. Pin trusted build actions/helpers to reviewed immutable revisions, verify required signatures before publishing, provide provenance/checksum verification instructions, and ensure release gates cover both implementations.

## Recommended order of work

1. Establish trusted configuration/origin selection and safe transport defaults, especially Go redirect suppression.
2. Fix the explicit CLI-contract mismatches and the shell wrapper's failure propagation.
3. Validate/version cache payloads, eliminate fixed staging names, and make lifecycle decisions concurrency-safe.
4. Define token ownership, authentication identity, configuration immutability, and macro semantics.
5. Add shared end-to-end parity fixtures, real platform tests, and reproducible/protected release gates.

## Final scores

These are qualitative engineering judgments, not vulnerability counts or certification grades.

| Criterion | Score / 20 | One-line justification |
| --- | ---: | --- |
| Coolness | **17 / 20** | Agent-backed armored caching, offline secret resolution, and two interoperable implementation targets make a genuinely useful developer tool. |
| Robustness | **11 / 20** | Strong cache regression tests are offset by lifecycle/concurrency gaps, weak transport bounds, and concrete CLI/configuration parity defects. |
| Safety | **10 / 20** | Encryption and shell-value hygiene are good, but implicit configuration trust, Go redirect leakage, token retention, and insufficient context validation need hardening. |

**Signed: Codex (GPT 6.1-sol)**
