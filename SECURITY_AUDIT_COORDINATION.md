# Security assessment coordination

Two independent source-only reviews assess f368802700f03c8b632bbacefbfc71dbfaae04f4.
Reports are preserved verbatim; neither findings nor scores were calibrated.
Execution headers verify Claude Opus 5.5 and GPT 6.1-sol. Exact successful
inputs are maintained in the operator's SA prompt files; hashes/commands are
in SECURITY_AUDIT_PROVENANCE.json. Excluded-report/README input boundaries
were checked against the logged commands; Git hashes/filename inventory are metadata.

| Review | Coolness | Robustness | Safety |
| --- | --- | --- | --- |
| Claude Opus 5.5 | 15/20 | 13/20 | 13/20 |
| GPT 6.1-sol | 17/20 | 13/20 | 12/20 |

## Release disposition and open boundaries

The npm job is explicitly gated on a created v* tag. Functional code and
workflow assessed here precede release-version metadata only.
Host validation independently passes 74 Node24 tests, ESLint, Go vet/race,
Node16 parsing/loading and native Windows cross-builds. Reviewers' read-only
sandboxes blocked runtime checks; that is a limitation, not evidence that
those product tests fail. Signing/checksums are checked on the actual release
artifacts, not inferred from workflow configuration.

Project configuration has broad authority over the environment and local
armored files. The high-severity untrusted-configuration finding remains an
open boundary: documentation requires reviewing/trusting configurations but
is not a technical trust gate or sandbox. Host synthetic probes confirm the
export/decrypt capability without executing exported commands or using a real
cache. No project-approval system or arbitrary variable denylist was introduced.

Other reported boundaries remain: shell-wrapper failure propagation, dotenv
encoding, concurrent KV writes, response/resource limits, mutable publication
inputs, and the declared interpolation semantics. Exact nyks behavior and
native recursion are retained; these reviews do not certify exhaustive parity
or vulnerability-database clearance. No claim is made that every finding is fixed.
