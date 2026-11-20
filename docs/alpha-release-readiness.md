# Alpha release readiness

**Current candidate:** `integration/alpha-master-astra`, forked from reviewed evidence pin `e6e58edb02c68797dc6e23a36a3c0fd1d443cfd9`. The earlier exact source suite at `c164a8f` passed **392, skipped 37, expected-failed one** using local-lab sockets; the first restricted-sandbox attempt failed 55/errored 25 due Unix-socket `EPERM`. The newer isolated candidate conditionally integrated the unique bounded grant reader after independent source review. The final exact implementation intake `2b371af` passed **424, skipped 37, historical-expected-failed one** with local lab sockets. Five sequential intake suites and raw JUnit are recorded in [the integration review](alpha-integration-review.md). The external five-pin review is `a664a27`; no release decision is inferred from branch existence.

| Scope | Decision | Missing proof |
| --- | --- | --- |
| Observation-only source diagnostic | **GO for isolated lab appraisal** | Bounded grant-read mechanics pass source tests, but local file custody and installed-platform behavior remain open; not a distributable release. |
| Installable Debian/Ubuntu CLI alpha | **NO-GO** | Reviewed original offline dependency archives, exact artifact build, four fresh Python 3.12/3.13 cells, ≥84 installed-console cases, 68 resource/privacy children, exact installed syscall tracing and independent final-pin acceptance. |
| Offline AI research | **GO for inert synthetic-fixture study only** | Independent semantic support and authenticated advisory provenance unproven. |
| Real-model AI evaluation/release | **NO-GO** | Separately authorized model/endpoint/export/token/cost cap and actual billing oracle, paired reproducible trials and semantic adjudication; zero real calls so far. |
| Diagnostic Runner | **NO-GO** | Design-only; containment, operator capability and frozen safety/performance validation absent. |
| Distributed autonomous enforcement/production | **NO-GO** | Five-second all-agent withdrawal recovery, target-side generation fencing, Trust custody and rollback safety remain open. |

The next three engineering actions are: (1) independently close the grant race with a meaningful actual-descriptor oracle and explicit file-custody contract; (2) provision a reviewed offline wheelhouse and fresh four-cell installed matrix through separate authorization; (3) run privacy/resource tracing on that exact installed artifact. A bounded real-model experiment is a separate optional authorization decision and cannot alter enforcement authority.
