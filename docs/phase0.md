# Phase 0: reuse assessment

Reviewed 2026-11-19 against primary project documentation. These are integration candidates, not dependencies in the current slice.

| Project / standard | Reuse decision | Boundary |
| --- | --- | --- |
| [OSS-CRS](https://openssf.org/projects/oss-crs/) | Consider its standardized CRS orchestration, OSS-Fuzz target interface, and resource budgets for isolated verification workers. | Do not run a CRS against public targets or make its output an authorization signal. |
| [Buttercup](https://github.com/trailofbits/buttercup) | Study fuzzing, reproducer, and patch evaluation workflows for later disposable labs. | Its AI patcher output requires independent tests and local approval. |
| [GUAC](https://github.com/guacsec/guac) | Consider for software identity and dependency graph correlation at scale. | A graph relationship is evidence for matching, not permission to mitigate. |
| [OSV schema](https://ossf.github.io/osv-schema/) | Reuse vulnerability IDs, package URLs, and affected version semantics. Exact enumerated versions are used in this slice. | Do not treat a version range as safe without ecosystem-specific comparison logic. |
| [CycloneDX](https://cyclonedx.org/specification/overview/) and [VEX](https://cyclonedx.org/use-cases/vulnerability-exploitability/) | Ingest SBOM component identities and contextual affected/not-affected claims later. | VEX assertions need issuer trust and local product context. |
| [in-toto attestations](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) | Map evidence digest and predicate to subject-bound attestations in a future schema version. | The current envelope is a simpler Ed25519 signed JSON object and is **not** in-toto compatible. |
| [TUF](https://theupdateframework.io/spec/) | Adopt role separation, expiry, anti-rollback, and delegated trust concepts for artifact distribution later. | The current publisher key file and sequence watermark are **not** a TUF implementation. |

The first slice deliberately avoids integrating large research systems. It validates the interface between signed evidence and independently controlled local decisions before adding discovery, exploit testing, or mitigations.
