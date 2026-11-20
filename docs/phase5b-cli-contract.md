# Phase 5B Linux observation CLI contract freeze

Baseline `ee739cacfaa3f81a0994b4d7802fd2943c067d86`. The first installable CLI inspects a local Linux package inventory and reports possible exposure from a pinned local advisory or signed-finding bundle. Its process has no protected writer capability, mitigation entry point, broker credential, privileged network scanner or local approval key. Default operation is offline and read-only.

## Proposed interfaces

| Surface | Contract |
| --- | --- |
| InventorySnapshot v1 | Host-local opaque snapshot ID, capture time, source adapter and version, OS release, package manager, package ecosystem/name/version/architecture and optional package URL. Store no secrets or user files. Report inaccessible sources and partial inventory. Root privilege is not a prerequisite. |
| ExposureObservation v1 | Exact inventory snapshot and advisory/finding digest, package identity and version comparator used, matched/unmatched/unknown result, reason, advisory source and time, evidence confidence and uncertainty, expiry or withdrawal status if independently available, and CLI version. Unknown is never promoted to safe or affected. |
| CLI output | Stable JSON for automation and concise human text. Exit status distinguishes successful observation, partial/unknown input and operational failure. Exposure is reported in output with a documented optional exit policy, because package matching is not an enforcement decision. No write or remediation command. |
| Install boundary | Python package console entry point with pinned supported Linux distributions and package-manager adapters; no post-install scripts, system services, firewall changes or background daemon. Local file inputs only until advisory source and network policy are reviewed. |

The CLI may consume the Phase 5A deterministic candidate format only as explicitly labeled research. A signed Finding still needs its existing signature and publisher-grant validation. The CLI can display native T4/T5 status only if supplied with verifiable current proof and local trust roots. A missing status becomes unknown. The output cannot serve as local approval or target authorization.

## Acceptance criteria

1. Install and invoke the CLI in disposable Linux containers representing each declared supported package manager. Record image digests and package fixtures. Ordinary unprivileged execution succeeds on readable inventory and reports partial state when access is denied.
2. Golden inventory and advisory fixtures cover exact match, unaffected version, ecosystem mismatch, epoch/revision boundaries, missing package, malformed input, stale or withdrawn advisory and unsupported comparator. Every output includes provenance, snapshot ID, comparator and uncertainty.
3. Static and runtime checks show zero protected-writer imports, target writes, mitigation calls, outbound network connections and privileged file access during observation. A malicious advisory cannot alter CLI behavior or invoke commands.
4. JSON schema and exit codes are stable across repeated runs, and human output does not claim protection. Capture CPU, peak RSS and elapsed time for small and large synthetic inventories with explicit denominators.

Open decisions include first supported Linux distributions, package database access rules, source of offline advisory snapshots, package URL normalization and how to present partial inventories. These decisions require fixture evidence before a compatibility promise.
