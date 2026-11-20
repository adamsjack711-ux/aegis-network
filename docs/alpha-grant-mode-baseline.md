# Legacy grant file mode compatibility measurement

Measured **before any shared source edit** on clean `feat/alpha-grant-astra` source parent `29455087922a728a41936d8c5c79ff9942e1e3df`. The probe wrote only disposable `fixtures/phase-next-cli/trust.json` bytes to a temporary file, changed its mode, then called the existing `config.load_publishers(path)` under macOS 27.0.1 arm64, Python 3.15.2, UID 501. Raw results: `benchmarks/alpha-grant/legacy-mode-probe.json`. The first harness attempt left an empty stdout artifact after it tried to overwrite a previous read-only test file; the harness was corrected by resetting owner write permission before each rewrite. That harness error was not a product test failure. The empty first-attempt stdout is retained as `legacy-mode-probe-first-failed.stdout`.

| Mode | Old loader result |
| --- | --- |
| `0600`, `0644`, `0640`, `0444`, `0400`, `0666`, `0622` | Accepted the same `validator-fixture`/`validator` grant. |
| `0000` | `PermissionError` for the non-root owner process. |

The old loader has **no mode/owner/ACL gate** beyond OS read permission. Therefore the earlier proposed `0600`/`0644`-only, group/other-write and ACL-unknown rejection policy is a **separate compatibility change**, not part of the approved narrow race repair. The isolated implementation attempt will preserve current readable-file behavior while recording `fstat` metadata and using one no-follow bounded descriptor read. A future stricter filesystem custody profile needs explicit Main/VAL approval, old/new mode tests on Debian/Ubuntu and macOS, and an operator migration path. This one-host probe does not establish root-owned file, ACL or Linux behavior.
