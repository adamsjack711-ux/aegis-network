# Independent validation of Phase 4E-C withdrawal-v2

**NO-GO for shared-writer activation.** The exact requested revision allowed a final valid anchor response to cross the freshness deadline in the publisher, relying appraisal and approval checks. A separate shadow-only fix checks trusted wall and monotonic time after the final blocking work. This validation exercised no protected effects. Native T4/T5 remain authoritative.

## Scope and provenance

- Historical implementation `f1692340b03521d44877b6ba4a2799db66a4576d` and requested v2 implementation `f7053de6f059535e631cbca9544cd2ee57b2ed48` were run from separate source archives. The shadow deadline fix is `8042097bbcd2a0f30d146d5057a6c846ee3ac746`, with the requested v2 pin as its direct parent.
- The new [validation oracle](../scripts/validate_phase4e_withdrawals.py) uses existing fixture provisioning, real private Unix sockets, independently reconstructed Merkle roots, direct Ed25519 verification of admission and withdrawal views, and read-only SQLite inspection. The original implementer wrote this separate harness. 4E-D separately verified the requested source at `bd481af1b00b2cd9c05c0dba31584269f3270b9f` and confirmed the post-I/O defect at `d4e8d130e6bee341c3f99734bdf5181ac04e46fe`. [4E-D report](../../phase4e-adversarial/docs/phase4e-adversarial.md)
- The topology demonstrates separate processes, keys and credentials under one host and controller. Injected view conflicts use only enrolled disposable test keys. Final-anchor and signer delays are injected in the fixture adapter around valid operations. Approval probes enter an empty context and never call a target writer.

## Safety, correctness and availability

| Case | Observation |
| --- | --- |
| Historical false positive and direct intake | The original implementation returned `reproduced` after one authorized matching receipt while the withdrawal was absent from the unchanged cut. V2 returned `inconclusive/revoked` with the same old cut. The admission vote and original scoped revoker signature verified independently. |
| One unavailable witness | Three checkpoint votes remained available. V2 held on the missing fourth withdrawal view. It also held when called directly at the publisher endpoint without the relying gate. The healthy path checked four distinct signatures over the same fresh challenge. |
| Stale and conflicting views | A cached response for an earlier nonce and a valid response delayed beyond its own challenge both held. A signed conflict between the publisher and reader that changed the exact scoped result held. Two valid same-nonce views differing only in unrelated withdrawals could yield an agreeing positive result. The published status binds the outcome and checkpoint, while the four view contents remain outside its commitment. |
| Duplicate, delayed and reordered receipts | An older signed withdrawal delivered after a newer unrelated one still denied the exact target. Reversing the two valid entries preserved the denial. A repeated valid intake yielded one durable retained record for that digest. A repeated leaf inside a single signed view invalidated that view and held. |
| Unauthorized and incorrectly scoped submissions | A publisher transport credential attempting revoker intake returned 403. Correctly signed withdrawals outside the issuer grant or cohort returned 409. These attempts left the denial ledger empty. An authorized withdrawal of a different bundle left the current exact bundle positive. |
| Restart and rollback | The original signed vote survived witness restart. Publisher and relying reader restart preserved the denial. Restoring the older denial database while retaining the anchor held. Restoring the exact current database recovered the denial. |
| Concurrent approval and revocation | A receipt arriving between the relying and publisher sampling rounds caused a disagreement and blocked the old approval. A receipt arriving after both rounds left an otherwise fresh token usable by the no-effect approval oracle until its existing deadline. The next refresh denied. Intake and writer commit remain separate distributed events. |

## Deadline defect and remediation

At the requested source, a synchronous floor read followed the last time sample. If the floor was valid but arrived late, the read could advance beyond challenge expiry and still permit a stale result or approval. The original relying call returned `reproduced` 32.41 ms after signed expiry. The no-effect approval context opened 35.85 ms after its monotonic deadline, and the publisher returned `reproduced` 37.08 ms after signed expiry. The separate fix samples after floor confirmation in the relying appraisal and approval checks and after signing before publication. The same three probes held at the repaired pin even when the valid floor response arrived 33.99–37.61 ms beyond expiry. The fix retains the earlier monotonic deadline derived from the signed expiry so a bounded backward UTC correction cannot extend it. Six regression cases cover the relying read, approval read, publisher read, delayed signing, and two early signed-expiry bounds under a bounded backward clock correction. 4E-D independently ran all six regressions from an archive of the repaired pin and passed a separate 15-case timing matrix across publication, relying refresh and approval. That matrix covered exact UTC expiry, the earlier monotonic bound, the shorter reader deadline and monotonic rollback. [4E-D timing results](../../phase4e-adversarial/benchmarks/phase4e-adversarial/c-timing-8042097-independent.xml)

A complete cross-service guarantee still requires an independently verified protected transaction with anchored state and enforced monotonic deadlines.

## Measurements at the requested revision

Twelve trials per arm at each history size on arm64 macOS 27.0.1 with Python 3.15.2. Latencies are nearest-rank p95 for the complete relying appraisal including independent publication. Expected positive controls are the healthy and valid unrelated-withdrawal arms. A fail-closed hold during an unavailable or invalid required view counts against availability and does not count as a false denial.

| Profile | Records | Healthy p95 | Positive with one witness offline | Positive after matching receipt before inclusion |
| --- | ---: | ---: | ---: | ---: |
| `checkpoint-v1` | 4 | 48.57 ms | 12/12 | 12/12 |
| `withdrawal-v2` | 4 | 65.11 ms | 0/12 | 0/12 |
| `checkpoint-v1` | 128 | 499.05 ms | 12/12 | 12/12 |
| `withdrawal-v2` | 128 | 521.41 ms | 0/12 | 0/12 |

V2 had **0 false denials in 48** expected-positive samples. Its missing-view hold took 8.64 ms and 8.52 ms p95 at the two sizes. The three deliberately delayed final reads are separate safety violations at the requested pin and do not enter the warm latency table. [Historical raw result](../benchmarks/phase4e-withdrawal-independent-historical.json) · [Requested candidate samples](../benchmarks/phase4e-withdrawal-independent-candidate.json)

The repaired profile preserved **0 false denials in 48** expected-positive samples, **24/24 holds** with one lane unavailable, and **24/24 revoked appraisals** before inclusion. Healthy appraisal p95 was **71.56 ms** at four records and **540.31 ms** at 128. Matching-receipt appraisal p95 was **62.38 ms** and **571.12 ms**. These samples describe the local fixture. [Repaired candidate samples](../benchmarks/phase4e-withdrawal-independent-fixed.json)

## Coverage boundary and remaining gates

Four fresh authenticated views establish what the responding witnesses attest for the challenge. A valid exact withdrawal durably accepted by one honest, responding witness is covered once that witness samples it. This remains true below the three-vote inclusion threshold. Submissions that have never been admitted, a withheld receipt at a sole Byzantine witness, and receipts accepted after sampling can remain invisible. The base 3-of-4 checkpoint model tolerates at most one Byzantine witness domain. The four-view positive rule accepts the availability cost of any missing lane. A single admission vote does not independently attest historical time when its signer lies.

Before writer activation, review and rerun the fault matrix independently with the exact bound writer candidate. The native writer still needs a reviewed 4E-A/4E-B/4E-C binding at the protected transaction, comprehensive deny precedence, restart-safe interruption, and coverage of before-commit revocation and deadline races. Distributed release further requires multi-host timing and fault tests with independently administered keys, services and restore anchors. Single-host evidence and previous Docker results establish narrower fixture behavior.

The full default suite from the repaired pin passed **289 tests**, including six new expiry regressions. Three Docker opt-ins were skipped in this run, with one inherited Starlette/httpx warning.

## Reproduction

Use a repository Python environment with the project test dependencies, and keep the fixture paths disposable. The oracle verifies the historical case with `--historical`. Its exit status is 1 at the original v2 candidate when it detects the three freshness violations. The same oracle on the repaired pin must exit 0.

```sh
repo=$(git rev-parse --show-toplevel)
pin=8042097bbcd2a0f30d146d5057a6c846ee3ac746
scratch=$(mktemp -d /tmp/aegis-4ec.XXXXXX)
git archive "$pin" | tar -xf - -C "$scratch"
(
  cd "$scratch"
  PYTHONPATH=src:. python "$repo/scripts/validate_phase4e_withdrawals.py" \
    --revision "$pin" --output /tmp/phase4e-validation.json
  PYTHONPATH=src:. python -m pytest -q -p no:cacheprovider
)
rm -rf "$scratch"
```
