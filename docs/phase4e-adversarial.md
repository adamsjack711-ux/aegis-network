# Phase 4E-D independent validation

**Acceptance decision: hold distributed enforcement.** Four ordinary findings published ahead of a queued withdrawal in four independent baseline trials. The agent durably denied the affected finding within 1.90 seconds of the restart request in each trial. The local defensive controls passed. Phase 4E implementation acceptance remains pending an integrated revision and evidence from the required authority and failure domains.

The integration lead approved Phase 4D commit `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f` as the control. The acceptance freeze is `f4142f710d50e22570610cd8ffcc77a58b236740`. The harness pin is `61909cc085389a1987a7b835517270160a896ab2`. The integration snapshot `05bbf0b5eaa9f15b2b512e6e48c11e3ef6de00ae` included planning, independent reviews, retained benchmark records, a withdrawal diagnostic, and the criteria freeze. Its implementation and inherited test trees matched the control. This validation handoff follows the approved baseline on its own branch. [Frozen criteria](phase4e-acceptance.md) · [Phase 4C findings](phase4c-adversarial.md) · [Phase 4D release readiness](phase4d-release-readiness.md)

## Findings register

Severity describes the observed defect or the consequence of an open deployment gate. Reproducibility applies to the exact fixture exercised. The three inherited High findings retain their Phase 4C identifiers and severity.

| Finding | Severity | Disposition and reproducibility |
| --- | --- | --- |
| 4E-D01 / 4C-06 / T6-01 · Withdrawal priority fails on the approved baseline | Medium | Reproduced in four fresh NATS/PostgreSQL projects, including compatibility and scratch-cleanup reruns. PostgreSQL showed the signed withdrawal pending with four ordinary records. JetStream independently placed it fifth each time. The affected agent had a durable exact scoped tombstone after 1,801.041, 1,807.267, 1,750.470, and 1,890.798 ms from the restart request. The test used a fixed burst of four ordinary findings and one agent. Sustained load, reserved ingress, and continuously reachable denial latency remain unmeasured. |
| 4C-01 · Independent withdrawal completeness at deployed writers | High | Open deployment gate. Local journal freshness and signed historical recovery passed twice. Authenticated independent admission, current cut delivery under real partitions, and rollback-resistant pins across failure domains remain unverified. |
| 4C-02 · Cross-broker ownership and generation fencing | High | Open deployment gate. Locally signed home contention, generation transfer, and modeled expiry passed twice. The harness uses one SQLite home and trusted adapter inputs. Broker authentication, generation-bound ACK and cursor progress, and every independently stored writer barrier remain unverified. |
| 4C-04 · Evidence withdrawal and independent custody | High | Open deployment gate. Signed status, unenrolled verifier denial, a verifier-key withdrawal, retained relying floor, and unavailable status at the fixture writer passed twice. The local test operator controlled every key and store. Operational custody and anchored restore remain unverified. |
| 4C-03 · Historical revoker lifecycle | Medium | The local journal denied the old view during modeled isolation and recovered the exact scoped withdrawal after the revoker grant expired. Both runs used the same enrolled roster and a modeled clock. Deployed revoker rotation, compromise handling and prolonged reconnect remain open. |
| 4C-05 · Complete independent observation and restrictive recovery | Medium | Nine paths across three fixed loopback endpoints were checked where all were reachable. Missing one replica left the audit at `recovery_required`; two reachable replicas stayed quarantined and all three reached independently observed safe hold on restart. Both runs passed. Inventory and custody beyond this fixture remain open. |
| 4E-D02 · Initial broker drill observer error | Test tooling | The initial SQL observer waited for an override row. Rapid represents the denial in the exact scoped tombstone row joined to the original finding. The initial run timed out even though readback later confirmed the tombstone. The corrected observer joins publisher, artifact and digest and matches the authenticated revocation decision. Failure reproducibility uses the four corrected trials. The first run remains in the raw results. |

## Scenario coverage

The table records the independent control-run evidence. Every full Phase 4E gate remains open pending the integrated candidate. “Partial” identifies the specific local observation available. “Blocked” identifies missing runtime or coverage.

| ID | Baseline status | Observed or missing evidence |
| --- | --- | --- |
| W01 | Fail | Signed normal traffic plus an exact withdrawal. PostgreSQL admission and JetStream dispatch disagreed with priority in every trial. Continuous-load and reachable-service latency remain open. |
| W02 | Fail | Restart preserved the queued withdrawal and produced its durable denial under five seconds. Ordinary publications overtook it in all four fresh projects. |
| W03 | Partial | W04 shows expiry of a previously valid cut when coverage is unavailable. Independently receipted but withheld withdrawal coverage at a deployed writer remains open. |
| W04 | Partial | A controlled offline journal clock crossed the recorded cutoff and the revoker's grant expiry. The reopened client held while offline, retained the old cursor, then read and persisted the actual historic withdrawal. Physical agent reconnect and live rotation remain open. |
| I01 | Partial | A second same-deployment enrollment and a concurrent second home claim were denied. One home, two modeled broker contexts. |
| I02 | Blocked | Authenticated broker contenders and durable per-broker ACK observations require deployed adapters and enrolled brokers. |
| I03 | Partial | A previous assignment was denied after transfer. Home audit advanced monotonically. Multi-writer commit and ACK fencing remain open. |
| I04 | Partial | A modeled signed-assignment expiry stopped peer writes. HTTP and audit showed restrictive recovery and fences advanced on restart. Transport credential expiry remains open. |
| I05 | Blocked | No independently anchored ownership restore or multi-writer barrier run. |
| E01 | Partial | A legitimate verifier outside the enrolled trust set added zero corroborating records. The known signed head was unchanged. A trusted-identity forgery campaign is outside this run. |
| E02 | Blocked | Contradictory independently produced observations at the integrated candidate's writer remain untested. |
| E03 | Partial | A duly signed verifier-key withdrawal advanced both witness archives and the reader's durable floor. Exact appraisal remained denied after reopening the reader. End-to-end write binding under this specific withdrawal remains open. |
| E04 | Partial | Independent signatures bind a common archive digest, exact scope, challenge and validity. Stale and conflicting live status branches remain open. |
| E05 | Partial | An unavailable test status provider stopped expansion and forced restrictive HTTP responses. Distributed witness custody and untrustworthy witness coverage remain open. |
| M01 | Partial | A validly reviewed digest for a different plan left every fence at zero and the audit empty. Separate elapsed approval expiry and candidate coverage remain open. |
| M02 | Pass in fixture | An appraised plan without local review left all nine routes open at fence zero and committed zero writes. The matched approved control independently showed three restricted marker routes and six healthy benign routes. |
| M03 | Pass in fixture | Unavailable status and modeled owner expiry each left exactly one canary restriction and zero peer restriction writes. HTTP and durable fences were inspected independently. |
| M04 | Partial | Restart of restrictive state advanced fences and produced verified safe hold. An independently anchored old snapshot challenge remains open. |
| M05 | Pass in fixture | The audit retained `recovery_required` while one HTTP endpoint was unreachable. Both reachable replicas were quarantined. Restart restored full observation at fence two. |
| M06 | Partial | Probes bracketed recovery and observed no protected marker reopening. Continuous sampling and deployed fault windows remain open. |
| C01 | Blocked | A broker restart and an Evidence withdrawal were exercised separately. Their simultaneous effect at an integrated guard remains open. |
| C02 | Blocked | Home transfer and Evidence status were checked separately. The joint stale-checkpoint path remains untested. |
| C03 | Blocked | The witnessed fixture rejected use of coordinator replay during local controls. An untrustworthy coordinator under a real network partition remains untested. |
| C04 | Partial | Simulated status loss stopped peer writes. A new fixture instance reopened the store with status still unavailable and all nine routes quarantined at fences 2/1/1. Independent networked witness, process failure, and continuous observation remain open. |
| C05 | Partial | Modeled agent journal recovery required current history and retained the historical withdrawal. No combined delayed broker delivery and live agent recovery timing. |

## Evidence and oracle

- An external observer uses standard-library HTTP against inventoried IPv4 loopback emulators, checking response status, complete fixture body, target identity, and fence independently of the control-plane observer. Expected modes are fixed in the test. Cross-checks reopen SQLite in read-only mode and query the audit sequence, target modes, generation, and retained status floor.
- The signed-state observer verifies Ed25519 endorsements and ownership requests with pinned public keys, independently reconstructs the status archive root, and checks the exact challenge and scope. Its public-only verifier rechecks retained samples and recomputes publication rank from independent durable and broker records. [Public verification script](../scripts/phase4e_verify_results.py)
- The broker drill uses the inherited disposable lab setup, one live coordinator and agent, one NATS instance and one PostgreSQL instance. The oracle uses an independent PostgreSQL read-only transaction, direct JetStream sequence reads, and direct SQLite tombstone readback. Time starts before the restart command, giving a conservative recovery upper bound. The run does not attribute the denial exclusively to JetStream delivery because journal reconciliation can also write it. [Withdrawal drill](../tests/phase4e/test_withdrawal_delivery.py)
- For the opt-in two-stream implementation, a separate oracle fills the ordinary stream by lowering its storage cap, then restarts the broker with both traffic types durably queued. It requires critical publication and agent denial while the ordinary outbox rows stay pending and the ordinary stream sequence stays fixed. After releasing that cap, it verifies ordinary publication and local audit progress. A single observer monotonic clock measures denial and ordinary release. The two streams' sequence numbers are used within their respective streams only.
- The retained results include each failed and passing run. They carry disposable public material, HTTP traces, durable readback and timestamps. The first three live attempts and initial local run finished before the temporary credential pause. The two follow-up broker runs and two expanded local runs used only throwaway credentials after the scope clarification. All traffic and credentials stayed on explicit localhost fixtures and disposable containers. The final scratch directory was empty after the broker drill. [Raw results and checksums](../benchmarks/phase4e-adversarial) · [Local harness](../tests/phase4e/test_defensive_validation.py)

## Reproduction and terminal handoff

The commands assume the original repository root, its existing Python environment, and permission to bind Unix and IPv4 loopback sockets. The broker drill additionally needs the local Unix Docker socket and cached `nats:2.10-alpine` and `postgres:16-alpine` images. It creates and cleans up its own project and volumes. Keep fresh evidence outside the retained results directory.

```sh
repo="$PWD"
harness="$repo/.worktrees/phase4e-adversarial"
python="$repo/.venv/bin/python"
scratch="$(mktemp -d /tmp/aegis-4ed.XXXXXX)"
cd "$harness"
git status --short --branch
git rev-parse HEAD
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$harness/src:$harness/tests/phase4d:$harness/scripts"

"$python" -m pytest -q -ra -o junit_family=legacy -p no:cacheprovider \
  tests/phase4e/test_defensive_validation.py --junitxml="$scratch/local-baseline.xml" --tb=short

for trial in 1 2; do
  AEGIS_PHASE4E_LIVE=1 AEGIS_PHASE4E_PRIORITY=0 \
    "$python" -m pytest -q -ra -o junit_family=legacy -p no:cacheprovider \
    tests/phase4e/test_withdrawal_delivery.py::test_W01_W02_queued_withdrawal_after_broker_restart \
    --junitxml="$scratch/broker-$trial.xml" --tb=short
done

(cd benchmarks/phase4e-adversarial && shasum -a 256 -c SHA256SUMS)
"$python" scripts/phase4e_verify_results.py benchmarks/phase4e-adversarial/*.xml
```

Expect 10 local cases to pass and both baseline broker trials to exit 1 at the frozen priority assertion. The retained diagnostic predates the observer correction. Compare its preserved failure with both corrected trials. [Readback summary](../benchmarks/phase4e-adversarial/readback.json)

When an integrated candidate is available, set `AEGIS_4E_CANDIDATE` to its reviewed exact hash. Keep the acceptance branch and the implementation branches separate. Extract the candidate into a temporary directory and use its source, scripts, and fixture setup with the frozen validation tests.

```sh
candidate="$scratch/candidate"
mkdir "$candidate"
git merge-base --is-ancestor ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f "$AEGIS_4E_CANDIDATE"
git archive "$AEGIS_4E_CANDIDATE" | tar -x -C "$candidate"
git rev-parse "$AEGIS_4E_CANDIDATE^{commit}"

export PYTHONPATH="$candidate/src:$candidate/tests/phase4d:$candidate/scripts"
(
  cd "$candidate"
  AEGIS_PHASE4E_LIVE=1 AEGIS_PHASE4E_PRIORITY=1 \
    "$python" -m pytest -q -ra -o junit_family=legacy -p no:cacheprovider \
    "$harness/tests/phase4e" --junitxml="$scratch/integrated-candidate.xml" --tb=short
)
```

Keep acceptance open until the exact candidate has independent results for withdrawal service under load, rollback-resistant ownership and status, authenticated role custody, and all protected writer and ACK lanes. The observed Phase 4D behaviors support disposable lab and shadow work.
