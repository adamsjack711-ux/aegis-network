# Phase 4E-D independent validation

**Acceptance decision: hold distributed enforcement.** On the reviewed combined source, opt-in withdrawal delivery passed its local priority probe, and the independently exercised B and C prototypes held their isolated writer barriers. The actual shared writer passed the inherited T6 checks. B and C still have separate writer models, leaving the combined authority path and its release gates open.

The integration lead approved Phase 4D `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f` as the control and identified `4918dadacc8dedd96d1c4b506e5f746040a01941` as the exact reviewed combined source. The acceptance freeze is `f4142f710d50e22570610cd8ffcc77a58b236740`. This validation branch reads pinned source from temporary exports. [Frozen criteria](phase4e-acceptance.md) · [Phase 4C findings](phase4c-adversarial.md) · [Phase 4D release readiness](phase4d-release-readiness.md)

## Results by source and writer

| Source and lane | Independent disposition |
| --- | --- |
| Approved baseline `ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f` | Ten local controls passed twice. Four fresh broker drills published a withdrawal fifth among five pending records. The exact durable denial was observed 1.75–1.90 s after the restart request. |
| Withdrawal feature `6e8bedccb184f3b4268670c93bc22310234c4f5e` | Two fresh opt-in trials saw the critical withdrawal and durable denial before releasing a full ordinary stream. Restart-to-denial upper bounds were 1,769.525 and 1,742.638 ms. All four ordinary records subsequently published and appeared in the local audit. |
| Identity feature `cb7986d1abb7491e73f5ce53bb01778ba7159d94` | Two authenticated broker contenders yielded one home owner in each of two trials. One unavailable writer left the successor preparing and the reachable writer quarantined. Old signed intent added zero receipts. Both writers durably installed the successor fence before fresh approvals produced test effects. |
| Trust feature `f1692340b03521d44877b6ba4a2799db66a4576d` | Two trials verified the actual scoped status signatures and signed cut, then independently fetched the exact revoked leaf with the primary archive down. Three witnesses supported appraisal and two stopped it. Restart retained the revocation and the fixture audit contained only the original canary and expiry. |
| Native shared T6 writer at `16e71ed1ccaf96209054fa3e5ddd03dd6e24b273` and `4918dadacc8dedd96d1c4b506e5f746040a01941` | Fifteen independent controls passed at each pin with the priority flag off. Healthy use of three journal witnesses preceded a two-witness hold. An incomplete newer cut stayed pinned and prevented an older view from authorizing peer writes. Exact post-canary Evidence withdrawal, stale ownership and wrong signed action/target all stopped the attempted peer work. A wrong expected fence stopped the initial activation. External HTTP and read-only SQLite confirmed the scope, fences and restrictive recovery. |
| Opt-in and additive services at combined source `4918dadacc8dedd96d1c4b506e5f746040a01941` | The three separate A, B and C observers passed. A recorded a 1,657.930 ms restart-to-denial upper bound with four ordinary records held and a 281.191 ms ordinary drain after release. B and C retained the same local writer and trust boundaries as their standalone checks. |
| Pre-intake and post-audit crash, A `4c6f674c1915ee255222f02c38c2e2c010421b1f` and combined `4918dadacc8dedd96d1c4b506e5f746040a01941` | The pre-intake agent first had a durable denial visible at 30.434 and 30.479 s from HTTP submission. The post-audit agent already had a denial at 50.269 and 47.655 ms, and its broker ACK was first observed at 30.434 and 30.477 s. Each recovered agent retained one durable decision and advanced its broker ACK floor. Both runs were dry-run transport. |
| Combined agent-only broker partition | Withdrawal reached JetStream while the disconnected worker had no durable local denial or ACK advancement. After rejoin the independent observer read the denial at 1.964 s and the broker ACK at 1.968 s. Target state during the transport-only run is unobserved. |
| One-witness admission at original C and combined source | The enrolled witness returned a valid, durably recorded receipt for a synthetic Evidence withdrawal. Scoped appraisal remained `reproduced` on both exact pins. After quorum receipt, a separate delayed-archive trial held before inclusion and again after restart. The one-witness trial appraises only and attempts zero target writes. |
| B restore at combined source | Restoring only the older home snapshot while retaining a newer external anchor rejected the staged current-owner write. A follow-up snapshot immediately after that rejected write showed quarantine already durable. The independent HTTPS observation left the snapshot unchanged. The old action receipt stayed intact. A higher reconciled generation with new exact approval was required for another effect. |
| Inherited Evidence contradiction and certified-view continuity on combined source | Both focused regressions passed. The inherited shared writer invalidated an exact plan after contradictory Evidence. The native T5 relying floor rejected older and conflicting certified status. These checks exercised the predecessor gates. |
| C shadow remediation `f7053de6f059535e631cbca9544cd2ee57b2ed48` | The original assertion still failed with `checkpoint-v1`. The opt-in `withdrawal-v2` passed it and returned revoked after the same one-witness admission, before archive inclusion. A stopped admitting witness held status and restart preserved denial. A separate trial held when a fourth withdrawal view was unavailable despite three checkpoint signatures, excluded an unauthorized transport submission, preserved positive appraisal for an unrelated scope, denied a stale captured view, and rejected an older relying ledger against its intact anchor. |
| C shadow import `86d2454bb9132642ce0b05fda0c7cd681c8f065f` | Both opt-in shadow probes and all 15 native T6 controls passed from one pinned integration export. Shadow appraisal uses its own writer boundary. |
| A transport-to-proof contract `c1e5702202ad317396856ee4af89590e14a57a16` | The focused receipt contract test passed. It separated transport delivery from independent receipt and inclusion, and showed the existing reader holding the prior cut needs a separate discovery path for early receipt. That pin proposes a deny-only adapter, and its delta adds a contract test and documentation. No runtime adapter is exercised by that result. |

The native writer constructs the T6 `EvidenceGate`, checks its journal and `NativeEvidenceStatus`, and signs local commands for the shared SQLite `OwnershipHome`. At the reviewed combined pin, Phase 4E-C `Gate` appraises an independently witnessed common cut in its own service lane, and Phase 4E-B owns a separate synthetic marker and receipt store. A common exact-plan binding across that cut, B owner and writer barrier, broker generation and ACK lane, and actual guarded mitigation transaction remains unimplemented. The tests preserve the distinct claims of each path.

All three inherited Docker regressions passed on the exact combined source in a detached local Git clone in 49.96 seconds. The Phase 4A workload independently confirmed 169/169 expected broker ACKs. The initial archive-based attempt passed the T4 witnessed broker replacement and T3 two-JetStream lease cases. Its Phase 4A benchmark stopped before lab setup because it records the Git source commit. That diagnostic stays in the retained results. [Final JUnit](../benchmarks/phase4e-adversarial/combined-inherited-docker.xml) · [Raw Phase 4A workload](../benchmarks/phase4e-adversarial/combined-inherited-phase4a.json.gz)

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
| 4E-D03 · Shared authority composition missing at the reviewed source | High | Source-confirmed. The separate B and C services have local rehearsal evidence, while the actual shared mitigation writer is guarded by the inherited T6 composition. A joint release claim needs one writer with exact current A/B/C bindings and end-to-end fencing and observation. |
| 4E-D04 · Crash drill import error | Test tooling | The initial controlled crash test imported its durable-name helper from the wrong module at both pins. Both diagnostic reports are retained. The correction keeps the crash and ACK assertions intact. |
| 4E-D05 · Single-witness withdrawal can leave positive Evidence | High | Reproduced at original C, the reviewed combined pin, and the `checkpoint-v1` profile on the remediation pin. One authenticated witness had durably accepted the withdrawal and returned its signed receipt while fresh positive appraisal remained available. The opt-in C `withdrawal-v2` profile passed the strict appraisal guard and lost-view and restore checks. Shared-writer closure remains open. No target write or marker reopening was attempted by the single-witness probe. |
| 4E-D06 · Five-second all-agent withdrawal reporting gate | Medium | Open. The exact crashed pre-intake agents yielded no independent durable denial observation within five seconds. Both post-audit agents retained an early denial, with ACK observations around 30.4 s. Transport-only runs supply no independent actuator or quarantine evidence. |
| 4E-D07 · Idle pre-observation quarantine | High | Related integration validation at `c32532c4aa709a4a11d9c53cf87deefb392efca8` reports reproducible durable-hold ordering failures on the idle ownership-loss path and the separate B marker service. Our B stale-restore path exercises an explicit rejected write before the observer, so its durable latch result covers that path. The separate integration artifacts retain both idle runs under `docs/phase4e-observer-order.md` and the `observer-order-*.json` files. |
| 4E-D08 · Shadow freshness is checked before final anchor I/O | High | Source-confirmed at C `f7053de`. The publisher checks expiry before the final checkpoint and withdrawal anchor reads and can sign afterward without sampling time again. The relying refresh and authorization use the same ordering. C's separate local reviewer reported expiry crossed in both relying paths without a target effect. The passing matched shadow tests in this branch cover receipt behavior and do not close the delayed-read condition. |

## Scenario coverage

The table records the scope of independently observed behavior at the named pins. “Partial” identifies a local result that falls short of the full distributed gate. “Blocked” identifies missing runtime wiring or coverage.

| ID | Baseline status | Observed or missing evidence |
| --- | --- | --- |
| W01 | Baseline fail, partial opt-in pass | All four baseline trials put the withdrawal last. All three priority trials delivered the withdrawal and observed durable denial ahead of four held ordinary publications. Continuous mixed-load and all-agent criteria remain open. |
| W02 | Baseline fail, partial opt-in pass | Restart retained the exact withdrawal. The priority fixture used a full ordinary lane and still completed independent durable denial in under five seconds. |
| W03 | Partial, C shadow v2 pass | Native T6 denied peer writes under an unresolved newer cut. C v1 held after quorum receipt and preserved positive appraisal after single-witness admission. Opt-in v2 denied before inclusion with the same one receipt. Joint writer coverage remains open. |
| W04 | Partial | A controlled offline journal clock crossed the recorded cutoff and the revoker's grant expiry. The reopened client held while offline, retained the old cursor, then read and persisted the actual historic withdrawal. Physical agent reconnect and live rotation remain open. |
| I01 | Partial | A second same-deployment enrollment and a concurrent second home claim were denied. One home, two modeled broker contexts. |
| I02 | Partial | Two mutually authenticated B broker adapters yielded one active generation. Real JetStream generation-bound ACK and cursor fencing are outside that adapter. |
| I03 | Partial | The native writer denied the old generation after a transfer. The B writer barrier held during one writer outage, and stale signed intent added zero receipts. Real JetStream generation-bound ACK remains open. |
| I04 | Partial | A modeled signed-assignment expiry stopped peer writes. HTTP and audit showed restrictive recovery and fences advanced on restart. Transport credential expiry remains open. |
| I05 | Partial | At the B local marker boundary, an older home restore with a current separate anchor denied the staged write and preserved the sole prior receipt. A read-only snapshot confirmed durable quarantine before the observer request. New exact approval followed a higher generation and a fresh barrier. Broker cursor/ACK and joint writer restore remain open. |
| E01 | Partial | A legitimate verifier outside the enrolled trust set added zero corroborating records. The known signed head was unchanged. A trusted-identity forgery campaign is outside this run. |
| E02 | Partial | The inherited shared-writer contradiction regression passed on the exact combined source. Contradictory C Evidence at the actual guarded writer remains blocked on wiring. |
| E03 | Partial | A duly signed verifier-key withdrawal advanced both witness archives and the reader's durable floor. Exact appraisal remained denied after reopening the reader. End-to-end write binding under this specific withdrawal remains open. |
| E04 | Partial | Independent signatures bind exact scope, challenge and validity. The shared T6 writer denied progression when the signed newer cut remained unresolved and an older cut was presented. Conflicting C status at the actual writer remains open. |
| E05 | Partial | Independent C processes appraised with three witnesses and held with two. The native writer stopped expansion and served restrictive HTTP on status loss. Operational custody and deliberate witness dishonesty remain open. |
| M01 | Partial | A valid review for a different plan, an invalid expected fence, and signed commands for the wrong action or target produced zero new effects. Separate elapsed approval expiry and distributed candidate coverage remain open. |
| M02 | Pass in fixture | An appraised plan without local review left all nine routes open at fence zero and committed zero writes. The matched approved control independently showed three restricted marker routes and six healthy benign routes. |
| M03 | Pass in fixture | Unavailable status and modeled owner expiry each left exactly one canary restriction and zero peer restriction writes. HTTP and durable fences were inspected independently. |
| M04 | Partial | Restart of restrictive state advanced fences and produced verified safe hold. An independently anchored old snapshot challenge remains open. |
| M05 | Pass in fixture | The audit retained `recovery_required` while one HTTP endpoint was unreachable. Both reachable replicas were quarantined. Restart restored full observation at fence two. |
| M06 | Partial, separate idle gate failed | Probes bracketed the exercised recovery and observed no protected marker reopening. Integration validation reports that idle ownership loss can precede durable quarantine. Continuous sampling and deployed fault windows remain open. |
| C01 | Blocked | A broker restart and an Evidence withdrawal were exercised separately. Their simultaneous effect at an integrated guard remains open. |
| C02 | Blocked | Home transfer and Evidence status were checked separately. The joint stale-checkpoint path remains untested. |
| C03 | Blocked | The witnessed fixture rejected use of coordinator replay during local controls. An untrustworthy coordinator under a real network partition remains untested. |
| C04 | Partial | Simulated status loss stopped peer writes. A new fixture instance reopened the store with status still unavailable and all nine routes quarantined at fences 2/1/1. Independent networked witness, process failure, and continuous observation remain open. |
| C05 | Partial | Controlled live agent death and one-agent partition exercised actual broker and audit recovery; transport-only actuator state remains unknown. Modeled T6 journal recovery required a current cut and retained the withdrawal. The all-agent five-second gate remains open. |

## Pre-observation enforcement follow-up

**FAIL for native ownership loss and the 4E-B marker target.** At the tested integrated pin, the native HTTP serving path denied access before the hold was durable. A monitored ownership loss reached its first health probe before committing quarantine. At the exact B pin the observer's first `/read` itself persisted the hold, while the untouched target resumed observing after its anchor returned. The native Evidence-loss control passed the narrower ordering test. [Exact pins, repeat trials and raw timing](phase4e-observer-order.md)

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
  tests/phase4e/test_defensive_validation.py -k 'not T6_' --junitxml="$scratch/local-baseline.xml" --tb=short

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

Extract the exact integrated source into a temporary directory. The native writer uses the legacy delivery profile. The loopback broker tests opt into the priority profile. The identity observer uses the provisioner from the candidate's identity test package, with separately implemented TLS HTTP and read-only SQL oracles.

```sh
AEGIS_4E_CANDIDATE=4918dadacc8dedd96d1c4b506e5f746040a01941
candidate="$scratch/candidate"
mkdir "$candidate"
git merge-base --is-ancestor ae59a97becfdbf9fb79c7cc89c0a27c662fb9a9f "$AEGIS_4E_CANDIDATE"
git archive "$AEGIS_4E_CANDIDATE" | tar -x -C "$candidate"
git rev-parse "$AEGIS_4E_CANDIDATE^{commit}"
cp "$harness/tests/phase4e/identity_observer.py" "$candidate/tests/identity_lab/test_independent_observer.py"

export PYTHONPATH="$candidate/src:$candidate/tests/phase4d:$candidate/scripts:$candidate"
(
  cd "$candidate"
  export AEGIS_PHASE4E_LIVE=1 AEGIS_PHASE4E_TOPOLOGY=loopback
  AEGIS_PHASE4E_PRIORITY=0 "$python" -m pytest -q -ra -o junit_family=legacy -p no:cacheprovider \
    "$harness/tests/phase4e/test_defensive_validation.py" tests/identity_lab/test_independent_observer.py \
    "$harness/tests/phase4e/trust_observer.py" --junitxml="$scratch/integrated-authority.xml" --tb=short
  AEGIS_PHASE4E_PRIORITY=1 "$python" -m pytest -q -ra -o junit_family=legacy -p no:cacheprovider \
    "$harness/tests/phase4e/test_withdrawal_delivery.py" --junitxml="$scratch/integrated-delivery.xml" --tb=short
)
```

Expect the strict single-witness assertion to fail at the named pin, with the quorum and native T6 guard cases passing. For the older shared-writer control, export `16e71ed1ccaf96209054fa3e5ddd03dd6e24b273` and run only `test_defensive_validation.py` with priority off. For the earlier A pins, run the priority cap test on `6e8bedccb184f3b4268670c93bc22310234c4f5e` and the crash test on `4c6f674c1915ee255222f02c38c2e2c010421b1f`. For B, export `cb7986d1abb7491e73f5ce53bb01778ba7159d94` and copy and run only the identity observer. For C, export `f1692340b03521d44877b6ba4a2799db66a4576d` and run only the Trust observer. Artifacts retain the exact cases and the earlier diagnostic failures.

Run the restored-home observer on the combined pin with the durable B quarantine latch. Run only the barrier observer on the earlier B pin. To reproduce the receipt contract check, export `c1e5702202ad317396856ee4af89590e14a57a16` and select `tests/phase4d/test_journal.py::test_native_receipt_binds_reencoded_transport_envelope_before_inclusion` with the source on `PYTHONPATH`.

Repeat the inherited Evidence conflict controls on the combined source with priority off.

```sh
(
  cd "$candidate"
  AEGIS_PHASE4E_PRIORITY=0 "$python" -m pytest -q -ra -o junit_family=legacy -p no:cacheprovider \
    tests/test_phase3c_pipeline.py::test_contradiction_invalidates_exact_plan_even_with_cached_positive \
    tests/phase4d_t5/test_independent_status.py::test_durable_floor_rejects_older_and_conflicting_certified_views \
    --junitxml="$scratch/inherited-evidence-conflict.xml" --tb=short
)
```

The inherited Docker suite requires a real Git checkout because the Phase 4A workload records the exact source identity.

```sh
git clone --local --shared --no-checkout "$repo" "$scratch/live-source"
git -C "$scratch/live-source" checkout --detach "$AEGIS_4E_CANDIDATE"
(
  cd "$scratch/live-source"
  export PYTHONPATH="$PWD/src" AEGIS_PHASE4A_LIVE=1 AEGIS_PHASE4D_LIVE=1 AEGIS_PHASE4D_T3_LIVE=1
  AEGIS_PHASE4E_PRIORITY=0 "$python" -m pytest -q -ra -o junit_family=legacy -p no:cacheprovider \
    tests/test_phase4a_distributed.py::test_live_distinct_processes_and_fault_recovery \
    tests/phase4d/test_journal.py::test_live_broker_loss_and_replacement_reconcile_with_independent_archive \
    tests/phase4d/test_ownership.py::test_live_independent_jetstream_leases_cannot_override_home \
    --basetemp="$scratch/inherited-state" --junitxml="$scratch/inherited-docker.xml" --tb=short
)
```

Keep enforcement limited to disposable labs and shadow work. Distributed acceptance requires an actual A/B/C writer binding, independent proof, broker generation and ACK fencing, authenticated independent failure domains, and a fulfilled all-agent withdrawal reporting bound.

### Reproduce the C shadow comparison

```sh
shadow="$scratch/shadow-v2"
mkdir "$shadow"
git archive f7053de6f059535e631cbca9544cd2ee57b2ed48 | tar -x -C "$shadow"
(
  cd "$shadow"
  export PYTHONPATH="$PWD/src:$PWD"
  for profile in checkpoint-v1 withdrawal-v2; do
    AEGIS_4ED_STATUS_PROFILE="$profile" "$python" -m pytest -q -ra -o junit_family=legacy -p no:cacheprovider \
      "$harness/tests/phase4e/trust_observer.py::test_W03_single_direct_admission_does_not_leave_positive_appraisal" \
      --junitxml="$scratch/$profile.xml" --tb=short
  done
  AEGIS_4ED_STATUS_PROFILE=withdrawal-v2 "$python" -m pytest -q -ra -o junit_family=legacy -p no:cacheprovider \
    "$harness/tests/phase4e/trust_observer.py::test_W03_v2_scope_freshness_and_restore" \
    --junitxml="$scratch/withdrawal-v2-faults.xml" --tb=short
)
```

The matched v1 assertion exits 1. Both opt-in cases pass. The separate authority probes run against disposable private Unix sockets and leave native T4/T5 on the actual shared writer.

To repeat the combined import checks, export `86d2454bb9132642ce0b05fda0c7cd681c8f065f`, run the two selectors above with `AEGIS_4ED_STATUS_PROFILE=withdrawal-v2`, and rerun `test_defensive_validation.py` with priority off and `src:tests/phase4d:scripts` on `PYTHONPATH`.

At `f7053de`, the publisher and the relying reader each refresh four direct views for the same nonce. The relying reader compares the publisher's signed status body to its own appraisal. A difference affecting the exact subject's outcome, reason, validity, or attestation set holds. Different unrelated records can yield identical status bodies because that body does not commit to the full collection of view receipts. Each reader retains its own verified receipts even when another lane is missing.

The shadow authorization lock and final status check cover local anchors and deadlines. A withdrawal arriving after the remote witness samples its view is a separate concurrency window. A local commit check has no fresh proof of subsequent remote intake unless that receipt has reached its relying anchor. The independent run exercised prior admission, lost view, stale replay, and restore. Concurrent remote admission and commit remain separate release evidence.

The post-read deadline is also a separate condition. At this pin, `Publisher.publish`, `Gate._refresh`, and `Gate.require_current` sample time before final potentially blocking anchor reads. The returned status or entered authorization can therefore be past the already sampled deadline. This branch records the source finding without claiming an observed target effect.
