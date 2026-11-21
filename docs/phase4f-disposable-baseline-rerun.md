# Phase 4F five-second gate and disposable baseline rerun

**Release decision remains NO-GO.** This pins the existing release oracle and a two-trial diagnostic for the retained baseline. The diagnostic has a smaller denominator and measures Mesh dry-run denial on one host. Release requires the full native-evidence matrix and independent custody. [Frozen release oracle](phase-next-six-validation-freeze.md#gate-4f--withdrawal-recovery-and-protected-writer) · [Recovery decision](phase4f-recovery-resolution.md)

## Frozen acceptance

- The unit is each enrolled agent and valid scoped withdrawal pair. Both witnessed submission to independently read agent-owned durable denial and witnessed durable admission to that same denial must have conservative upper bounds of **5,000 ms or less** for every eligible pair. Keep the original timestamps through restart. An independent read-only SQLite observer verifies exact signed source bytes, native T4/T5 proof, local inventory and policy, a single logical `revocation_decisions` denial and the exact `revoked_targets` tombstone. Use the first-present observation as the upper bound with clock uncertainty included.
- Count **72 fault pairs** from three eligible agents, two withdrawals, three fresh repeats and four fault arms. The arms are pre-intake process kill plus broker restart, broker/network partition and rejoin, denial committed before lost ACK/replay, and stale owner versus successor. Each fault run has **1,000 ordinary pending findings**. Count **18 further pairs** in the healthy broker-restart controls with three agents, two withdrawals and three repeats.
- Crashed, disconnected or unobservable enrolled agents stay in the denominator. Record missed and censored pairs with their reason. Track target holds, broker ACKs, replay cursors and witness receipts separately from agent-owned SQLite denial. Closure requires every pair, zero false accepted denials, lost obligations, unauthorized positive writes, stale-generation wins or target reopenings, and the multi-host identity, witness and rollback custody in the frozen release contract.

The retained independent SQLite observer still found both exact denials absent **30,559.741 ms after broker restart**, after the coordinator had durably admitted the withdrawals. They were first present at **30,585.717 ms**. The separate pre-intake baseline missed **6/6** pre-intake crash pairs at about **30.59–30.69 s**. The reproduced dominant local delay was the retained 30-second KV lease. The later 1,000-backlog diagnostic also missed at **12,613.289 and 12,599.589 ms**. The full **72 + 18** release matrix remains unrun. [Retained recovery evidence](phase4f-recovery-resolution.md#retained-evidence-and-what-it-proves) · [Independent baseline](phase-next-r-external-handoff-review.md) · [1,000-backlog diagnostic](phase-next-six-findings-register.md)

## Minimum paired baseline rerun

Use the original trace-and-review source `2fa7321618fc5e7435b339ffa9368de258198d21` in a clean detached checkout, with the same harness and images. This is the smallest matched comparison the existing harness supports. Run one fresh pre-intake SIGKILL plus NATS restart, then one fresh broker restart with the worker alive. Each trial uses one enrolled dry-run agent, two scoped withdrawals, four dedicated ordinary findings and the same two additional mixed-publisher findings. The denominator is two fault pairs and two healthy pairs, with a new disposable Compose project and temporary state for each invocation. Its prior results were 30,589.201 and 30,576.431 ms in the fault, and 1,767.656 and 1,753.683 ms with the worker alive. [Independent test review](phase-next-remediation-candidate-review.md#4f-withdrawal-recovery-diagnosis)

| Pin | SHA-256 |
| --- | --- |
| `scripts/phase4e_withdrawal_recovery_check.py` | `82f0fc0edec09a220f1976d0ab810f4f9b98115039217acb3e35ca77811a8050` |
| `scripts/phase4a_bench.py` | `4a3d9887134caac0b89826969f553b285022ca12af905fe84a228cf263e21f2a` |
| `compose.phase4a.yaml` | `264439f222a46bc154ec192a08e474e67785d20588541c888cda7ecffd25c9d6` |
| Cached `nats:2.10-alpine` image ID | `b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927` |
| Cached `postgres:16-alpine` image ID | `1d5b02d3a9941fbd52437db4107f8c52d6297dac553ca1e5c299ebb3756b4857` |
| [Prior fault JSON](../benchmarks/phase-next-remediation/4f-sigkill-fault.json) | `19d7bbcccb69ad7238fd93588e04634c8e02c08528b437d8eb703dea20fee17d` |
| [Prior healthy JSON](../benchmarks/phase-next-remediation/4f-broker-control.json) | `bec42e65ee8876db7926eff65a10832c51b0c328a56ca0d630cf7100f96444c1` |
| [Retained recovery trace](../benchmarks/phase4f-kv-recovery/baseline-sigkill.json) | `8cc699a8d7a478f0ed789cef40ac84a402526349636ce833e393833b51eda95f` |

From that checkout with the reviewed Python dependencies, an available local Docker Unix socket and both cached image IDs confirmed, use a new output directory outside the checkout. The harness binds published ports to loopback, uses synthetic fixture keys and starts Compose with `--pull never`.

```sh
export PYTHONDONTWRITEBYTECODE=1
diagnostic_dir=$(mktemp -d)
python scripts/phase4e_withdrawal_recovery_check.py . --authorize-local-lab \
  --ordinary-count 4 --priority --kill-agent --output "$diagnostic_dir/fault.json"
python scripts/phase4e_withdrawal_recovery_check.py . --authorize-local-lab \
  --ordinary-count 4 --priority --output "$diagnostic_dir/healthy.json"
```

Check both withdrawals individually against their original target IDs, the independent read-only denial set, and the original submission timestamp. Retain raw JSON under new names and record the OS, Python and image IDs, the original journal admission and relevant KV claim, broker, audit and ACK stages separately. The diagnostic reports submit-to-audit and restart-to-audit timings. It lacks an independent native admission timestamp and a first-present read-only polling bound, so it cannot close either release acceptance path. A harness exit of zero confirms its assertions and eventual readback. Deadline scoring is separate.

The rerun was **not executed** during this plan review. The configured local Docker socket was unavailable. Historical evidence and the release NO-GO remain in force.
