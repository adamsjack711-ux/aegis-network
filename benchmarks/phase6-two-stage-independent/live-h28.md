# Independent score for the two h28 probes

**Both probes met their preselected expectations.** Original h28 was selected at `18593d963efb7652d49ddfb6d52a85c5e6e03b71` from the independently frozen corpus `46b5566`. Each stage has one live observation. No other provider result contributed to either score.

| Probe | Frozen expectation | Observed score | Provider-reported tokens, input / output |
|---|---|---|---|
| A, identity only | Select exactly the PyPI dunefinch-loom row among the three candidates | Complete set 1/1 at /affected/1, zero extras or omissions | 309 / 37 |
| B, independent identity admission | At 5.1.0 the package is affected because the introduced boundary is inclusive | Decision 1/1, pointer precision 1/1 and support coverage 1/1 | 249 / 44 |

The B citation is the original 140-byte interval [90, 230) in the frozen source, SHA-256 `81f9150c58f408a6768de70bde9de09d1098c9c2741b008614708d132f2517d5`. That row defines [5.1.0, 5.3.0). Both probes returned HTTP 200 and each local marker records attempt 1. Replay at `703d32413bfd6da4877a4de3b4a892a339dec042` matched the retained native draft, response hash, stage verdict, token usage and local request digest for each arm. The attempt markers and wire files establish local provenance; neither response independently attests to the request digest.

Using A's actual returned draft, the offline-linked B request was byte-identical to the live oracle B request, SHA-256 `eddb187063fe829896d45323bd8329e73f7a7a8bd01550ff099c5585d7ee8536`. There was no third live probe. The two observations establish success on this one introduced-boundary case. The earlier combined s43 abstention remains unattributed.

**Next discriminating case:** original h53 tests exclusion exactly at a fixed boundary, again with a same-name ecosystem decoy and a different-package decoy. Running A and independent oracle B would distinguish identity selection from interpretation of that opposite boundary. This is a recommendation only. [Frozen scoring and observation details](live-h28.json)
