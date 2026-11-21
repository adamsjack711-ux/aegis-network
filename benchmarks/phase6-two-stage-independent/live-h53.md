# Independent h53 fixed-boundary replay

Both saved replies passed the preselection at f0c63303b301fd847019d9e3c503ad5b543a0a28 for the original h53 case in seal 46b55669f9534e6307260c98c245bf7f62734227. The independent replay used 703d32413bfd6da4877a4de3b4a892a339dec042 with the sealed source and target. The h53 bridge at daf170ccf935e691a0d2ff5d513a2a43c0c185e2 separately reproduced both request bodies and both complete transport records. Both reviewer runs denied network access.

| Stage | Native decision and source check | Score | Input / output tokens |
|---|---|---|---|
| A, identity | Matched only npm bogfirth-plume at /affected/2. Both decoys excluded. | Complete sets 1/1 | 299 / 35 |
| B, oracle admission | Unaffected. Target 2.7.0 equals the exclusive fixed endpoint of the range starting at 2.1.0. | Decisions 1/1, pointer precision 1/1, reference coverage 1/1 | 245 / 38 |

B emitted the frozen row ID. The checker resolved it to /affected/2, source bytes [167,303), SHA-256 7f1499f6f87a580ad33b294767274c6c687f050509974bdee67a7629c4f7e756. The returned row matched the sealed source slice exactly. Neither arm abstained. Using the actual A draft to construct linked B offline produced the identical 1320-byte oracle B wire. Only oracle B had a recorded live attempt.

| Stage | Request bytes | Request SHA-256 | Saved native response SHA-256 |
|---|---:|---|---|
| A | 1449 | bcd7a58962ec8aebdb0e6cbf1012e8edc9f501158252a414cbd56833426ee375 | 75a68b6a9d754cd3b48e83a20c82d68cde04eed08c0978649ae88bf8ead3f378 |
| B | 1320 | 6d3e172a61c815be80f6f7118d835d451b5e0981301ac1eb4232370603298924 | e39e233e95e07d587116de305cb41d8a705419dc15b425254e2f37789aa86dd7 |

Each local attempt marker recorded attempt 1 and the reproduced body digest. Both HTTP records reported 200. Each completed native response matched the transport model, usage, draft hash and response hash. Fresh checker outputs matched the saved transport checks. Request provenance rests on retained local records. The result covers one preselected synthetic case.
