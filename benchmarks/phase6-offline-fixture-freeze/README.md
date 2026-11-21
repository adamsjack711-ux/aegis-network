# Phase 6 offline advisory triage fixture freeze

Use source `50ba781` with the fixed clock 2026-11-20T00:00:00Z. The manifest references existing sealed inputs and labels by their full Git pins and SHA-256. Per-case hashes cover sorted compact JSON with no trailing newline. The five lifecycle inputs have seven revision steps. The sixth control is a malformed scripted response assessed directly by the Investigator.

**Entry point.** In a disposable local database, ingest the supplied snapshot through `ThreatScout.ingest`. Pass the emitted sequence, fixture vulnerability ID, asset, and exact `ScriptedProvider` response to `OfflineHandoff.consume`. After each commit, call `read_history(path, "osv", advisory_id)` on a fresh connection. For the malformed control use the pinned test's `sample(0)` and `investigate` call. The provider is scripted throughout.

| Score | Rule |
| --- | --- |
| Structured metadata | For each newly committed revision, compare the deterministic outcome to the independently frozen label. Count once per origin. An unknown label on ambiguous identity is a correct abstention. |
| Reportable outcome | Compare the emitted candidate field against the expected reportable value separately. For m82 the metadata excludes the version, the provider says affected, and the reportable value must be unknown. Score that as a correct guard and a miss if measuring reportable agreement with the structured label. Malformed input must produce rejected/unknown and zero accepted excerpts. |
| Semantic support | Resolve each expected pointer against the original bytes and verify digest, ecosystem/package and version relation. Require exact pointer sets, including the empty set for ambiguity. Excerpt byte alignment alone earns no support credit. The m82 quotation refers to a separate inventory. Report independent narrative entailment as unscored until a reviewer supplies separate labels. |
| Lifecycle | Match each receipt and the complete ordered history, including status, originating revision digest and its saved payload. Revisions may supersede earlier rows. Withdrawal must hold the new result and preserve the original payload as withdrawn. A held or missing step stays in the denominator. |

**Evidence boundary.** The existing raw output was captured on 39d580a. The Investigator, Scout, baseline and models are identical at 50ba781. The intervening handoff change extracted the history query and formatter and added the read-only entry point and open-error diagnostic. The pinned 50ba781 regression records the direct malformed-result control. This freeze reconciled gold, stored outputs, source digests, pointer sets and historical payloads. It did not run the seven-step wiring on 50ba781. [Exact inputs, expected outputs and evidence hashes](manifest.json)

**Tomorrow.** The integration owner must replay all seven steps through the normal source-pin API and retain separate scores and fresh-reader observations. VAL must independently inspect pointer meaning, reconcile missing or extra rows, and adjudicate any narrative-support claim. Stop wiring at the first unsupported current affected finding, including a withdrawn row presented as current. These scripted cases measure metadata triage and failure handling. Live-provider accuracy remains unmeasured.

## Run the pinned replay locally

Use a checkout of the replay candidate with the manifest's Git objects available.
The following macOS host commands use the reviewed local Linux arm64 image and
the approved `aegis-tester-50ba781-recipient.tar.gz` as an offline dependency
source. Set `bundle` to the local archive path. The replay needs only Pydantic
and its dependencies from the approved wheelhouse. The source code comes from
Git. The staging directory under the host home must be shared with the local
Docker VM.

```sh
set -eu
candidate=$(git rev-parse HEAD)
source=50ba7818b2a143a7ff4308e6b96c94dc322b9b03
image=sha256:6d620701a04f97b737f115f6e750d1fc3b8084d56acd801decfe781893c7443d
base=benchmarks/phase6-offline-fixture-freeze
bundle=/absolute/path/to/aegis-tester-50ba781-recipient.tar.gz
stage=$(mktemp -d "$HOME/.aegis-phase6-replay.XXXXXX")
printf 'Local evidence directory %s\n' "$stage"

printf 'd4745deb7eb9524092f42a430eaa32682d3b18d4c93af6d0dae7f25076bd306c  %s\n' "$bundle" |
    shasum -a 256 -c
git diff --exit-code "$source" "$candidate" -- src tests pyproject.toml
mkdir "$stage/input" "$stage/input/artifacts" "$stage/dependencies"
git archive "$candidate" src "$base/manifest.json" "$base/replay.py" |
    tar -xf - -C "$stage/input"
jq -r '.artifacts | to_entries[] | [.key,.value.commit,.value.path] | @tsv' \
    "$stage/input/$base/manifest.json" > "$stage/artifacts.tsv"
while IFS="$(printf '\t')" read -r key pin path; do
    git show "$pin:$path" > "$stage/input/artifacts/$key"
done < "$stage/artifacts.tsv"
tar -xzf "$bundle" -C "$stage/dependencies"
printf '%s\n' "$candidate" > "$stage/candidate.txt"

docker run --rm --pull=never --platform linux/arm64 --network none \
    --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges \
    --read-only --tmpfs /tmp:rw,exec,nosuid,nodev,mode=1777 --workdir /tmp \
    --mount "type=bind,src=$stage/input,dst=/input,readonly" \
    --mount "type=bind,src=$stage/dependencies/aegis-tester-50ba781-recipient/wheels,dst=/wheels,readonly" \
    --env HOME=/tmp "$image" sh -ec '
        python3.12 -Im venv /tmp/venv
        /tmp/venv/bin/python -Im pip --isolated install --disable-pip-version-check \
            --no-index --find-links /wheels pydantic==2.14.4 >&2
        /tmp/venv/bin/python -Im pip --isolated check >&2
        export PYTHONPATH=/input/src
        /tmp/venv/bin/python -B - <<PYENV
import os, platform, sys
from pathlib import Path
import aegis.intelligence.handoff as handoff
assert Path(handoff.__file__).resolve().is_relative_to(Path("/input/src"))
assert os.getuid() == 65534
print(platform.platform(), platform.python_version(), os.getuid(), file=sys.stderr)
PYENV
        exec /tmp/venv/bin/python -B /input/benchmarks/phase6-offline-fixture-freeze/replay.py /input/artifacts
    ' > "$stage/replay.json" 2> "$stage/environment.log"
shasum -a 256 "$stage/replay.json"
```

Expect `fixture_comparison=matched`, seven matched steps with six commits and
one held withdrawal, and one matched malformed response. Output contains the
complete emitted events, receipts and fresh histories. The harness compares
saved rows against the frozen reference except for measured latency, and
checks that rows observed again in the same database preserve their payload
including original latency. A mismatch exits nonzero, retains the observations
already taken and marks later steps `not-run`. Each case database is disposable.

The comparison checks exact excerpt bytes and structured reference bindings;
independent adjudication of package and version meaning, narrative entailment,
and observation of attempted effects are separate review steps. The guest is
isolated from the network. Independent tracing is required to measure attempts.
