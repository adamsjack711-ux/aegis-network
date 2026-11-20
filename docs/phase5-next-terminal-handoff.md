# Phase 5 next VAL terminal handoff

Branch `test/phase5-next-validation`; worktree `.worktrees/phase5-next-validation`; baseline `8292e531194216a578c32c912d066f98cdbce9ea`. Acceptance was committed first at `68f9fd8fc84e8d92673c43ad20e3230a714ddac2`. The main checkout, implementation branches and master were untouched. [Freeze](phase5-next-acceptance-freeze.md) and [results](phase5-next-validation-results.md) are the review entry points; raw outputs and independent checks are under `benchmarks/phase5-next-validation/`.

To reproduce the research byte/label audit from this worktree:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src ../../.venv/bin/python scripts/phase5a1_evaluate.py --output /private/tmp/aegis-phase5-next-5a1.json
python3 scripts/phase5_next_validate_research.py /private/tmp/aegis-phase5-next-5a1.json /private/tmp/aegis-phase5-next-research-check.json
```

The evaluator records its exact Git source pin and requires a clean worktree, so rerunning after this results commit will record a new validation commit and produce a new raw digest. Compare case outcomes and denominators, not timestamp-dependent file hashes. The retained raw run was made before results files were added. The focused pytest command and Linux release preflight command are in the results report. The latter deliberately stops before install without a reviewed wheelhouse.

Next review needs an independently supplied, hashed offline wheelhouse and Ubuntu/Python 3.13 image for the four installed CLI cells; an enrolled model, export scope and actual billing oracle for real-model evaluation; and a concrete pinned Diagnostic Runner implementation with OS containment before any safety trial. Native and distributed enforcement require their separate frozen matrix and independent custody proof. Preserve all original failed raw artifacts and first failed attempts when successors are tested.
