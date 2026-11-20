# ALPHA-3 terminal handoff

Checkout: `.worktrees/alpha-cli-privacy`, branch `feat/alpha-cli-privacy`, base `29455087922a728a41936d8c5c79ff9942e1e3df`. No master merge.

From that worktree, reproduce the disposable image and evidence:

```sh
docker build -f scripts/alpha_cli_privacy/Dockerfile -t aegis-alpha-cli-privacy:local scripts/alpha_cli_privacy
python3 scripts/alpha_cli_privacy/run_resources.py > benchmarks/alpha-cli-privacy/raw/resource-run.log 2>&1
python3 scripts/alpha_cli_privacy/run_failures.py > benchmarks/alpha-cli-privacy/raw/failure-run.log 2>&1
python3 scripts/alpha_cli_privacy/run_traces.py > benchmarks/alpha-cli-privacy/raw/trace-run.log 2>&1
gzip -n -f benchmarks/alpha-cli-privacy/inputs/status-100 benchmarks/alpha-cli-privacy/inputs/status-10000 benchmarks/alpha-cli-privacy/inputs/status-100000
rm -r benchmarks/alpha-cli-privacy/state
python3 scripts/alpha_cli_privacy/write_manifest.py
```

`run_resources.py` recreates uncompressed dpkg inputs and compressed per-trial JSON stdout. `run_traces.py` creates a disposable `benchmarks/alpha-cli-privacy/state` directory with a random test identity; the cleanup command removes it after its tree metadata is recorded. Verify the committed evidence against [the SHA-256 manifest](../benchmarks/alpha-cli-privacy/sha256-manifest.json). The Dockerfile's base digest is pinned, but Debian/PyPI build packages are not an approved offline wheelhouse; record the new image digest if rebuilt.

Observed: 100,000 rows verified 6/6 at 512/256 MiB, maximum process RSS 105.88 MiB, no OOM; 12/12 default/failure traces had zero write and network syscall attempts. Explicit state creation was scoped. Invalid signatures and missing independent Evidence status remained unknown. Full installed-console, platform, and output-consumer gates remain open. Original 3/3 OOM evidence is retained separately at the baseline pin and must stay in the decision record.
