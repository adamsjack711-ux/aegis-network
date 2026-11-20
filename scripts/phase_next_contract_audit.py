"""Pin-aware static review of Phase 5 authority and network boundaries."""

import argparse
import ast
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess


CONTRACTS = ("src/aegis/artifact.py", "src/aegis/core.py")
FORBIDDEN_IMPORTS = ("aegis.mitigation", "aegis.phase3c", "aegis.ownership", "aegis.agent_runtime",
                     ".mitigation", ".phase3c", ".ownership", ".agent_runtime")
NETWORK_IMPORTS = ("socket", "urllib", "httpx", "requests", "aiohttp")


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root)


def inspect_source(root, relative):
    path = root / relative
    tree = ast.parse(path.read_text())
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append("." * node.level + (node.module or ""))
    text = path.read_text()
    forbidden = [name for name in FORBIDDEN_IMPORTS if name in text or any(name in item for item in imports)]
    network = [name for name in NETWORK_IMPORTS if any(item.startswith(name) for item in imports)]
    dynamic = [name for name in ("importlib", "subprocess", "eval(", "exec(", "__import__(") if name in text]
    return {"path": relative, "sha256": sha256(path.read_bytes()).hexdigest(),
            "imports": imports, "forbidden_authority_references": forbidden,
            "network_imports": network, "dynamic_execution_markers": dynamic}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--source-pin", required=True)
    parser.add_argument("--baseline-pin", default="ee739cacfaa3f81a0994b4d7802fd2943c067d86")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.candidate_root.resolve()
    actual = git(root, "rev-parse", "HEAD").decode().strip()
    if actual != args.source_pin or git(root, "status", "--porcelain").strip():
        raise ValueError("candidate source is not the requested clean exact pin")
    contracts = []
    for relative in CONTRACTS:
        current = (root / relative).read_bytes()
        baseline = git(root, "show", args.baseline_pin + ":" + relative)
        contracts.append({"path": relative, "candidate_sha256": sha256(current).hexdigest(),
                          "baseline_sha256": sha256(baseline).hexdigest(),
                          "unchanged": current == baseline})
    paths = [p.relative_to(root).as_posix() for p in (root / "src/aegis/intelligence").rglob("*.py")]
    paths += [p.relative_to(root).as_posix() for p in (root / "src/aegis").glob("*cli*.py")]
    paths += [p.relative_to(root).as_posix() for p in (root / "src/aegis").glob("*observer*.py")]
    paths += [p.relative_to(root).as_posix() for p in (root / "src/aegis").glob("*adapter*.py")]
    sources = [inspect_source(root, path) for path in sorted(set(paths))]
    result = {"at_utc": datetime.now(timezone.utc).isoformat(), "source_pin": actual,
              "baseline_pin": args.baseline_pin, "contracts": contracts, "sources": sources,
              "interpretation": "static triage only; runtime side-effect and provenance tests remain required"}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"contract_changes": sum(not row["unchanged"] for row in contracts),
                      "authority_references": sum(bool(row["forbidden_authority_references"]) for row in sources),
                      "network_imports": sum(bool(row["network_imports"]) for row in sources)}))


if __name__ == "__main__":
    main()
