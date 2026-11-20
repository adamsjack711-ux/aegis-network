"""Small, offline text baseline for the frozen VAL-D advisory input contract.

This deliberately abstains on Debian epochs, prereleases and absent evidence.
It reads the same asset and source bytes as any model arm. It does not sign or
publish a finding and is not a substitute for structured source authentication.
"""

import json
import re
import sys


def version_tuple(text):
    if not re.fullmatch(r"\d+(?:\.\d+){1,3}", text):
        return None
    return tuple(int(part) for part in text.split("."))


def decide(asset, sources):
    if not sources:
        return "unknown", "no-source"
    text = " ".join(row["text"] for row in sources).lower()
    eco = asset["ecosystem"].lower()
    name = asset["name"].lower()
    version = asset["version"].lower()
    if eco == "unknown" or eco == "deb" or "pre-release" in text and "not tested" in text:
        return "unknown", "unsupported-or-ambiguous-version"
    if "conflict" in text or "unresolved" in text:
        return "unknown", "source-conflict"
    if "no affected package" in text or "no claim is made" in text:
        return "unknown", "no-supported-claim"
    if "was withdrawn" in text and "test artifact" in text:
        return "unaffected", "withdrawn-test-artifact"
    if f"{eco} {name}" not in text:
        return "unknown", "identity-not-in-source"
    if f"{eco} {name} is a separate project" in text:
        return "unaffected", "separate-ecosystem"
    if f"{eco} {name} {version} is unaffected" in text:
        return "unaffected", "explicit-unaffected"
    if f"{eco} {name} {version} is affected" in text:
        return "affected", "explicit-affected"
    match = re.search(r"(?:versions? )?before (\d+(?:\.\d+){1,3})", text)
    if match and version_tuple(version) and version_tuple(match.group(1)):
        return ("affected" if version_tuple(version) < version_tuple(match.group(1)) else
                "unaffected"), "simple-before-boundary"
    match = re.search(r"(?:below|<) (\d+(?:\.\d+){1,3})", text)
    if match and version_tuple(version) and version_tuple(match.group(1)):
        return ("affected" if version_tuple(version) < version_tuple(match.group(1)) else
                "unaffected"), "simple-below-boundary"
    return "unknown", "not-parsed"


def main():
    item = json.load(sys.stdin)
    decision, reason = decide(item["asset"], item["sources"])
    citations = [row["id"] for row in item["sources"]]
    print(json.dumps({"decision": decision, "citations": citations,
                      "claims": [], "reason": reason}, sort_keys=True))


if __name__ == "__main__":
    main()
