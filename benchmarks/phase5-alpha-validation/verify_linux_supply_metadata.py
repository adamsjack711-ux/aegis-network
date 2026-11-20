"""Read-only official JSON metadata verification; no binary download."""
import hashlib
import json
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

OWNER = Path(__file__).resolve().parents[3] / "linux-alpha-supply-prep"
OUT = Path(__file__).with_name("linux-supply-prep-official-metadata.json")

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise RuntimeError("redirect not permitted")

opener = build_opener(ProxyHandler({}), NoRedirect())

def metadata(url, host):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname != host or parts.username or parts.password:
        raise ValueError("unapproved metadata destination")
    with opener.open(Request(url, headers={"User-Agent": "Aegis-independent-supply-review/1.0", "Accept": "application/json"}), timeout=10) as response:
        if response.status != 200 or urlsplit(response.url).hostname != host:
            raise ValueError("unexpected metadata origin")
        raw = response.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("metadata too large")
    return json.loads(raw)

manifest = (OWNER / "supply-prep/manifest.json").read_bytes()
provenance = (OWNER / "supply-prep/provenance.json").read_bytes()
releases = {}
wheels = []
for item in json.loads(provenance)["wheels"]:
    key = (item["distribution"], item["version"])
    if key not in releases:
        url = "https://pypi.org/pypi/" + quote(key[0], safe="") + "/" + quote(key[1], safe="") + "/json"
        releases[key] = metadata(url, "pypi.org")
    matches = [x for x in releases[key]["urls"] if x["filename"] == item["file"]]
    wheels.append({"file": item["file"], "exact_one": len(matches) == 1,
                   "digest_matches": len(matches) == 1 and matches[0]["digests"]["sha256"] == item["sha256"],
                   "url_matches": len(matches) == 1 and matches[0]["url"] == item["source"]})
assets = []
for item in json.loads((OWNER / "supply-prep/cpython.json").read_text()):
    data = metadata("https://api.github.com/repos/astral-sh/python-build-standalone/releases/assets/" + str(item["asset_id"]), "api.github.com")
    assets.append({"asset_id": item["asset_id"], "name_matches": data.get("name") == item["name"],
                   "digest_matches": data.get("digest") == item["digest"],
                   "url_matches": data.get("browser_download_url") == item["url"],
                   "official_digest": data.get("digest")})
result = {"owner_commit": "777f4304a2c333be8527575c0b5963c0cf2acb94",
          "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
          "draft_provenance_sha256": hashlib.sha256(provenance).hexdigest(),
          "scope": "official JSON metadata only; no binary artifacts downloaded",
          "pypi_release_queries": len(releases), "wheels": wheels, "astral_assets": assets}
OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps({"pypi_release_queries": len(releases), "wheels": len(wheels),
                  "wheel_digest_matches": sum(x["digest_matches"] for x in wheels),
                  "wheel_url_matches": sum(x["url_matches"] for x in wheels),
                  "astral_assets": len(assets),
                  "astral_matches": sum(x["name_matches"] and x["digest_matches"] and x["url_matches"] for x in assets)}, sort_keys=True))
