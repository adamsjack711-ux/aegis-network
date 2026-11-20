"""Disposable Linux explicit-state symlink and permission check."""

import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from uuid import UUID

from aegis.local_observer import ObservationError, asset_identity


with TemporaryDirectory(prefix="aegis-linux-state-") as temporary:
    root = Path(temporary)
    outside = root / "outside"
    outside.mkdir()
    alias = root / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    cases = {}
    for name, path in (("ancestor", alias / "aegis"), ("final", alias)):
        try:
            asset_identity(path)
        except ObservationError as exc:
            cases[name] = {"rejected": True, "error": str(exc)}
        else:
            cases[name] = {"rejected": False}
    cases["outside_unchanged"] = not (outside / "aegis").exists() and not (outside / "identity.json").exists()
    chosen = root / "chosen"
    first = asset_identity(chosen)
    second = asset_identity(chosen)
    cases["explicit"] = {"stable_uuid4": first == second and UUID(first).version == 4,
                         "dir_mode": oct(stat.S_IMODE(os.stat(chosen).st_mode)),
                         "file_mode": oct(stat.S_IMODE(os.stat(chosen / "identity.json").st_mode)),
                         "files": sorted(p.name for p in chosen.iterdir())}
print(json.dumps(cases, sort_keys=True, indent=2))
