# Aegis Network

**A security alert just landed. Which machines need a closer look?**

![A signed alert next to three Linux terminals, with one highlighted](docs/assets/aegis-banner.webp)

Say an alert flags version `2.4.1` of a package. Checking who sent the alert and which machines run that version takes time. Aegis does both checks on Debian and Ubuntu.

1. **Check the alert.** Aegis checks that a trusted publisher signed it.
2. **Look for a match.** It looks for the exact package and version on the machine.

> [!NOTE]
> Aegis runs offline and keeps your package list on the machine. This lab preview reports matches and leaves any fixes to you.

## Try it in a lab

On Debian or Ubuntu with Python 3.12 or newer, run this from the repo folder to list your installed packages.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
PYTHONPATH=src python -B -m aegis.cli inventory
```

The [CLI guide](docs/phase5b-linux-cli.md) shows how to check a signed alert file. The [architecture notes](architecture.md) explain how the larger project fits together.
