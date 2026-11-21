# Aegis Network

## The problem

A security alert says a certain version of a software package has a flaw. If you manage several computers, it takes time to check which ones have that version and whether the alert came from a source you trust.

## What Aegis does

Aegis checks the alert's digital signature and compares the affected package versions with what's installed on a Debian or Ubuntu machine. It works offline and keeps the package list on the machine.

An exact match tells you where to look first. This early preview is for lab use. It reports what it finds and leaves any fixes to you.

## Try it

In a lab running Debian or Ubuntu with Python 3.12 or newer, run these commands from the repo folder.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
PYTHONPATH=src python -B -m aegis.cli inventory
```

See the [CLI guide](docs/phase5b-linux-cli.md) to check your inventory against a signed alert file. For more about the project design, see the [architecture](architecture.md).
