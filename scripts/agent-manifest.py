#!/usr/bin/env python3
"""Writes agent.json, the manifest agents read to update themselves, for the agent exes in a
folder of release files.

    scripts/agent-manifest.py <dist-dir> <version>

Each architecture's agent is `groundhog-agent-<arch>.exe`; any that's present is listed with
its SHA-256. `groundhog mirror-agent` copies exactly these files, and any folder holding them
works as an update source.
"""
import hashlib
import json
import pathlib
import sys

ARCHES = ["x64", "arm64"]


def main() -> int:
    dist, version = pathlib.Path(sys.argv[1]), sys.argv[2].removeprefix("v")
    agents = {}
    for arch in ARCHES:
        exe = dist / f"groundhog-agent-{arch}.exe"
        if exe.is_file():
            agents[arch] = {"file": exe.name, "sha256": hashlib.sha256(exe.read_bytes()).hexdigest()}
    if not agents:
        print(f"no groundhog-agent-<arch>.exe files in {dist}", file=sys.stderr)
        return 1
    manifest = {"version": version, "agents": agents}
    (dist / "agent.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
