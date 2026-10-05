#!/usr/bin/env python3
"""Writes the winget manifests for a release, for submitting to microsoft/winget-pkgs.

    scripts/winget-manifest.py <dist-dir> <version> <out-dir>

<dist-dir> holds the release's groundhog-agent-<arch>.exe files (their SHA-256 goes into the
manifest); the manifests go to <out-dir>/manifests/g/GusCatalano/Groundhog/<version>/, the
layout winget-pkgs uses. The package installs groundhog-agent as a portable command, so
`winget install GusCatalano.Groundhog` puts `groundhog-agent` on the PATH.
"""
import datetime
import hashlib
import pathlib
import sys

ID = "GusCatalano.Groundhog"
REPO = "https://github.com/guscatalano/Groundhog"
SCHEMA = "1.12.0"
ARCHES = ["x64", "arm64"]

HEADER = "# yaml-language-server: $schema=https://aka.ms/winget-manifest.{kind}.{schema}.schema.json\n\n"


def main() -> int:
    dist, version, out = pathlib.Path(sys.argv[1]), sys.argv[2].removeprefix("v"), pathlib.Path(sys.argv[3])
    folder = out / "manifests" / "g" / "GusCatalano" / "Groundhog" / version
    folder.mkdir(parents=True, exist_ok=True)

    installers = []
    for arch in ARCHES:
        exe = dist / f"groundhog-agent-{arch}.exe"
        if not exe.is_file():
            print(f"missing {exe}", file=sys.stderr)
            return 1
        sha = hashlib.sha256(exe.read_bytes()).hexdigest().upper()
        installers.append(
            f"- Architecture: {arch}\n"
            f"  InstallerUrl: {REPO}/releases/download/v{version}/{exe.name}\n"
            f"  InstallerSha256: {sha}\n"
        )

    (folder / f"{ID}.yaml").write_text(
        HEADER.format(kind="version", schema=SCHEMA)
        + f"PackageIdentifier: {ID}\nPackageVersion: {version}\nDefaultLocale: en-US\n"
        + f"ManifestType: version\nManifestVersion: {SCHEMA}\n",
        encoding="utf-8",
    )
    (folder / f"{ID}.installer.yaml").write_text(
        HEADER.format(kind="installer", schema=SCHEMA)
        + f"PackageIdentifier: {ID}\nPackageVersion: {version}\n"
        + "InstallerType: portable\nCommands:\n- groundhog-agent\n"
        + f"ReleaseDate: {datetime.date.today().isoformat()}\n"
        + "Installers:\n" + "".join(installers)
        + f"ManifestType: installer\nManifestVersion: {SCHEMA}\n",
        encoding="utf-8",
    )
    (folder / f"{ID}.locale.en-US.yaml").write_text(
        HEADER.format(kind="defaultLocale", schema=SCHEMA)
        + f"PackageIdentifier: {ID}\nPackageVersion: {version}\nPackageLocale: en-US\n"
        + "Publisher: Gus Catalano\nPublisherUrl: https://github.com/guscatalano\n"
        + f"PublisherSupportUrl: {REPO}/issues\n"
        + f"PackageName: Groundhog\nPackageUrl: {REPO}\n"
        + f"License: MIT\nLicenseUrl: {REPO}/blob/main/LICENSE\n"
        + "ShortDescription: Brings a fresh Windows machine to a known state from one declarative file.\n"
        + "Description: |-\n"
        + "  Groundhog applies a Groundhogfile (YAML or JSON) to the machine it runs on: apps, files,\n"
        + "  environment, registry, Windows features, users, certificates, services, firewall rules,\n"
        + "  desktop settings and custom steps. It resumes after restarts, runs only what changed, and\n"
        + "  can preview what an apply would do. Meant for VM templates, sandboxes and dev machines.\n"
        + "Moniker: groundhog\nTags:\n- configuration\n- provisioning\n- automation\n- devbox\n- vm\n"
        + f"ReleaseNotesUrl: {REPO}/releases/tag/v{version}\n"
        + f"Documentations:\n- DocumentLabel: Groundhogfile reference\n  DocumentUrl: {REPO}/blob/main/docs/groundhogfile.md\n"
        + f"ManifestType: defaultLocale\nManifestVersion: {SCHEMA}\n",
        encoding="utf-8",
    )
    print(folder)
    return 0


if __name__ == "__main__":
    sys.exit(main())
