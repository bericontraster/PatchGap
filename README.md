<p align="center">
  <img src="assets\patchgap.png" alt="PatchGap logo: a shield with a patch closing a gap" width="200" height="200">
</p>

# PatchGap

PatchGap helps administrators identify package updates on Linux systems and check installed package versions for known vulnerability advisories. It also supports disconnected systems: export a package inventory where there is no internet, transfer the file, and query that saved inventory from a connected machine.

## Table of contents

- [Overview](#overview)
- [Demo](#demo)
- [What PatchGap checks](#what-patchgap-checks)
- [Quick start](#quick-start)
- [Offline inventory and online CVE scan](#offline-inventory-and-online-cve-scan)
- [Commands](#commands)
- [Understanding results](#understanding-results)
- [Privacy and safety](#privacy-and-safety)
- [Scope and limitations](#scope-and-limitations)
- [Project files](#project-files)
- [License](#license)

## Overview

PatchGap is designed for a common Linux administration problem: the system that needs reviewing may not be allowed to access the internet. The tool separates local package discovery from online vulnerability lookups:

1. Read installed package versions and available updates from the system's package manager.
2. Optionally save the installed package inventory as a portable JSON file.
3. On an internet-connected machine, submit the saved package names and versions to OSV and review matching advisories.

PatchGap is an inventory and reporting tool. It does not install, upgrade, or remove software.

## Demo

<p align="center">
  <img src="assets/patchgap.gif" alt="PatchGap demo: scanning a saved package inventory, inspecting a package's CVE advisories, and manually researching a related public proof of concept" width="900">
</p>

<p align="center"><em>Export an offline inventory, scan it online, inspect a package's advisories, then follow up with manual CVE and public PoC research.</em></p>

The CVE search and proof-of-concept research shown are manual follow-up steps. PatchGap reports package versions and matching advisories; it does not search for exploits or validate PoCs.

## What PatchGap checks

| Check | Data source | Network required |
| --- | --- | --- |
| Available package updates | Local package-manager metadata | No, unless refreshing metadata |
| Installed package inventory | Local package database | No |
| Known advisories for outdated packages | OSV API | Yes |
| Known advisories for a transferred inventory | OSV API, using the source OS ecosystem saved in the inventory | Yes |

Supported package managers are APT, DNF, YUM, Pacman, Zypper, and APK. OSV ecosystem mappings currently include Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux, Red Hat Enterprise Linux, openSUSE, SUSE Linux Enterprise, and Wolfi.

## Quick start

Requirements: Linux and Python 3.9 or newer. PatchGap uses only the Python standard library.

```sh
chmod +x patchgap
./patchgap
```

To run the implementation directly without the shell launcher:

```sh
python3 patchgap.py
```

The launcher locates `patchgap.py` next to itself, so the two files should stay together.

## Offline inventory and online CVE scan

On the system to review, export its installed package names and versions. This works offline and does not refresh repositories:

```sh
./patchgap --export-inventory patchgap-inventory.json
```

Transfer `patchgap-inventory.json` to an internet-connected Linux machine with PatchGap, then check every recorded package version:

```sh
./patchgap --scan-inventory patchgap-inventory.json --online
```

The scan uses the source system's OS ecosystem recorded in the inventory; the connected machine's installed packages do not affect the scan.

Long advisory lists are shortened in the findings table to keep each row on one line. To browse the complete list for a package, add `--inspect`:

```sh
./patchgap --scan-inventory patchgap-inventory.json --online --inspect
```

Enter a package name or part of a name at the prompt. PatchGap shows matching packages, then displays advisory IDs in pages of 25.

## Commands

| Command | Purpose |
| --- | --- |
| `./patchgap` | Show locally available package updates using cached metadata; no network access |
| `./patchgap --online` | Check outdated local packages against OSV |
| `./patchgap --refresh` | Refresh package metadata, then show available updates; may require root |
| `./patchgap --export-inventory FILE` | Save installed package names, versions, and source OS details to JSON |
| `./patchgap --scan-inventory FILE --online` | Check all package versions in a saved inventory against OSV |
| `./patchgap --scan-inventory FILE --online --inspect` | Interactively browse full advisory lists after the scan |
| `./patchgap --online --output report.txt` | Print a report and save a plain-text copy |
| `./patchgap --help` | Show all options |

`--refresh` updates repository metadata only. On Arch Linux, PatchGap uses `checkupdates` when available instead of `pacman -Sy`. Without `--refresh`, update results depend on the metadata already cached on the machine.

## Understanding results

- **Update available** means the configured package manager reports a newer package version in its current metadata.
- **Advisory IDs** can include CVE identifiers and distro-specific security notice IDs.
- **No matching advisories** means OSV returned no matching record for that package and version. It does not prove the software is vulnerability-free.
- **Unknown** means PatchGap could not check the package, the lookup failed, or the saved system's ecosystem is unsupported. Unknown is not the same as a clean result.

Terminal colors are enabled automatically for interactive output and disabled for redirected output or when `NO_COLOR` is set. Use `--no-color` to disable colors or `--color` to force them. Reports saved with `--output` are plain text.

## Privacy and safety

- Normal inventory and update checks do not contact an external service.
- `--online` sends package names, installed versions, and the OSV ecosystem to the OSV API.
- The exported inventory includes the source host name, OS details, package names, and installed versions. Review it before transferring or sharing it.
- PatchGap does not install, upgrade, or remove packages. `--refresh` does update local package-manager metadata.

## Scope and limitations

PatchGap reports package-manager inventory and update status. It does not inspect arbitrary executable files, source checkouts, containers, or software installed outside a supported package manager. Online checks depend on OSV's coverage and the accuracy of the package name, version, and ecosystem mapping. Repository metadata may be stale unless refreshed.

## Project files

- `patchgap` — small POSIX shell launcher
- `patchgap.py` — Python implementation
- `assets/patchgap-logo.svg` — project logo used above
- `assets/patchgap.gif` — animated usage demonstration

## License

PatchGap is released under the [MIT License](LICENSE).
