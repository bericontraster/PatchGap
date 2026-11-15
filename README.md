# PatchGap

PatchGap inventories package updates available on a Linux system. It runs offline by default and can optionally check installed versions of outdated packages against the OSV vulnerability database.

## Requirements

- Linux
- Python 3.9 or newer (standard library only)
- One supported package manager: APT, DNF, YUM, Pacman, Zypper, or APK

The shell entry point `linux-outdated-enum.sh` forwards to the Python implementation. You can also run the Python file directly.

## Usage

```sh
chmod +x linux-outdated-enum.sh
./linux-outdated-enum.sh
```

Examples:

```sh
# Check cached package metadata without network access
./linux-outdated-enum.sh

# Refresh package metadata, then inventory updates (may require root)
sudo ./linux-outdated-enum.sh --refresh

# Also check outdated installed versions against OSV (requires internet)
./linux-outdated-enum.sh --online

# Save a plain-text report only when requested
./linux-outdated-enum.sh --online --output patchgap-report.txt
```

`--refresh` runs the package manager's metadata refresh command. It does not install, upgrade, or remove packages. For Arch Linux it uses `checkupdates` when available, avoiding `pacman -Sy`. Without `--refresh`, update availability depends on metadata already cached on the machine.

By default, the report is printed to the terminal and no report file is created. `--output FILE` writes the same clean, plain-text report to the selected path.

## CVE lookup details

Online mode submits package names and installed versions for packages reported as outdated to the [OSV API](https://osv.dev/). It currently maps Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux, Red Hat Enterprise Linux, openSUSE, SUSE Linux Enterprise, and Wolfi. Other distributions are still inventoried, but their CVE status is shown as unknown until an ecosystem mapping is available.

The lookup checks only outdated packages found by the package manager. A result of "none found" means OSV returned no matching advisory for that package and version; it does not guarantee that the software has no known or unknown vulnerabilities. Online mode sends package names and installed versions to OSV. Offline mode makes no network requests and reports no CVE verdict.

PatchGap reports package-manager updates. It does not determine whether manually installed binaries or source checkouts are current.
