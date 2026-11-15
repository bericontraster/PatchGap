# PatchGap

PatchGap inventories Linux package updates and can check package versions against OSV. It runs offline by default and uses Python 3.9 or newer with no third-party dependencies.

Supported package managers: APT, DNF, YUM, Pacman, Zypper, and APK.

## Run

```sh
chmod +x patchgap
./patchgap
```

The Python implementation can also be run directly with `python3 patchgap.py`.

## Offline inventory, online CVE scan

On the offline Linux machine, export its installed package names and versions:

```sh
./patchgap --export-inventory patchgap-inventory.json
```

Transfer `patchgap-inventory.json` to an internet-connected machine, then query OSV:

```sh
./patchgap --scan-inventory patchgap-inventory.json --online
```

This scans all recorded package versions, even if they are not installed on the connected machine. The inventory records the source machine's OS and OSV ecosystem so the query uses that system's package context.

## Other options

```sh
# Check locally available updates using cached metadata; no network access
./patchgap

# Check updates for outdated local packages against OSV
./patchgap --online

# Refresh package metadata first (may require root)
sudo ./patchgap --refresh

# Save a plain-text report only when requested
./patchgap --online --output patchgap-report.txt
```

`--refresh` updates package metadata only; it does not install, upgrade, or remove packages. On Arch Linux it uses `checkupdates` when available, avoiding `pacman -Sy`. Without `--refresh`, update availability depends on cached metadata.

By default, reports are printed to the terminal and not saved. `--output FILE` saves the plain-text report. `--export-inventory FILE` writes a portable JSON inventory; it contains the host name, OS details, package names, and installed versions.

Terminal colors are enabled automatically for interactive output and disabled when output is redirected or the `NO_COLOR` environment variable is set. Use `--no-color` to disable them or `--color` to force them. Saved report files remain plain text.

## CVE lookup

Online lookups send package names, installed versions, and the recorded OSV ecosystem to the [OSV API](https://osv.dev/). Current ecosystem mappings include Debian, Ubuntu, Alpine, AlmaLinux, Rocky Linux, Red Hat Enterprise Linux, openSUSE, SUSE Linux Enterprise, and Wolfi. Unsupported distributions are reported with unknown CVE status.

The local `--online` scan checks outdated packages reported by the package manager. `--scan-inventory FILE --online` checks all packages in that saved inventory. "No matching advisories" means OSV returned no matching record; it is not a guarantee that software is vulnerability-free. Online inventory scans can make multiple requests for large package lists.
