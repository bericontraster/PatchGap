#!/usr/bin/env python3
"""Read-only Linux package update inventory with optional OSV vulnerability lookup."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.0.0"
OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"


@dataclass
class Update:
    name: str
    installed: str
    available: str
    advisories: list[str] = field(default_factory=list)
    cve_status: str = "not checked"


def run(args: list[str], timeout: int = 45) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    try:
        return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout,
                              check=False, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(args, 127, "", str(exc))


def installed_os() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                data[key] = value.strip().strip('"')
    except OSError:
        pass
    return data


def manager() -> str | None:
    for name, executable in (("apt", "apt-get"), ("dnf", "dnf"),
                             ("yum", "yum"), ("pacman", "pacman"),
                             ("zypper", "zypper"), ("apk", "apk")):
        if shutil.which(executable):
            return name
    return None


def refresh_metadata(pm: str) -> tuple[bool, str]:
    if pm == "pacman":
        # `pacman -Sy` can create a partial-upgrade state. checkupdates uses a
        # separate sync database and is the safe refresh path when installed.
        if not shutil.which("checkupdates"):
            return False, "checkupdates is not installed; skipped unsafe pacman -Sy refresh."
        result = run(["checkupdates"], timeout=300)
        if result.returncode in (0, 2):
            return True, "Package metadata refreshed in checkupdates' isolated database."
        detail = (result.stderr or result.stdout).strip().splitlines()
        return False, detail[-1] if detail else f"checkupdates failed (exit {result.returncode})."
    commands = {
        "apt": ["apt-get", "update", "-qq"],
        "dnf": ["dnf", "-q", "makecache", "--refresh"],
        "yum": ["yum", "-q", "makecache", "--refresh"],
        "pacman": [],  # handled above
        "zypper": ["zypper", "--non-interactive", "refresh"],
        "apk": ["apk", "update"],
    }
    result = run(commands[pm], timeout=300)
    if result.returncode == 0:
        return True, "Package metadata refreshed."
    detail = (result.stderr or result.stdout).strip().splitlines()
    return False, detail[-1] if detail else f"{pm} metadata refresh failed (exit {result.returncode})."


def apt_updates() -> list[Update]:
    result = run(["apt", "list", "--upgradable"])
    found: list[Update] = []
    pattern = re.compile(r"^([^/]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^]]+)\]")
    for line in result.stdout.splitlines():
        match = pattern.match(line.strip())
        if match:
            name, available, installed = match.groups()
            found.append(Update(name, installed, available))
    return found


def rpm_updates(pm: str) -> list[Update]:
    result = run([pm, "-q", "check-update"])
    found: list[Update] = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0].startswith(("Last metadata", "Obsoleting")):
            continue
        package_arch = fields[0]
        if "." not in package_arch:
            continue
        name, _arch = package_arch.rsplit(".", 1)
        installed_result = run(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", name])
        installed = installed_result.stdout.strip() or "unknown"
        found.append(Update(name, installed, fields[1]))
    # dnf/yum use exit 100 when updates are available.
    return found


def pacman_updates(use_checkupdates: bool = False) -> list[Update]:
    result = run(["checkupdates"] if use_checkupdates else ["pacman", "-Qu"])
    found = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[2] == "->":
            found.append(Update(fields[0], fields[1], fields[3]))
    return found


def zypper_updates() -> list[Update]:
    result = run(["zypper", "--no-refresh", "--non-interactive", "--terse", "list-updates"])
    found = []
    for line in result.stdout.splitlines():
        if not line.startswith("v|-"):
            continue
        fields = [part.strip() for part in line.split("|")]
        if len(fields) >= 6:
            found.append(Update(fields[2], fields[3], fields[4]))
    return found


def apk_updates() -> list[Update]:
    result = run(["apk", "version", "-l", "<"])
    found = []
    # apk prints: package-installed < package-available
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[1] != "<":
            continue
        current, available = fields[0], fields[2]
        # Keep package names intact while separating the final version token.
        match = re.match(r"^(.*)-([0-9][A-Za-z0-9._+~-]*)$", current)
        cand = re.match(r"^(.*)-([0-9][A-Za-z0-9._+~-]*)$", available)
        if match and cand:
            found.append(Update(match.group(1), match.group(2), cand.group(2)))
    return found


def collect_updates(pm: str, refreshed: bool = False) -> list[Update]:
    collectors = {"apt": apt_updates, "dnf": lambda: rpm_updates("dnf"),
                  "yum": lambda: rpm_updates("yum"), "pacman": lambda: pacman_updates(refreshed),
                  "zypper": zypper_updates, "apk": apk_updates}
    return collectors[pm]()


def osv_ecosystem(os_release: dict[str, str]) -> str | None:
    distro = os_release.get("ID", "").lower()
    ecosystems = {
        "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine",
        "almalinux": "AlmaLinux", "rocky": "Rocky Linux",
        "rhel": "Red Hat", "redhat": "Red Hat", "centos": "Red Hat",
        "opensuse": "openSUSE", "opensuse-leap": "openSUSE",
        "opensuse-tumbleweed": "openSUSE", "sles": "SUSE", "wolfi": "Wolfi",
    }
    return ecosystems.get(distro)


def osv_lookup(updates: list[Update], ecosystem: str | None) -> tuple[str, int]:
    if ecosystem is None:
        for item in updates:
            item.cve_status = "unknown (OSV ecosystem mapping unavailable)"
        return "OSV does not provide a configured distro ecosystem for this system; CVE status is unknown.", 0
    if not updates:
        return f"No outdated packages to check against OSV ({ecosystem}).", 0

    vulnerabilities = 0
    failures = 0
    # OSV querybatch returns results in the same order as the submitted queries.
    for start in range(0, len(updates), 100):
        batch = updates[start:start + 100]
        body = {"queries": [{"package": {"name": item.name, "ecosystem": ecosystem},
                              "version": item.installed} for item in batch]}
        request = urllib.request.Request(
            OSV_ENDPOINT,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "User-Agent": f"PatchGap/{VERSION}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=25) as response:
                payload = json.loads(response.read().decode("utf-8"))
            results = payload.get("results", [])
            if len(results) != len(batch):
                raise ValueError("OSV returned an unexpected number of results")
            for item, result in zip(batch, results):
                advisories = []
                for vuln in result.get("vulns", []):
                    ids = [vuln.get("id", "")] + vuln.get("aliases", [])
                    cves = sorted({value for value in ids if value.startswith("CVE-")})
                    advisories.extend(cves or [vuln.get("id", "OSV advisory")])
                item.advisories = sorted(set(advisories))
                item.cve_status = "findings" if item.advisories else "none found"
                vulnerabilities += len(item.advisories)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
            failures += len(batch)
            for item in batch:
                item.cve_status = "unknown (OSV lookup failed)"
            print(f"Warning: OSV lookup failed: {exc}", file=sys.stderr)
    if failures:
        return f"OSV lookup completed with {failures} package(s) unverified; their CVE status is unknown.", vulnerabilities
    return f"OSV lookup completed for {len(updates)} outdated package(s) using {ecosystem}.", vulnerabilities


def table(rows: list[Update]) -> list[str]:
    if not rows:
        return ["No package updates were reported by the configured package manager."]
    name_w = min(32, max(7, max(len(row.name) for row in rows)))
    installed_w = min(24, max(9, max(len(row.installed) for row in rows)))
    available_w = min(24, max(9, max(len(row.available) for row in rows)))
    lines = [f"{'PACKAGE':<{name_w}}  {'INSTALLED':<{installed_w}}  {'AVAILABLE':<{available_w}}  CVE STATUS"]
    lines.append(f"{'-' * name_w}  {'-' * installed_w}  {'-' * available_w}  {'-' * 30}")
    for row in sorted(rows, key=lambda x: x.name.lower()):
        cv = row.cve_status
        if row.advisories:
            cv = ", ".join(row.advisories)
        lines.append(f"{row.name[:name_w]:<{name_w}}  {row.installed[:installed_w]:<{installed_w}}  "
                     f"{row.available[:available_w]:<{available_w}}  {cv}")
    return lines


def build_report(args: argparse.Namespace) -> tuple[str, int]:
    os_release = installed_os()
    pm = manager()
    now = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    os_name = os_release.get("PRETTY_NAME", platform.platform())
    lines = [
        "PATCHGAP | LINUX UPDATE INVENTORY",
        "=" * 76,
        f"Host:       {platform.node() or 'unknown'}",
        f"Operating system: {os_name}",
        f"Kernel:     {platform.release()}",
        f"Scanned:    {now}",
        f"Mode:       {'online CVE lookup (OSV)' if args.online else 'offline inventory'}",
        f"Metadata:   {'refresh requested' if args.refresh else 'cached package-manager metadata'}",
        "",
    ]
    if pm is None:
        lines += ["Package updates", "-" * 76,
                  "No supported package manager found (apt, dnf, yum, pacman, zypper, apk)."]
        return "\n".join(lines) + "\n", 0

    refresh_message = ""
    refresh_failed = False
    refresh_succeeded = False
    if args.refresh:
        refresh_succeeded, refresh_message = refresh_metadata(pm)
        refresh_failed = not refresh_succeeded
    updates = collect_updates(pm, refreshed=refresh_succeeded and pm == "pacman")
    lookup_message = "CVE lookup was not requested."
    findings = 0
    if args.online:
        lookup_message, findings = osv_lookup(updates, osv_ecosystem(os_release))

    lines += [f"Package updates ({pm})", "-" * 76]
    lines.extend(table(updates))
    lines += ["", "Vulnerability lookup", "-" * 76, lookup_message]
    if args.online:
        lines.append(f"Advisory identifiers reported: {findings}")
    lines += ["", "Notes", "-" * 76,
              "Update availability comes from local package-manager metadata. Use --refresh to request fresh metadata.",
              "Online checks query OSV for the installed versions of packages reported as outdated.",
              "No findings means OSV returned no matching advisories; it is not a guarantee that software is vulnerability-free.",
              "This scan covers package-manager updates. It does not prove that manually installed binaries are current."]
    if refresh_message:
        lines += [f"Metadata refresh: {refresh_message}"]
    if refresh_failed:
        lines += ["The report may use stale cached metadata because refresh failed."]
    return "\n".join(lines) + "\n", findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inventory outdated Linux packages, with optional online OSV vulnerability lookup.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--online", action="store_true",
                        help="query OSV for vulnerabilities affecting outdated installed package versions")
    parser.add_argument("--refresh", action="store_true",
                        help="refresh package-manager metadata before scanning (may require root)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="also save the plain-text report to FILE; by default nothing is saved")
    parser.add_argument("--version", action="version", version=f"PatchGap {VERSION}")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report, _ = build_report(args)
    except KeyboardInterrupt:
        print("\nScan cancelled.", file=sys.stderr)
        return 130
    print(report, end="")
    if args.output:
        try:
            destination = Path(args.output).expanduser()
            destination.write_text(report, encoding="utf-8")
        except OSError as exc:
            print(f"Error: could not save report to {args.output}: {exc}", file=sys.stderr)
            return 2
        print(f"Report saved to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
