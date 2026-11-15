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
SUPPORTED_OSV_ECOSYSTEMS = {
    "Debian", "Ubuntu", "Alpine", "AlmaLinux", "Rocky Linux", "Red Hat",
    "openSUSE", "SUSE", "Wolfi",
}


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
        installed = rpm_installed_version(package_arch) or "unknown"
        found.append(Update(name, installed, fields[1]))
    # dnf/yum use exit 100 when updates are available.
    return found


def rpm_installed_version(package: str) -> str:
    result = run(["rpm", "-q", "--qf", "%{EPOCHNUM}\\t%{VERSION}-%{RELEASE}\\n", package])
    if result.returncode != 0:
        return ""
    fields = result.stdout.splitlines()[0].split(chr(9), 1) if result.stdout.splitlines() else []
    if len(fields) != 2:
        return ""
    epoch, version = fields
    return f"{epoch}:{version}" if epoch not in ("", "0", "(none)") else version


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


def collect_installed(pm: str) -> list[Update]:
    """Return installed package names and versions for portable inventory export."""
    if pm == "apt":
        result = run(["dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\t${db:Status-Status}\\n"])
        rows = []
        for line in result.stdout.splitlines():
            fields = line.split(chr(9))
            if len(fields) != 3 or fields[2] != "installed":
                continue
            name = fields[0].split(":", 1)[0]
            rows.append(Update(name, fields[1], ""))
        return unique_records(rows)
    if pm in ("dnf", "yum", "zypper"):
        result = run(["rpm", "-qa", "--qf", "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}-%{RELEASE}\\n"])
        rows = []
        for line in result.stdout.splitlines():
            fields = line.split(chr(9))
            if len(fields) == 3 and fields[0] and fields[2]:
                version = f"{fields[1]}:{fields[2]}" if fields[1] not in ("", "0", "(none)") else fields[2]
                rows.append(Update(fields[0], version, ""))
        return unique_records(rows)
    if pm == "pacman":
        result = run(["pacman", "-Q"])
        rows = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 2:
                rows.append(Update(fields[0], fields[1], ""))
        return unique_records(rows)
    if pm == "apk":
        result = run(["apk", "info", "-v"])
        rows = []
        for line in result.stdout.splitlines():
            match = re.match(r"^(.*)-([0-9][A-Za-z0-9._+~-]*)$", line.strip())
            if match:
                rows.append(Update(match.group(1), match.group(2), ""))
        return unique_records(rows)
    return []


def unique_records(rows: list[Update]) -> list[Update]:
    unique: dict[tuple[str, str], Update] = {}
    for row in rows:
        unique[(row.name, row.installed)] = row
    return list(unique.values())


def make_inventory(pm: str, packages: list[Update]) -> dict[str, object]:
    os_release = installed_os()
    return {
        "format": "patchgap-inventory",
        "schema_version": 1,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "host": platform.node(),
        "package_manager": pm,
        "os": {
            "id": os_release.get("ID", "unknown"),
            "name": os_release.get("PRETTY_NAME", platform.platform()),
            "version_id": os_release.get("VERSION_ID", ""),
            "ecosystem": osv_ecosystem(os_release),
        },
        "packages": [{"name": item.name, "version": item.installed}
                     for item in sorted(packages, key=lambda p: (p.name.lower(), p.installed))],
    }


def load_inventory(path: str) -> tuple[dict[str, object], list[Update]]:
    try:
        data = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read inventory file: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != "patchgap-inventory" or data.get("schema_version") != 1:
        raise ValueError("unsupported inventory format or schema version")
    os_data = data.get("os")
    packages = data.get("packages")
    if not isinstance(os_data, dict) or not isinstance(packages, list):
        raise ValueError("inventory is missing its OS details or package list")
    ecosystem = os_data.get("ecosystem")
    if ecosystem is not None and not isinstance(ecosystem, str):
        raise ValueError("inventory ecosystem must be a string or null")
    if ecosystem not in SUPPORTED_OSV_ECOSYSTEMS:
        os_data["ecosystem"] = None
    rows = []
    for index, package in enumerate(packages, 1):
        if not isinstance(package, dict):
            raise ValueError(f"invalid package record at index {index}")
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not name.strip() or not isinstance(version, str) or not version.strip():
            raise ValueError(f"package record {index} needs a non-empty name and version")
        rows.append(Update(name.strip(), version.strip(), ""))
    data["packages"] = [{"name": p.name, "version": p.installed} for p in rows]
    return data, unique_records(rows)


def osv_ecosystem(os_release: dict[str, str]) -> str | None:
    distro = os_release.get("ID", "").lower()
    ecosystems = {
        "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine",
        "almalinux": "AlmaLinux", "rocky": "Rocky Linux",
        "rhel": "Red Hat", "redhat": "Red Hat",
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
        return f"No package versions to check against OSV ({ecosystem}).", 0

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
    return f"OSV lookup completed for {len(updates)} package version(s) using {ecosystem}.", vulnerabilities


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


def fit_cell(value: str, width: int) -> str:
    if len(value) <= width:
        return value.ljust(width)
    return value[:max(0, width - 1)] + "…"


def compact_advisories(advisories: list[str], width: int) -> str:
    full = ", ".join(advisories)
    if len(full) <= width:
        return full.ljust(width)
    shown: list[str] = []
    for advisory in advisories:
        candidate = shown + [advisory]
        remaining = len(advisories) - len(candidate)
        suffix = f" … (+{remaining} more)" if remaining else ""
        if len(", ".join(candidate)) + len(suffix) > width:
            break
        shown = candidate
    remaining = len(advisories) - len(shown)
    suffix = f" … (+{remaining} more)"
    while shown and len(", ".join(shown)) + len(suffix) > width:
        shown.pop()
        remaining = len(advisories) - len(shown)
        suffix = f" … (+{remaining} more)"
    if not shown:
        return fit_cell(advisories[0], width)
    return (", ".join(shown) + suffix).ljust(width)


def inventory_report(data: dict[str, object], packages: list[Update], lookup_message: str) -> tuple[str, int]:
    os_data = data["os"]
    assert isinstance(os_data, dict)
    host = data.get("host") or "unknown"
    os_name = os_data.get("name") or os_data.get("id") or "unknown"
    ecosystem = os_data.get("ecosystem")
    created_at = data.get("created_at") or "unknown"
    findings = sum(len(package.advisories) for package in packages)
    unknown = sum(package.cve_status.startswith("unknown") for package in packages)
    lines = [
        "PATCHGAP | SAVED INVENTORY CVE SCAN",
        "=" * 76,
        f"Inventory host: {host}",
        f"Operating system: {os_name}",
        f"Inventory created: {created_at}",
        f"OSV ecosystem: {ecosystem or 'unsupported / unknown'}",
        f"Packages checked: {len(packages)}",
        "",
        "Vulnerability findings",
        "-" * 76,
        lookup_message,
    ]
    affected = [package for package in packages if package.advisories]
    if affected:
        terminal_width = shutil.get_terminal_size((100, 24)).columns
        table_width = max(60, min(terminal_width, 160))
        name_w = min(26, max(10, int(table_width * 0.22)))
        version_w = min(24, max(10, int(table_width * 0.20)))
        advisory_w = table_width - name_w - version_w - 4
        lines.append(f"{fit_cell('PACKAGE', name_w)}  {fit_cell('VERSION', version_w)}  ADVISORIES")
        lines.append(f"{'-' * name_w}  {'-' * version_w}  {'-' * advisory_w}")
        for package in sorted(affected, key=lambda p: p.name.lower()):
            lines.append(f"{fit_cell(package.name, name_w)}  {fit_cell(package.installed, version_w)}  "
                         f"{compact_advisories(package.advisories, advisory_w)}")
        lines += ["", "Long advisory lists are shortened in this table. Use --inspect to read the full list for a package."]
    elif unknown == 0:
        lines.append("No matching OSV advisories were returned for the recorded package versions.")
    lines += ["", f"Advisory identifiers: {findings}", f"Packages with unknown CVE status: {unknown}"]
    if unknown:
        lines.append("Some package checks could not be completed or the inventory ecosystem is unsupported.")
    lines += ["", "This checks package versions recorded in the inventory, not the current machine.",
              "No findings is not a guarantee that the recorded software is vulnerability-free."]
    return "\n".join(lines) + "\n", findings


def write_report(path: str, report: str) -> Path:
    destination = Path(path).expanduser()
    destination.write_text(report, encoding="utf-8")
    return destination


def colors_enabled(args: argparse.Namespace) -> bool:
    if args.no_color:
        return False
    if args.color:
        return True
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


def colorize_report(report: str) -> str:
    reset = "\033[0m"
    bold = "\033[1m"
    dim = "\033[2m"
    cyan = "\033[36m"
    blue = "\033[34m"
    green = "\033[32m"
    yellow = "\033[33m"
    red = "\033[31m"
    white = "\033[97m"
    sections = {
        "Package updates", "Vulnerability lookup", "Notes",
        "Vulnerability findings",
    }
    rendered = []
    for line in report.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        ending = line[len(content):]
        if content.startswith("PATCHGAP |"):
            content = f"{bold}{cyan}{content}{reset}"
        elif content and set(content) <= {"=", "-"}:
            content = f"{dim}{blue}{content}{reset}"
        elif content in sections or content.startswith("Package updates ("):
            content = f"{bold}{cyan}{content}{reset}"
        elif content.startswith("PACKAGE") or content.startswith("PACKAGE "):
            content = f"{bold}{white}{content}{reset}"
        elif content.startswith("No package updates") or content.startswith("No matching OSV advisories"):
            content = f"{green}{content}{reset}"
        elif content.startswith("Warning:") or content.startswith("Some package checks"):
            content = f"{yellow}{content}{reset}"
        elif re.match(r"^[A-Za-z][A-Za-z _-]*:", content):
            label, value = content.split(":", 1)
            content = f"{cyan}{label}:{reset}{value}"
        elif re.match(r"^\S+\s{2,}\S+", content):
            columns = re.split(r"(\s{2,})", content.rstrip())
            cells = columns[::2]
            if len(columns) >= 3:
                if len(cells) >= 3:
                    cells[0] = f"{bold}{white}{cells[0]}{reset}"
                    cells[1] = f"{yellow}{cells[1]}{reset}"
                    if len(cells) >= 4:
                        cells[2] = f"{green}{cells[2]}{reset}"
                        for index in range(3, len(cells)):
                            cells[index] = color_status(cells[index], bold, red, yellow, green, dim, reset)
                    else:
                        cells[2] = color_status(cells[2], bold, red, yellow, green, dim, reset)
                    rebuilt = []
                    for index, cell in enumerate(cells):
                        rebuilt.append(cell)
                        if 2 * index + 1 < len(columns):
                            rebuilt.append(columns[2 * index + 1])
                    content = "".join(rebuilt)
        rendered.append(content + ending)
    return "".join(rendered)


def color_status(status: str, bold: str, red: str, yellow: str,
                 green: str, dim: str, reset: str) -> str:
    if "CVE-" in status or "GHSA-" in status or "findings" in status.lower():
        color = f"{bold}{red}"
    elif "unknown" in status.lower():
        color = yellow
    elif "none found" in status.lower() or "no matching" in status.lower():
        color = green
    elif "not checked" in status.lower():
        color = dim
    else:
        color = green
    return f"{color}{status}{reset}"


def inspect_findings(packages: list[Update], use_color: bool) -> None:
    affected = sorted((p for p in packages if p.advisories), key=lambda p: p.name.lower())
    if not affected:
        print("There are no advisory lists to inspect.")
        return
    print("\nAdvisory inspector: enter a package name or part of a name; enter q to quit.")
    while True:
        try:
            query = input("Package> ").strip()
        except EOFError:
            return
        if query.lower() in {"q", "quit", "exit"}:
            return
        if not query:
            continue
        matches = [p for p in affected if query.casefold() in p.name.casefold()]
        if not matches:
            print("No matching package. Try a shorter name or enter q to quit.")
            continue
        if len(matches) == 1:
            selected = matches[0]
        else:
            for index, package in enumerate(matches[:40], 1):
                print(f"{index:>2}. {package.name} {package.installed} ({len(package.advisories)} advisories)")
            if len(matches) > 40:
                print(f"Showing 40 of {len(matches)} matches; refine the package search.")
                continue
            try:
                choice = input("Select number (or enter another search)> ").strip()
            except EOFError:
                return
            if not choice.isdigit() or not 1 <= int(choice) <= len(matches):
                print("No package selected.")
                continue
            selected = matches[int(choice) - 1]
        heading = f"\n{selected.name} {selected.installed} — {len(selected.advisories)} advisories"
        print(f"\033[1;36m{heading}\033[0m" if use_color else heading)
        page_size = 25
        for start in range(0, len(selected.advisories), page_size):
            page = selected.advisories[start:start + page_size]
            for index, advisory in enumerate(page, start + 1):
                item = f"  {index:>3}. {advisory}"
                print(f"\033[1;31m{item}\033[0m" if use_color else item)
            if start + page_size < len(selected.advisories):
                try:
                    if input("-- more -- press Enter to continue, q to stop -- ").strip().lower() == "q":
                        break
                except EOFError:
                    return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inventory outdated Linux packages, with optional online OSV vulnerability lookup.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--online", action="store_true",
                        help="query OSV for vulnerabilities affecting outdated installed package versions")
    parser.add_argument("--refresh", action="store_true",
                        help="refresh package-manager metadata before scanning (may require root)")
    parser.add_argument("--export-inventory", metavar="FILE",
                        help="save all installed package names and versions for transfer to an online machine")
    parser.add_argument("--scan-inventory", metavar="FILE",
                        help="check a saved inventory file; use together with --online")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="also save the plain-text report to FILE; by default nothing is saved")
    color_group = parser.add_mutually_exclusive_group()
    color_group.add_argument("--color", action="store_true", help="force colored terminal output")
    color_group.add_argument("--no-color", action="store_true", help="disable colored terminal output")
    parser.add_argument("--inspect", action="store_true",
                        help="interactively inspect full advisory lists after scanning a saved inventory")
    parser.add_argument("--version", action="version", version=f"PatchGap {VERSION}")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.export_inventory and (args.scan_inventory or args.online or args.refresh):
            raise ValueError("--export-inventory cannot be combined with --scan-inventory, --online, or --refresh")
        if args.scan_inventory and not args.online:
            raise ValueError("--scan-inventory requires --online")
        if args.scan_inventory and args.refresh:
            raise ValueError("--refresh cannot be used with --scan-inventory")
        if args.inspect and not args.scan_inventory:
            raise ValueError("--inspect is available with --scan-inventory")
        if args.inspect and not sys.stdin.isatty():
            raise ValueError("--inspect requires an interactive terminal")

        if args.scan_inventory:
            if args.output and Path(args.output).expanduser().resolve() == Path(args.scan_inventory).expanduser().resolve():
                raise ValueError("--output must use a different file from --scan-inventory")
            data, packages = load_inventory(args.scan_inventory)
            ecosystem = data["os"].get("ecosystem")  # type: ignore[union-attr]
            lookup_message, _ = osv_lookup(packages, ecosystem if isinstance(ecosystem, str) else None)
            report, _ = inventory_report(data, packages, lookup_message)
        elif args.export_inventory:
            if args.output and Path(args.output).expanduser().resolve() == Path(args.export_inventory).expanduser().resolve():
                raise ValueError("--output and --export-inventory must use different files")
            pm = manager()
            if pm is None:
                raise ValueError("no supported package manager found; cannot export a package inventory")
            packages = collect_installed(pm)
            inventory = make_inventory(pm, packages)
            destination = Path(args.export_inventory).expanduser()
            destination.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
            report = ("PATCHGAP | INVENTORY EXPORTED\n" + "=" * 76 + "\n" +
                      f"Host: {inventory['host']}\nOperating system: {inventory['os']['name']}\n" +
                      f"Package manager: {pm}\nPackages recorded: {len(packages)}\n" +
                      f"Inventory file: {destination}\n")
        else:
            report, _ = build_report(args)
    except KeyboardInterrupt:
        print("\nScan cancelled.", file=sys.stderr)
        return 130
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    use_color = colors_enabled(args)
    print(colorize_report(report) if use_color else report, end="")
    if args.output:
        try:
            destination = write_report(args.output, report)
        except OSError as exc:
            print(f"Error: could not save report to {args.output}: {exc}", file=sys.stderr)
            return 2
        message = f"Report saved to {destination}"
        print(f"\033[32m{message}\033[0m" if use_color else message)
    if args.inspect:
        inspect_findings(packages, use_color)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
