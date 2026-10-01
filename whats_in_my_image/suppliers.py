"""Turn raw package metadata into a plain-language supplier name."""

from __future__ import annotations

import re
import urllib.parse

# Long (16 hex digit) OpenPGP key IDs of well-known package signing keys. Keys that the
# image itself imported (rpm "gpg-pubkey" entries) are added at runtime, so this list only
# needs to cover the common cases.
KNOWN_KEYS = {
    "199e2f91fd431d51": "Red Hat, Inc. (release key 2)",
    "5054e4a45a6340b3": "Red Hat, Inc. (auxiliary key 3)",
    "21ea45ab2f86d6a1": "Fedora EPEL 8",
    "8a3872bf3228467c": "Fedora EPEL 9",
}


def rpm_vendor_label(vendor: str) -> str:
    v = (vendor or "").strip()
    low = v.lower()
    if not v:
        return "Unknown vendor (no vendor recorded)"
    if "red hat" in low:
        return "Red Hat"
    if "fedora" in low:
        return "Fedora Project (community)"
    if "centos" in low:
        return "CentOS Project (community)"
    if "rocky" in low:
        return "Rocky Linux (community)"
    if "alma" in low:
        return "AlmaLinux (community)"
    if "amazon" in low:
        return "Amazon Linux"
    if "oracle" in low:
        return "Oracle Linux"
    if "suse" in low:
        return "SUSE"
    return v


def rpm_repo_label(repo: str) -> str:
    r = (repo or "").lower()
    if not r:
        return ""
    if r == "@commandline":
        return "a local RPM file (not from any repository)"
    if r.startswith(("ubi-", "ubi8", "ubi9", "ubi10")):
        return f"Red Hat UBI repository ({repo})"
    if r.startswith("rhel") or "rhel-" in r or r.startswith(("rhocp", "rhoso", "codeready")):
        return f"Red Hat repository ({repo})"
    if "epel" in r:
        return f"EPEL community repository ({repo})"
    return f"repository '{repo}'"


def distro_label(os_release: dict[str, str]) -> str:
    ident = (os_release.get("ID") or "").lower()
    names = {
        "rhel": "Red Hat",
        "centos": "CentOS Project",
        "rocky": "Rocky Linux",
        "almalinux": "AlmaLinux",
        "fedora": "Fedora Project",
        "debian": "Debian Project",
        "ubuntu": "Ubuntu (Canonical)",
        "alpine": "Alpine Linux",
        "wolfi": "Wolfi (Chainguard)",
        "chainguard": "Chainguard",
        "amzn": "Amazon Linux",
        "ol": "Oracle Linux",
        "sles": "SUSE",
        "opensuse-leap": "openSUSE",
        "photon": "VMware Photon OS",
        "mariner": "Microsoft CBL-Mariner",
        "azurelinux": "Microsoft Azure Linux",
    }
    return names.get(ident, os_release.get("NAME") or "the operating-system vendor")


def registry_from_url(url: str, default: str) -> str:
    if not url:
        return default
    host = urllib.parse.urlparse(url).hostname or ""
    if host in ("registry.npmjs.org", "registry.yarnpkg.com"):
        return "npm public registry (npmjs.com)"
    if host in ("pypi.org", "files.pythonhosted.org"):
        return "PyPI (Python Package Index)"
    return f"{host or url} (private or mirror registry)" if host else default


def go_module_supplier(module: str) -> str:
    if module.startswith(("golang.org/x/", "go.googlesource.com")):
        return "Go project (golang.org/x)"
    parts = module.split("/")
    if parts[0] in ("github.com", "gitlab.com", "bitbucket.org") and len(parts) >= 2:
        return f"Open source: {parts[0]}/{parts[1]}"
    return f"Open source: {parts[0]}"


def java_supplier(group: str, evidence: str) -> str:
    if group and evidence == "pom.properties":
        return f"Maven repository (group {group})"
    if group:
        return f"{group} (from jar manifest)"
    return "Unknown (identified from file name only)"


_NUM = re.compile(r"(\d+|[a-zA-Z]+|~)")


def compare_versions(a: str, b: str) -> int:
    """Loose rpm/dpkg-style version comparison: -1, 0, 1."""
    if a == b:
        return 0
    ea, _, ra = a.partition(":") if ":" in a.split("-")[0] else ("0", "", a)
    eb, _, rb = b.partition(":") if ":" in b.split("-")[0] else ("0", "", b)
    if ea != eb and ea.isdigit() and eb.isdigit():
        return 1 if int(ea) > int(eb) else -1
    ta, tb = _NUM.findall(ra), _NUM.findall(rb)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if x == "~" or y == "~":
            return -1 if x == "~" else 1
        if x.isdigit() and y.isdigit():
            return 1 if int(x) > int(y) else -1
        if x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1
        return 1 if x > y else -1
    if len(ta) == len(tb):
        return 0
    longer, sign = (ta, 1) if len(ta) > len(tb) else (tb, -1)
    nxt = longer[min(len(ta), len(tb))]
    return -sign if nxt == "~" else sign  # "1.0~rc1" sorts before "1.0"
