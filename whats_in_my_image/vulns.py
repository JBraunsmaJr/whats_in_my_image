"""Import vulnerability findings (Trivy, Grype, Harbor) and attribute each one to an origin.

The scanner says *what* is vulnerable; this module answers *who put it there*, by
tying each finding to the component (and therefore the layer) we traced earlier.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path

from .parsers.ecosystems import normalize_pypi

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


@dataclass
class Vuln:
    id: str
    severity: str
    package: str
    version: str
    fixed_version: str
    title: str
    path: str = ""
    layer: int | None = None
    component_id: str = ""
    origin: str = "unknown"
    tool: str = ""
    attribution: str = ""  # how the layer was determined

    def to_dict(self) -> dict:
        return asdict(self)


def _sev(s: str) -> str:
    s = (s or "UNKNOWN").upper()
    return {"NEGLIGIBLE": "LOW", "MODERATE": "MEDIUM", "IMPORTANT": "HIGH"}.get(s, s if s in SEVERITIES else "UNKNOWN")


def parse_trivy(doc: dict, diff_index: dict[str, int]) -> list[Vuln]:
    out = []
    for res in doc.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            layer = diff_index.get((v.get("Layer") or {}).get("DiffID", ""))
            out.append(
                Vuln(
                    v.get("VulnerabilityID", ""),
                    _sev(v.get("Severity")),
                    v.get("PkgName", ""),
                    v.get("InstalledVersion", ""),
                    v.get("FixedVersion", "") or "",
                    (v.get("Title") or v.get("Description") or "")[:240],
                    v.get("PkgPath") or "",
                    layer,
                    tool="Trivy",
                )
            )
    return out


def parse_grype(doc: dict, diff_index: dict[str, int]) -> list[Vuln]:
    out = []
    for m in doc.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        layer, path = None, ""
        for loc in a.get("locations") or []:
            path = path or loc.get("path", "")
            if loc.get("layerID") in diff_index:
                layer = diff_index[loc["layerID"]]
                break
        fix = v.get("fix") or {}
        out.append(
            Vuln(
                v.get("id", ""),
                _sev(v.get("severity")),
                a.get("name", ""),
                a.get("version", ""),
                ", ".join(fix.get("versions") or []),
                (v.get("description") or "")[:240],
                path.lstrip("/"),
                layer,
                tool="Grype",
            )
        )
    return out


def parse_harbor(doc: dict, diff_index: dict[str, int]) -> list[Vuln]:
    reports = [doc] if "vulnerabilities" in doc else [r for r in doc.values() if isinstance(r, dict)]
    out = []
    for rep in reports:
        for v in rep.get("vulnerabilities") or []:
            layer = diff_index.get((v.get("layer") or {}).get("diff_id", ""))
            out.append(
                Vuln(
                    v.get("id", ""),
                    _sev(v.get("severity")),
                    v.get("package", ""),
                    v.get("version", ""),
                    v.get("fix_version", "") or "",
                    (v.get("description") or "")[:240],
                    "",
                    layer,
                    tool="Harbor (Trivy)",
                )
            )
    return out


def load_report(path: Path, diff_index: dict[str, int]) -> list[Vuln]:
    doc = json.loads(path.read_text())
    if isinstance(doc, dict) and "Results" in doc:
        return parse_trivy(doc, diff_index)
    if isinstance(doc, dict) and "matches" in doc:
        return parse_grype(doc, diff_index)
    if isinstance(doc, dict):
        return parse_harbor(doc, diff_index)
    raise ValueError(f"{path} is not a Trivy, Grype or Harbor vulnerability report")


def run_scanner(which: str, image, log) -> tuple[str, list[Vuln]] | None:
    """Run Trivy or Grype (whichever is installed) against the exact layers we analysed."""
    tools = ["trivy", "grype"] if which == "auto" else [which]
    tools = [t for t in tools if shutil.which(t)]
    if not tools:
        if which != "auto":
            log(f"  {which} is not installed; skipping vulnerability scan")
        return None
    diff_index = {d: i for i, d in enumerate(image.diff_ids)}
    with tempfile.TemporaryDirectory(prefix="wimi-scan-") as tmp:
        archive = image.write_docker_archive(Path(tmp) / "image.tar")
        for tool in tools:
            log(f"Running {tool} vulnerability scan (this can take a few minutes the first time) ...")
            if tool == "trivy":
                cmd = ["trivy", "image", "--input", str(archive), "--format", "json", "--quiet", "--scanners", "vuln"]
            else:
                cmd = ["grype", f"docker-archive:{archive}", "-o", "json", "-q"]
            # fixed argv built above, no shell; the scanner binary was resolved with shutil.which
            res = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603
            if res.returncode != 0 or not res.stdout.strip():
                log(f"  {tool} failed: {res.stderr.strip()[:400]}")
                continue
            doc = json.loads(res.stdout)
            return tool, (parse_trivy if tool == "trivy" else parse_grype)(doc, diff_index)
    return None


def fetch_harbor(image, log) -> list[Vuln] | None:
    """Pull the vulnerability report Harbor already produced for this artifact."""
    client = image.registry_client
    if client is None:
        log("  --harbor-vulns needs an image pulled from the Harbor registry")
        return None
    project, _, repo = client.ref.repository.partition("/")
    repo_enc = urllib.parse.quote(urllib.parse.quote(repo, safe=""), safe="")
    diff_index = {d: i for i, d in enumerate(image.diff_ids)}
    for digest in filter(None, (image.manifest_digest, image.index_digest)):
        url = (
            f"https://{client.ref.registry}/api/v2.0/projects/{project}/repositories/{repo_enc}"
            f"/artifacts/{digest}/additions/vulnerabilities"
        )
        try:
            doc = client.get_json(url)
        except Exception as e:
            log(f"  Harbor report not available for {digest[:19]}: {e}")
            continue
        vulns = parse_harbor(doc, diff_index)
        if vulns or doc:
            return vulns
    return None


# --------------------------------------------------------------------------- attribution


def _strip_epoch(v: str) -> str:
    return re.sub(r"^\d+:", "", v or "")


def _norm_name(name: str, eco: str) -> str:
    return normalize_pypi(name) if eco == "python" else name.lower()


def attribute(vulns: list[Vuln], components: list[dict], per_layer: list[str]) -> None:
    by_name: dict[str, list[dict]] = {}
    for c in components:
        by_name.setdefault(_norm_name(c["name"], c["ecosystem"]), []).append(c)
        if c["ecosystem"] == "java" and ":" in c["name"]:
            by_name.setdefault(c["name"].split(":", 1)[1].lower(), []).append(c)
    for v in vulns:
        cands = by_name.get(v.package.lower()) or by_name.get(normalize_pypi(v.package)) or []
        ver = _strip_epoch(v.version)
        exact = [c for c in cands if _strip_epoch(c["version"]) == ver] or [
            c
            for c in cands
            if ver
            and (_strip_epoch(c["version"]).startswith(ver) or ver.startswith(_strip_epoch(c["version"]) or "\0"))
        ]
        if v.path and len(exact) > 1:
            exact = [c for c in exact if any(v.path.startswith(p) or p.startswith(v.path) for p in c["paths"])] or exact
        if exact:
            c = exact[0]
            v.component_id, v.layer = c["id"], c["layer"]
            v.attribution = "matched to traced component"
        elif v.layer is not None:
            v.attribution = f"layer reported by {v.tool}"
        else:
            v.attribution = "could not be attributed"
        v.origin = per_layer[v.layer] if v.layer is not None and 0 <= v.layer < len(per_layer) else "unknown"
