"""Command-line entry point: ``wimi <image> --base <base image>``."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import textwrap
from pathlib import Path

from . import __version__, html_report, report, vulns as vulnmod
from .analyze import Analyzer, base_label, compute_origins
from .sources import SourceError, load_image
from .walker import Walker

EPILOG = textwrap.dedent("""\
    image sources:
      harbor.example.mil/project/app:1.2       pull from any registry (Harbor, Iron Bank, Docker Hub ...)
      docker-archive:app.tar  /  app.tar       a `docker save` / `podman save` archive
      oci:./layout-dir  /  oci-archive:x.tar   an OCI image layout
      docker:app:1.2  /  podman:app:1.2        export from the local container engine

    examples:
      wimi harbor.example.mil/team/api:2.4 \\
           --base registry1.dso.mil/ironbank/redhat/ubi/ubi9:9.4
      wimi harbor.example.mil/team/api:2.4 --base "Iron Bank Python=registry1.dso.mil/ironbank/opensource/python:3.11" \\
           --base registry1.dso.mil/ironbank/redhat/ubi/ubi9:9.4 --scan
      wimi api.tar --base ubi9.tar --vuln-report trivy.json --app-name "Payments team build"

    credentials are read from `docker login` / `podman login`, or WIMI_USERNAME / WIMI_PASSWORD.
""")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wimi", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG,
        description="What's In My Image: trace every package, library and program in a container image back to "
                    "the base image or build step that put it there, and produce an executive-ready report.")
    p.add_argument("image", help="image to analyse (see image sources below)")
    p.add_argument("--base", action="append", default=[], metavar="[NAME=]IMAGE",
                   help="base image the target was built FROM (repeat for a chain, e.g. Iron Bank Python and UBI)")
    p.add_argument("--app-name", default="Application build (your team)",
                   help="label for the layers added on top of the base (default: %(default)s)")
    p.add_argument("--no-auto-base", action="store_true",
                   help="do not try the base image recorded in the image's own annotations")
    g = p.add_argument_group("vulnerabilities (optional)")
    g.add_argument("--scan", nargs="?", const="auto", choices=["auto", "trivy", "grype"],
                   help="run Trivy or Grype (if installed) and attribute every finding")
    g.add_argument("--vuln-report", action="append", default=[], type=Path, metavar="FILE",
                   help="import an existing Trivy / Grype / Harbor JSON report")
    g.add_argument("--harbor-vulns", action="store_true",
                   help="download the scan Harbor already ran for this image (Harbor registries only)")
    g = p.add_argument_group("output")
    g.add_argument("-o", "--output-dir", type=Path, default=Path("wimi-reports"))
    g.add_argument("--formats", default="html,json,csv", help="comma list of html,json,csv (default: %(default)s)")
    g.add_argument("-q", "--quiet", action="store_true", help="only print the final summary")
    g = p.add_argument_group("registry access")
    g.add_argument("--platform", default="linux/amd64", help="platform for multi-arch images (default: %(default)s)")
    g.add_argument("--username", default=os.environ.get("WIMI_USERNAME"))
    g.add_argument("--password-stdin", action="store_true", help="read the registry password from stdin")
    g.add_argument("--insecure", action="store_true", help="skip TLS verification (self-signed Harbor)")
    g.add_argument("--ca-cert", help="CA bundle for registries using an internal certificate authority (e.g. DoD PKI)")
    g.add_argument("--plain-http", action="store_true", help="use http:// instead of https://")
    g.add_argument("--cache-dir", type=Path, default=Path(os.environ.get("WIMI_CACHE",
                                                                         Path.home() / ".cache" / "whats-in-my-image")))
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _safe_name(name: str) -> str:
    tail = name.rsplit("/", 1)[-1]
    return re.sub(r"[^A-Za-z0-9._-]+", "_", tail).strip("_")[:80] or "image"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "scan":
        argv = argv[1:]
    args = _parser().parse_args(argv)
    log = (lambda *a, **k: None) if args.quiet else (lambda msg: print(msg, file=sys.stderr, flush=True))

    password = os.environ.get("WIMI_PASSWORD")
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    target_opts = dict(username=args.username, password=password, insecure=args.insecure,
                       ca_cert=args.ca_cert, plain_http=args.plain_http)
    common = dict(platform=args.platform, cache_dir=args.cache_dir, log=log)

    try:
        image = load_image(args.image, **common, **target_opts)
    except SourceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    target_registry = image.registry_client.ref.registry if image.registry_client else None

    # ---- base images: only their configs (layer digests) are needed, not their content
    base_specs = []
    for spec in args.base:
        name, sep, ref = spec.partition("=")
        base_specs.append((name.strip(), ref.strip()) if sep and ref else ("", spec))
    auto = image.annotations.get("org.opencontainers.image.base.name") or \
        image.labels.get("org.opencontainers.image.base.name")
    if not base_specs and auto and not args.no_auto_base:
        log(f"Image records its base as {auto}; checking it")
        base_specs.append(("", auto))
    bases = []
    for name, ref in base_specs:
        try:
            opts = dict(target_opts)
            if target_registry and not ref.startswith(target_registry + "/"):
                opts.update(username=None, password=None)  # never send one registry's password to another
            b = load_image(ref, **common, fetch_layers=False, **opts)
            bases.append({"ref": ref, "label": name or base_label(ref), "diff_ids": b.diff_ids})
        except SourceError as e:
            print(f"warning: could not load base image {ref}: {e}", file=sys.stderr)

    # ---- walk layers, attribute, analyse
    log(f"Analysing {image.name} ({len(image.layers)} layers)")
    walker = Walker()
    walker.scan(image, log)
    history, _ = image.layer_history()
    origins, per_layer, notes = compute_origins(image.diff_ids, bases, history, image.labels, args.app_name)
    analyzer = Analyzer(image, walker, origins, per_layer)
    analyzer.run()

    # ---- vulnerabilities
    found_vulns = None
    tool = ""
    diff_index = {d: i for i, d in enumerate(image.diff_ids)}
    for path in args.vuln_report:
        try:
            found_vulns = (found_vulns or []) + vulnmod.load_report(path, diff_index)
            tool = tool or f"imported report ({path.name})"
        except (OSError, ValueError) as e:
            print(f"warning: could not read {path}: {e}", file=sys.stderr)
    if args.harbor_vulns:
        hv = vulnmod.fetch_harbor(image, log)
        if hv is not None:
            found_vulns, tool = (found_vulns or []) + hv, tool or "Harbor scan"
    if args.scan:
        res = vulnmod.run_scanner(args.scan, image, log)
        if res:
            tool, sv = res
            found_vulns = (found_vulns or []) + sv
            tool = tool.capitalize()
    if found_vulns is not None:
        found_vulns = _dedupe(found_vulns)
        vulnmod.attribute(found_vulns, [vars(c) for c in analyzer.components], per_layer)

    model = report.build(image, walker, analyzer, origins, per_layer, notes, found_vulns, tool, args.app_name)

    # ---- write outputs
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stem = args.output_dir / f"provenance-{_safe_name(image.name)}"
    formats = {f.strip().lower() for f in args.formats.split(",")}
    written = []
    if "html" in formats:
        p = stem.with_name(stem.name + ".html")
        p.write_text(html_report.render(model), encoding="utf-8")
        written.append(p)
    if "json" in formats:
        p = stem.with_name(stem.name + ".json")
        p.write_text(json.dumps(model, indent=2, default=str), encoding="utf-8")
        written.append(p)
    if "csv" in formats:
        written.append(_write_csv(stem.with_name(stem.name + "-components.csv"), model))
        if model["vulns"] is not None:
            written.append(_write_vuln_csv(stem.with_name(stem.name + "-vulnerabilities.csv"), model))

    _print_summary(model, written)
    return 0


def _dedupe(vs):
    seen, out = set(), []
    for v in vs:
        key = (v.id, v.package, v.version, v.path)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def _write_csv(path: Path, m: dict) -> Path:
    labels = {o["key"]: o["label"] for o in m["origins"]}
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["component", "version", "type", "supplier", "added_by", "layer", "change", "previous_version",
                    "managed_by", "location", "license", "concerns", "evidence", "purl"])
        for c in m["components"]:
            w.writerow([c["name"], c["version"], c["type_label"], c["supplier"], labels.get(c["origin"], c["origin"]),
                        c["layer"] + 1, c["change"], c["previous_version"], c["managed_by"], "; ".join(c["paths"]),
                        c["license"], "; ".join(f["message"] for f in c["flags"]), "; ".join(c["evidence"]), c["purl"]])
    return path


def _write_vuln_csv(path: Path, m: dict) -> Path:
    labels = {o["key"]: o["label"] for o in m["origins"]}
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "severity", "package", "installed_version", "fixed_version", "introduced_by", "layer",
                    "attribution", "title"])
        for v in m["vulns"]:
            w.writerow([v["id"], v["severity"], v["package"], v["version"], v["fixed_version"],
                        labels.get(v["origin"], v["origin"]), "" if v["layer"] is None else v["layer"] + 1,
                        v["attribution"], v["title"]])
    return path


def _print_summary(m: dict, written: list[Path]) -> None:
    out = sys.stdout
    width = 78
    print("\n" + "=" * width, file=out)
    print(f" {m['image']['name']}", file=out)
    print("=" * width, file=out)
    for o in m["origins"]:
        layers = f"layers {o['layers'][0]}-{o['layers'][-1]}" if len(o["layers"]) > 1 else \
            (f"layer {o['layers'][0]}" if o["layers"] else "")
        vul = f"  {o['vulns_total']:>5} vulns" if m["vulns"] is not None else ""
        print(f" {o['label'][:44]:<44} {layers:<13} {o['components']:>6} comps{vul}", file=out)
    print("-" * width, file=out)
    for t in m["takeaways"]:
        mark = {"good": "+", "bad": "!", "warn": "!", "neutral": "*"}[t["tone"]]
        print(textwrap.fill(t["text"], width, initial_indent=f" {mark} ", subsequent_indent="   "), file=out)
    print("-" * width, file=out)
    for p in written:
        print(f" wrote {p}", file=out)
    print(file=out)
