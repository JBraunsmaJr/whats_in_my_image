# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-01

First public release.

### Added

- Trace every component of a container image to the base image or the build step that added it, using exact
  layer-digest matching against one or more base images (`--base`), with a timestamp-based estimate when no base is given.
- OS package attribution for RPM (sqlite and Berkeley DB), Debian/Ubuntu (including distroless) and Alpine/Wolfi,
  tracked layer by layer so upgrades are credited to the layer that made them.
- RPM supplier evidence: signing key ID, vendor, build host, and source repository from dnf history.
- Language packages: Python, npm, Java (including fat jars) and Go modules embedded in binaries.
- Detection of program files that no package manager installed, and of risky build steps such as `curl | sh`
  and disabled signature or TLS checks.
- Vulnerability attribution from Trivy, Grype or Harbor scan results (`--scan`, `--vuln-report`, `--harbor-vulns`).
- Executive HTML report with plain-English conclusions, plus JSON and CSV exports.
- Image sources: any OCI registry (Harbor, Iron Bank, Docker Hub, Red Hat, Quay ...), `docker save` archives,
  OCI layouts, and the local Docker or Podman engine.
- Standard library only, Python 3.9+.
- Container image on GHCR, signed with cosign, with SLSA build provenance and CycloneDX SBOMs.
