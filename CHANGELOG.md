# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Documentation site at https://willj4945.github.io/whats_in_my_image/, built with Material for MkDocs and published
  to GitHub Pages from `main`. The command line reference is generated from `wimi --help`.

### Changed

- README is now a short landing page that links into the documentation site.
- The sample report moved from `docs/index.html` to `docs/sample-report.html`.

## [0.2.0] - 2026-10-02

Identifies base images automatically, explains why vulnerabilities have no fix, and adds a layer cake view.

### Added

- Vendor fix status for every vulnerability, read from the scanner (Trivy `Status`, Grype `fix.state`): fix
  available, no fix released yet, fix deferred, will not fix, no longer supported, under investigation. Shown as a
  chart, a filterable column and a CSV column. New findings for "will not fix", "end of life" and "deferred", and a
  bottom-line statement of how many vulnerabilities will never be removed by updating and need a risk decision.
- Base image catalog (`wimi catalog add | crawl | list | remove`): record the layer digests of the base images you
  use, then any scan identifies its base automatically and exactly, with no `--base` and no Dockerfile needed. The
  whole base chain is found even if `--base` names only part of it, so an unnamed base is never counted as the
  application team's work.
- "Outdated base image" finding when the catalog knows newer releases of the base an image was built on.
- Warning when the application layers look like they contain another, unidentified base image.
- "Layer cake" view in the HTML report: the image drawn as stacked slices, bottom-up in build order, coloured by
  who added each layer, sized by layer size, with the end of the base image marked. Each slice links to its build step.

### Changed

- README and help show the published container image and generic registry examples. Harbor is one optional integration,
  not a requirement.

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
- Licensed under the Apache License 2.0.
- Container image on GHCR, signed with cosign, with SLSA build provenance and CycloneDX SBOMs.

[Unreleased]: https://github.com/willj4945/whats_in_my_image/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/willj4945/whats_in_my_image/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/willj4945/whats_in_my_image/releases/tag/v0.1.0
