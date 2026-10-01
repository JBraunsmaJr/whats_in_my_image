# What's In My Image (`wimi`)

**Prove where every piece of a container image came from.**

When a scan finds a problem in an image, people often blame "the base image" (often Iron Bank) by default. `wimi`
replaces that assumption with evidence. It unpacks the image layer by layer and traces every OS package, library
and program file to the **base image or the build step that put it there**. It then writes a report that an
executive (CISO/CIO) can read in two minutes and an engineer can act on.

Illustrative terminal summary (the HTML report has the full detail):

```text
==============================================================================
 registry.example.mil/payments/api:2.4
==============================================================================
 Iron Bank base: redhat/ubi/ubi9              layers 1-2       182 comps     41 vulns
 Application build (your team)                layers 3-9       406 comps    212 vulns
------------------------------------------------------------------------------
 * Iron Bank supplied 182 components (31%) and the application build added
   406 components (69%) of the 588 found in this image.
 ! Most critical/high-severity vulnerabilities (38 of 44) were introduced
   after the Iron Bank base, by the application build. ...
```

## Why the answer can be trusted

| Question | How `wimi` answers it | Strength of evidence |
| --- | --- | --- |
| Which layers came from the base image? | Layer SHA-256 digests compared with known base images, found automatically from a [base image catalog](#identifying-the-base-automatically) or given with `--base` | **Cryptographic proof** (identical digest = identical bytes) |
| Who installed each OS package? | The RPM/dpkg/apk database is read at *every* layer, so each package is credited to the layer that installed its current version | Exact |
| Who built and signed each RPM? | Signing key ID from the package's OpenPGP signature, Vendor field, build host | Exact (e.g. `199E2F91FD431D51` = Red Hat release key 2) |
| Which repository did it come from? | dnf/microdnf history database (`ubi-9-baseos-rpms`, `epel`, `@commandline` ...) | Exact, when the history file is present |
| What about pip/npm/Maven/Go libraries? | Their own metadata (`dist-info`, `package.json`, `pom.properties`, Go build info) | Exact |
| What about loose binaries? | Every executable is checked against all package file lists; anything unowned is flagged with its SHA-256 and the build step that added it | Exact as far as the build step |
| Who introduced each CVE? | Each finding from your scanner (Trivy, Grype, or Harbor's built-in scan) is matched to the traced component | Exact when matched (shown per finding) |

If the application build upgrades a base package (for example `dnf update openssl`), that version is credited to the
**application build**, because that is the layer that put it there.

## Install

Requires Python 3.9 or newer. The tool uses **only the standard library**, so it has no dependencies to vet and works
on air-gapped or locked-down hosts. Docker is **not** required.

**From a release (recommended).** Download the wheel from the
[Releases](https://github.com/willj4945/whats_in_my_image/releases) page, verify it (see below), then:

```bash
pip install whats_in_my_image-0.1.0-py3-none-any.whl     # provides the `wimi` command
```

**As a container** from [`ghcr.io/willj4945/whats_in_my_image`](https://github.com/willj4945/whats_in_my_image/pkgs/container/whats_in_my_image)
(built on Red Hat UBI 9, runs as a non-root user, signed with cosign):

```bash
mkdir -p reports
docker run --rm -u "$(id -u):0" -v "$PWD/reports:/out" \
  ghcr.io/willj4945/whats_in_my_image:latest \
  registry.example.mil/team/app:1.2 -o /out
```

The report lands in `./reports`. Pass registry credentials with `-e WIMI_USERNAME -e WIMI_PASSWORD`.

**From source:** `pip install .` or run without installing: `python3 -m whats_in_my_image --help`.

### Verifying a release

Every release is built by GitHub Actions and ships with signed build provenance (SLSA), CycloneDX SBOMs for the
wheel and the image, a cosign signature on the image, and a `SHA256SUMS` file. The exact verification commands,
filled in for that release, are in each release's notes. In general:

```bash
gh attestation verify whats_in_my_image-0.1.0-py3-none-any.whl --repo willj4945/whats_in_my_image
gh attestation verify oci://ghcr.io/willj4945/whats_in_my_image:0.1.0 --repo willj4945/whats_in_my_image
sha256sum --check SHA256SUMS
```

Each release also includes a `wimi` provenance report of its own container image.

## Usage

```bash
# Scan any image in any registry. Known base images are recognised automatically (see the catalog below).
wimi registry.example.mil/team/api:2.4

# Or name the base image(s) yourself. Name them however you like; repeat --base for a chain.
wimi registry.example.mil/team/api:2.4 \
     --base "Iron Bank Python 3.11=registry1.dso.mil/ironbank/opensource/python/python311:3.11" \
     --base "Iron Bank UBI 9=registry1.dso.mil/ironbank/redhat/ubi/ubi9:9.4" \
     --app-name "Payments team build"

# Add vulnerability attribution (pick one)
wimi IMAGE --scan                         # runs Trivy or Grype if installed
wimi IMAGE --vuln-report trivy.json       # imports a Trivy or Grype JSON report from your pipeline
wimi IMAGE --harbor-vulns                 # optional: reuses the scan a Harbor registry already ran

# Other sources
wimi app.tar                              # `docker save` / `podman save` archives
wimi oci:./layout-dir                     # OCI layout directory
wimi docker:myapp:latest                  # local Docker / Podman engine
```

**Credentials** are taken from `docker login` / `podman login`, or from `WIMI_USERNAME` / `WIMI_PASSWORD`
(handy for CI service accounts), or from `--username` plus `--password-stdin`. Credentials are only sent to the
registry they belong to. For internal CAs (for example DoD PKI) use `--ca-cert bundle.pem`. Use `--insecure` only
for lab registries.

### Identifying the base automatically

You don't need to know which base an image was built on, or have its Dockerfile. Catalogue the base images your
organisation uses once, and `wimi` recognises them in any image:

```bash
# Every recent release of a base repository (newest first; --match filters tags by regex)
wimi catalog crawl registry1.dso.mil/ironbank/redhat/ubi/ubi9 --limit 30 --name "Iron Bank UBI 9"
wimi catalog crawl registry.access.redhat.com/ubi9/ubi-minimal --match '^9\.[0-9]+-[0-9.]+$'

# Individual images
wimi catalog add "Iron Bank Python 3.11=registry1.dso.mil/ironbank/opensource/python/python311:3.11"

wimi catalog list
wimi registry.example.mil/team/api:2.4     # no --base needed
```

The catalog stores only layer digests (about 0.4 KB per image), at `~/.config/whats-in-my-image/catalog.json` or
wherever `WIMI_CATALOG` points, so a team can share one file. Identification is exact: an image was built on a
catalogued base only if its first layers are byte-for-byte identical to that base's layers. The catalog also makes
the report more useful:

* **The whole base chain is found**, for example UBI 9, then Iron Bank Python on top of it, even if you name only one
  base or none. A base that nobody named can't be miscounted as the application team's work.
* **The exact base release is named**, for example `ubi-minimal:9.7-1778562320`, rather than "some UBI 9".
* **Outdated bases are flagged:** "built on a release from May; the catalog knows 33 newer releases". Old base
  releases are a common, easily fixed reason the base appears to have vulnerabilities.

If you give a `--base` that doesn't match, the report says so plainly ("The image was NOT built on ..."). If the
application layers look like they contain another base nobody identified (a long pause in build times), the report
warns about that too. With no catalog match and no `--base`, `wimi` estimates the boundary from build timestamps and
marks it as an estimate.

## Output

All files go to `./wimi-reports/` (change with `-o`):

| File | For |
| --- | --- |
| `provenance-<image>.html` | **Executive report.** One self-contained file to email, attach to a ticket, or print to PDF. |
| `provenance-<image>.json` | Full data for automation / dashboards |
| `provenance-<image>-components.csv` | Inventory for spreadsheets: supplier, layer, evidence and concerns for every component |
| `provenance-<image>-vulnerabilities.csv` | Every CVE with the party that introduced it |

The HTML report has these sections:

1. **Bottom line**: plain-English conclusions, each backed by numbers, such as who supplied what share of the
   software, where the critical/high vulnerabilities came from, and who can fix them.
2. **Where the contents came from**: the proof behind each origin, charts of components and vulnerabilities by origin.
3. **How the image was built**: every layer, what it actually added, the recorded build command, and risky practices
   (`curl | sh`, disabled signature/TLS checks, chmod 777 ...).
4. **Findings that need attention**: each finding grouped by owner, so it can be routed to the right team.
5. **Vulnerabilities**: each CVE with severity, fix status, and the party that introduced it (filterable).
6. **Full inventory**: every component with its supplier and the evidence behind that attribution (searchable).
7. **Method & glossary**: how the conclusions were reached, written for non-specialists.

## Running in CI (GitLab example)

```yaml
provenance:
  image:
    name: ghcr.io/willj4945/whats_in_my_image:latest
    entrypoint: [""]
  script:
    - wimi "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA" --catalog ci/base-catalog.json
        --vuln-report trivy.json -o reports
  artifacts:
    paths: [reports/]
  variables:
    WIMI_USERNAME: $CI_REGISTRY_USER
    WIMI_PASSWORD: $CI_REGISTRY_PASSWORD
```

Commit the team's base catalog (`ci/base-catalog.json` here) so every pipeline identifies bases the same way.

## What is supported

* **Registries:** any registry that speaks the OCI Distribution API: Iron Bank (registry1.dso.mil), Docker Hub, GHCR, GitLab, Artifactory, Nexus, Quay, Red Hat, Harbor, ECR/ACR/GAR (with a token as the password). No particular registry is required.
* **Image formats:** Docker v2 and OCI manifests, multi-arch indexes (`--platform`), gzip/zstd/uncompressed layers
* **OS packages:** RPM (sqlite and Berkeley DB, so UBI 7/8/9/10, RHEL, Rocky, Alma, Fedora, Amazon Linux), Debian/Ubuntu (incl. distroless), Alpine/Wolfi
* **Language packages:** Python (pip/wheel/egg), Node.js (npm/yarn), Java (jar/war/ear, incl. Spring Boot fat jars), Go (module list embedded in binaries, Go 1.18+)
* **Vulnerability sources:** Trivy JSON, Grype JSON, or Harbor's own scan results (optional, Harbor users only)

## Limitations

* Attribution is per **layer**. If a team squashes the base and application into a single layer, the boundary cannot be
  proven, and the report will say so.
* Programs compiled from source or copied in without a package manager can only be traced to the build step that
  added them. The report lists each one with its SHA-256 so it can be followed up.
* Supplier information comes from the image's own package metadata. A package signature tells you which key signed
  it; checking that key against your trust policy happens outside this tool.
* Rust, .NET and Ruby dependencies are not yet itemised (their binaries still appear as program files).

## Development

```bash
python3 -m unittest discover -s tests     # offline tests with synthetic images
ruff check . && ruff format --check .     # lint and formatting (ruff 0.16)
bandit -c pyproject.toml -r whats_in_my_image
```

GitHub Actions runs these on every push and pull request, along with tests on Python 3.9 to 3.14, CodeQL,
Trivy, Gitleaks, workflow security checks and OpenSSF Scorecard. Findings appear under the repository's
**Security → Code scanning** tab. See [SECURITY.md](SECURITY.md) for details and for how to report a vulnerability.

### Branch protection

`main` and the release tags are protected by the GitHub rulesets in [.github/rulesets/](.github/rulesets/). To apply
them, open **Settings → Rules → Rulesets → New ruleset → Import a ruleset** and import each file:

| File | Effect |
| --- | --- |
| `main-protection.json` | Changes reach `main` only by pull request, all CI and Security checks must pass on an up-to-date branch, and `main` can't be force-pushed or deleted. Nobody can bypass it. |
| `main-review.json` | Pull requests need one approving review. Repository admins may skip this when merging their own pull request, so a single maintainer isn't locked out. |
| `release-tags.json` | Published `v*` tags can't be moved or deleted, so a signed release always points at the same commit. |

### Cutting a release

1. Update the version in `pyproject.toml` and `whats_in_my_image/__init__.py`, and add a section to `CHANGELOG.md`.
2. Optionally refresh the base image digest in the `Dockerfile`.
3. Commit, then tag and push: `git tag -a v0.2.0 -m "v0.2.0" && git push origin v0.2.0`.

The Release workflow refuses to publish if the tag does not match the package version, or if the image has a
critical vulnerability with a fix available.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
