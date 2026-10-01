# What's In My Image (`wimi`)

**Prove where every piece of a container image came from.**

When a scan finds a problem in an image, people often blame "the base image" (often Iron Bank) by default. `wimi`
replaces that assumption with evidence. It unpacks the image layer by layer and traces every OS package, library
and program file to the **base image or the build step that put it there**. It then writes a report that an
executive (CISO/CIO) can read in two minutes and an engineer can act on.

Illustrative terminal summary (the HTML report has the full detail):

```text
==============================================================================
 harbor.example.mil/payments/api:2.4
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
| Which layers came from the base image? | Layer SHA-256 digests compared with the base image's digests | **Cryptographic proof** (identical digest = identical bytes) |
| Who installed each OS package? | The RPM/dpkg/apk database is read at *every* layer, so each package is credited to the layer that installed its current version | Exact |
| Who built and signed each RPM? | Signing key ID from the package's OpenPGP signature, Vendor field, build host | Exact (e.g. `199E2F91FD431D51` = Red Hat release key 2) |
| Which repository did it come from? | dnf/microdnf history database (`ubi-9-baseos-rpms`, `epel`, `@commandline` ...) | Exact, when the history file is present |
| What about pip/npm/Maven/Go libraries? | Their own metadata (`dist-info`, `package.json`, `pom.properties`, Go build info) | Exact |
| What about loose binaries? | Every executable is checked against all package file lists; anything unowned is flagged with its SHA-256 and the build step that added it | Exact as far as the build step |
| Who introduced each CVE? | Each finding from Trivy, Grype or Harbor is matched to the traced component | Exact when matched (shown per finding) |

If the application build upgrades a base package (for example `dnf update openssl`), that version is credited to the
**application build**, because that is the layer that put it there.

## Install

Requires Python 3.9 or newer. The tool uses **only the standard library**, so it has no dependencies to vet and works
on air-gapped or locked-down hosts. Docker is **not** required.

```bash
pip install .            # provides the `wimi` command
# or, without installing:
python3 -m whats_in_my_image --help
```

## Usage

```bash
# Image in Harbor, built FROM an Iron Bank image (this is the common case)
wimi harbor.example.mil/team/api:2.4 \
     --base registry1.dso.mil/ironbank/redhat/ubi/ubi9:9.4

# A chain of bases: UBI -> Iron Bank Python -> your app. Name them however you like.
wimi harbor.example.mil/team/api:2.4 \
     --base "Iron Bank Python 3.11=registry1.dso.mil/ironbank/opensource/python/python311:3.11" \
     --base "Iron Bank UBI 9=registry1.dso.mil/ironbank/redhat/ubi/ubi9:9.4" \
     --app-name "Payments team build"

# Add vulnerability attribution (pick one)
wimi IMAGE --base BASE --scan                     # runs Trivy or Grype if installed
wimi IMAGE --base BASE --harbor-vulns             # reuses the scan Harbor already ran
wimi IMAGE --base BASE --vuln-report trivy.json   # imports an existing Trivy/Grype/Harbor JSON

# Other sources
wimi app.tar --base base.tar            # `docker save` / `podman save` archives
wimi oci:./layout-dir                   # OCI layout directory
wimi docker:myapp:latest                # local Docker / Podman engine
```

**Credentials** are taken from `docker login` / `podman login`, or from `WIMI_USERNAME` / `WIMI_PASSWORD`
(useful with Harbor robot accounts in CI), or from `--username` plus `--password-stdin`. Credentials are only sent
to the registry they belong to. For internal CAs (for example DoD PKI) use `--ca-cert bundle.pem`. Use `--insecure`
only for lab registries.

**Use the exact base tag your Dockerfile builds `FROM`.** If the base you give doesn't match, the report says so
plainly ("The image was NOT built on ..."). That is itself a useful finding, because it usually means the
image was built on an older base release. If no base is given, `wimi` estimates the boundary from build timestamps
and marks the result as an estimate.

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
  image: python:3.11-slim
  script:
    - pip install .
    - wimi "$HARBOR/$CI_PROJECT_PATH:$CI_COMMIT_SHORT_SHA" --base "$IRONBANK_BASE" --harbor-vulns -o reports
  artifacts:
    paths: [reports/]
  variables:
    WIMI_USERNAME: $HARBOR_ROBOT_USER
    WIMI_PASSWORD: $HARBOR_ROBOT_TOKEN
```

## What is supported

* **Registries:** Harbor, Iron Bank (registry1.dso.mil), Docker Hub, Quay, Red Hat, GitLab, Artifactory, Nexus, ECR/ACR/GAR (with a token as the password)
* **Image formats:** Docker v2 and OCI manifests, multi-arch indexes (`--platform`), gzip/zstd/uncompressed layers
* **OS packages:** RPM (sqlite and Berkeley DB, so UBI 7/8/9/10, RHEL, Rocky, Alma, Fedora, Amazon Linux), Debian/Ubuntu (incl. distroless), Alpine/Wolfi
* **Language packages:** Python (pip/wheel/egg), Node.js (npm/yarn), Java (jar/war/ear, incl. Spring Boot fat jars), Go (module list embedded in binaries, Go 1.18+)
* **Vulnerability sources:** Trivy JSON, Grype JSON, Harbor vulnerability reports

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
