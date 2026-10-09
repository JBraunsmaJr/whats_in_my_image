# Quick start

## 1. Scan an image

Point `wimi` at any image reference. Credentials from `docker login` or `podman login` are used automatically.

```bash
wimi registry.example.mil/team/api:2.4
```

`wimi` downloads the image's layers (no Docker needed), reads the package databases in every layer, and works out
which layers belong to the base image. It prints a short summary and writes the reports to `./wimi-reports/`.

## 2. Tell it about the base image

If the base image is in your [catalog](../guide/catalog.md), or recorded in the image's own annotations, `wimi`
identifies it automatically. Otherwise name it:

```bash
wimi registry.example.mil/team/api:2.4 \
     --base "Iron Bank UBI 9=registry1.dso.mil/ironbank/redhat/ubi/ubi9:9.4" \
     --app-name "Payments team build"
```

!!! note
    With no base given and no catalog match, `wimi` estimates the boundary from layer build times and labels it as
    an estimate in the report. See [Naming the base image](../guide/base-images.md).

## 3. Add vulnerabilities

Pick one:

```bash
wimi IMAGE --scan                      # runs Trivy or Grype if installed
wimi IMAGE --vuln-report trivy.json    # imports a Trivy, Grype or Harbor JSON report
wimi IMAGE --harbor-vulns              # reuses the scan a Harbor registry already ran
```

Each finding is matched to the component it affects, so the report shows who introduced it and who can fix it.

## 4. Read the report

Open `wimi-reports/provenance-<image>.html` in a browser. It starts with the **bottom line**: who supplied what share
of the software, where the critical and high vulnerabilities came from, and who can fix them. Have a look at the
[sample report](../sample-report.html) to see a complete one.

## Where next

* Build a [base image catalog](../guide/catalog.md) so bases are identified with no `--base`.
* Add `wimi` to your pipeline with the [GitLab CI](../ci/gitlab.md) or [GitHub Actions](../ci/github-actions.md) examples.
* Learn [how attribution works](../concepts/how-it-works.md) and why it can be trusted.
