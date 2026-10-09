# Vulnerabilities

`wimi` doesn't scan for vulnerabilities itself. It takes findings from your scanner and matches each one to the traced
component, so every CVE is credited to the party that introduced it, and that can fix it.

## Getting findings in

=== "Run a scanner"

    ```bash
    wimi IMAGE --scan            # Trivy or Grype, whichever is installed
    wimi IMAGE --scan trivy      # or choose one
    ```

=== "Import a report"

    ```bash
    trivy image --format json -o trivy.json IMAGE
    wimi IMAGE --vuln-report trivy.json
    ```

    Trivy, Grype and Harbor JSON reports are accepted. Repeat `--vuln-report` to combine several.
    Use this in pipelines that already run a scanner.

=== "Reuse Harbor's scan"

    ```bash
    wimi harbor.example.com/project/app:1.2 --harbor-vulns
    ```

    Downloads the scan a Harbor registry already ran for this image. Harbor users only.

## What you get

* **Who introduced it:** the base image or the application build. Each finding is matched to the traced component it
  affects. If no component matches, the layer reported by the scanner is used instead, and if there is none the
  finding is shown as *Unattributed* rather than guessed. The report states which method was used for every finding.
* **Severity**, with critical and high findings summarised in the bottom line.
* **Vendor fix status**, read from the scanner (Trivy `Status`, Grype `fix.state`):

| Fix status | Meaning |
| --- | --- |
| Fix available | Updating the package removes the finding. |
| No fix released yet | The vendor has not shipped a fix. |
| Fix deferred | The vendor plans to fix it later. |
| Will not fix | The vendor will not fix it in this release. |
| No longer supported | The package or release is end of life. |
| Under investigation | The vendor has not decided yet. |

"Will not fix", "end of life" and "deferred" findings are raised as their own findings, and the bottom line states
how many vulnerabilities will never be removed by updating and need a risk decision.
