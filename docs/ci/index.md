# CI/CD

Run `wimi` after your image is built and pushed, so every build gets a provenance report alongside its scan.
The published container image works on any runner that can run containers, and the wheel works anywhere Python 3.9+
is available.

<div class="grid cards" markdown>

-   :simple-gitlab:{ .lg .middle } **[GitLab CI](gitlab.md)**

    ---

    A job that uses the `wimi` image directly, with GitLab registry credentials.

-   :simple-githubactions:{ .lg .middle } **[GitHub Actions](github-actions.md)**

    ---

    A workflow job that scans an image in GHCR and uploads the report.

</div>

## Recommendations for any pipeline

* **Commit a shared base catalog** (for example `ci/base-catalog.json`) and pass it with `--catalog`, so every pipeline
  identifies bases the same way. See [Base image catalog](../guide/catalog.md).
* **Reuse your scanner's output.** If the pipeline already runs Trivy or Grype, save its JSON and pass it with
  `--vuln-report` instead of scanning twice.
* **Pin the `wimi` image** to a version tag or digest, and [verify it](../getting-started/verify.md) when you upgrade.
* **Keep the reports** as pipeline artifacts. The HTML file is self-contained, so it can be opened straight from the
  artifact browser or attached to a change ticket.
* Use a **read-only registry token** for `WIMI_USERNAME` / `WIMI_PASSWORD`. `wimi` only ever pulls.
