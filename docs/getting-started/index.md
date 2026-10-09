# Getting started

`wimi` (What's In My Image) unpacks a container image layer by layer and traces every component to the base image or
the build step that added it. This section takes you from nothing to your first report.

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **[Installation](installation.md)**

    ---

    Install the wheel from a release, run the signed container image, or run from source.

-   :material-rocket-launch:{ .lg .middle } **[Quick start](quickstart.md)**

    ---

    Scan an image, add vulnerability attribution, and read the report.

-   :material-certificate:{ .lg .middle } **[Verifying a release](verify.md)**

    ---

    Check the signatures, build provenance and checksums before you install.

</div>

## Requirements

* Python 3.9 or newer (or any container runtime, to use the published image).
* Network access to the registry that holds your image, or an exported image archive.
* Optional: [Trivy](https://trivy.dev) or [Grype](https://github.com/anchore/grype) to attribute vulnerabilities.

Docker is **not** required. `wimi` talks to registries directly and reads archives and OCI layouts from disk.
