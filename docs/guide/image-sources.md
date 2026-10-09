# Image sources

`wimi` reads an image from wherever it lives. Docker is not required unless you read from the local Docker engine.

| Source                                | Example                                         | Notes                                                                       |
|---------------------------------------|-------------------------------------------------|-----------------------------------------------------------------------------|
| Any OCI registry                      | `wimi registry.example.mil/team/app:1.2`        | Tags or digests (`@sha256:...`). See [Registry access](registry-access.md). |
| `docker save` / `podman save` archive | `wimi app.tar` or `wimi docker-archive:app.tar` | Any existing file path is treated as an archive.                            |
| OCI archive                           | `wimi oci-archive:app.tar`                      |                                                                             |
| OCI image layout directory            | `wimi oci:./layout-dir`                         | Any existing directory is treated as an OCI layout.                         |
| Local Docker engine                   | `wimi docker:myapp:latest`                      | Exported with `docker save`.                                                |
| Local Podman engine                   | `wimi podman:myapp:latest`                      | Exported with `podman save`.                                                |

Base images given with `--base` (and `wimi catalog add`) accept the same forms, so you can compare an exported
application image with an exported base:

```bash
wimi api.tar --base ubi9.tar --vuln-report trivy.json --app-name "Payments team build"
```

!!! tip "Only the base's layer list is needed"
    For a base image, `wimi` reads only its configuration (the list of layer digests), not its layers. Naming a large
    base adds almost nothing to the download.

## Image formats

* Docker v2 and OCI manifests
* Multi-arch indexes: choose the platform with `--platform` (default `linux/amd64`)
* gzip, zstd and uncompressed layers (zstd needs Python 3.14, or the `zstd` extra on older Python)
