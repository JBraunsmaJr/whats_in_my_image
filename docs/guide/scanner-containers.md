# Scanner containers

`--scan` runs Trivy or Grype against the exact layers `wimi` traced. You don't need the scanner installed: if its
container image is available, `wimi` can run it as a short-lived **sidecar container** instead. This keeps the `wimi`
image small and lets Trivy and Grype be approved, mirrored and updated on their own schedules, which suits
air-gapped networks.

## The short way

With the [`wimi-docker` wrapper](../getting-started/installation.md#the-wimi-docker-wrapper), the engine socket, user
and volumes are set up for you:

```bash
WIMI_SCANNER_PULL=true wimi-docker registry.example.mil/team/app:1.2 --scan
```

An installed `wimi` (from the wheel) needs nothing extra either. It finds the engine socket on the host directly.
The rest of this page explains what happens underneath, and how to set it up by hand for air-gapped networks.

## How a scanner is chosen

For each scanner (Trivy first, then Grype, unless you name one with `--scan trivy` or `--scan grype`):

1. **Installed binary.** If `trivy` / `grype` is on `PATH`, it is used.
2. **Container image.** Otherwise, if a container engine socket is reachable (`/var/run/docker.sock`, a Podman socket,
   or `DOCKER_HOST=unix://...`) and the scanner image is **already present locally**, it runs as a sidecar.
3. **Skipped.** Otherwise that scanner is skipped, and the log says why.

Missing scanner images are never pulled unless you set `WIMI_SCANNER_PULL=true`. Change the order with
`WIMI_SCANNER_MODE`: `auto` (default), `binary` (never use containers), `container`, or `off`.

!!! danger "The engine socket is root on the host"
    Access to the container engine socket is equivalent to root on the host. Mount it only where that is acceptable.
    Otherwise install the scanner binaries, import a report with `--vuln-report`, or set `WIMI_SCANNER_MODE=binary`.
    Kubernetes pods normally have no engine socket, so `--scan` falls back to an installed binary or skips.

## How the sidecar is isolated

* All Linux capabilities are dropped, and `no-new-privileges` is set.
* The image to scan is copied in through the engine API, so no host path is needed for it.
* Only the scanner's own variables (`TRIVY_*` or `GRYPE_*`, plus any you list in `WIMI_SCANNER_ENV`) are passed in.
  The engine socket is never shared with the sidecar.
* It runs on the engine's default network, with optional memory and time limits, and is removed when the scan ends.
  Sidecars left behind by a killed run are cleaned up by the next run once their time limit has passed.

## Choosing the scanner image

By default `wimi` looks for `aquasec/trivy` or `ghcr.io/aquasecurity/trivy`, and `anchore/grype` or
`ghcr.io/anchore/grype`, using the newest tag present locally. If your registry mirrors them under other names:

```bash
-e WIMI_TRIVY_IMAGE=registry.example.mil/mirror/trivy:0.75.0     # exact tag or @sha256 digest
-e WIMI_GRYPE_IMAGE=registry.example.mil/mirror/grype            # no tag: newest local tag of this repository
```

Give several candidates separated by commas; the first one present locally is used.

!!! tip
    Name an exact tag or digest in pipelines, so the report always records a scanner you have approved.

## Air-gapped vulnerability databases

Every `TRIVY_*` variable is passed to the Trivy sidecar and every `GRYPE_*` variable to the Grype sidecar, exactly as
an installed scanner would read them. When one of them names a path, that path is made visible at the same location
inside the sidecar:

* **`wimi` running in a container:** the volume `wimi` has mounted at that path is shared with the sidecar.
* **`wimi` running on the host:** the host path itself is shared.

Shared paths are **read-only**, except the scanner's database directory (`TRIVY_CACHE_DIR` or `GRYPE_DB_CACHE_DIR`),
which stays writable so a connected scanner can download or refresh its database. A volume that is read-only for
`wimi` is always read-only for the sidecar.

!!! warning "Only forward what the scanner image may see"
    Everything passed to a sidecar, including variables listed in `WIMI_SCANNER_ENV` and the files they name, is
    visible to the scanner image. Scanner images usually run as root, so treat them as trusted software.

So the same settings work whether the scanner is a binary or a container. A complete offline example:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock --group-add "$(stat -c %g /var/run/docker.sock)" \
  -v vulndb:/vulndb:ro -v "$PWD/reports:/out" \
  -e WIMI_TRIVY_IMAGE=registry.example.mil/mirror/trivy:0.75.0 \
  -e TRIVY_CACHE_DIR=/vulndb/trivy -e TRIVY_SKIP_DB_UPDATE=true -e TRIVY_SKIP_JAVA_DB_UPDATE=true \
  -e WIMI_GRYPE_IMAGE=registry.example.mil/mirror/grype:v0.120.1 \
  -e GRYPE_DB_CACHE_DIR=/vulndb/grype -e GRYPE_DB_AUTO_UPDATE=false -e GRYPE_DB_VALIDATE_AGE=false \
  -e GRYPE_CHECK_FOR_APP_UPDATE=false \
  ghcr.io/willj4945/whats_in_my_image:latest registry.example.mil/team/app:1.2 --scan -o /out
```

* `--group-add` lets the non-root `wimi` user use the socket.
* The `vulndb` volume holds `trivy/db/` (and `trivy/java-db/` for Java) and `grype/6/`. On a connected machine,
  `trivy image --download-db-only --cache-dir DIR/trivy` (plus `--download-java-db-only`) and `grype db update` with
  `GRYPE_DB_CACHE_DIR=DIR/grype` produce that layout. Copy it across whenever a new database is brought in.
* `GRYPE_DB_VALIDATE_AGE=false` matters: by default Grype refuses a database more than a few days old.
* Trivy's scan cache is kept in memory in a sidecar (`TRIVY_CACHE_BACKEND=memory` unless you set it), so the database
  volume can be read-only.
* The database files must be readable by the scanner image's user. That is usually root with all capabilities dropped,
  so files owned by another user need to be world-readable (`chmod -R a+rX`). Or set `WIMI_SCANNER_USER`.
* If `wimi` can't identify its own container to find its volumes, set `WIMI_CONTAINER_ID`, or name the mounts
  yourself with `WIMI_VULNDB_MOUNT=SOURCE:/path[:ro|rw]`.

## What the report records

The vulnerability section names the scanner and its version, whether it ran as an installed binary or from which
container image (with its digest), and when its vulnerability data was built. If that data is **more than 30 days
old**, the bottom line says so, because vulnerabilities published since then are not in the report.

## Settings

| Variable                               | Default        | Purpose                                                                                                    |
|----------------------------------------|----------------|------------------------------------------------------------------------------------------------------------|
| `WIMI_TRIVY_IMAGE`, `WIMI_GRYPE_IMAGE` | upstream names | Scanner image(s) to use, comma separated.                                                                  |
| `WIMI_SCANNER_MODE`                    | `auto`         | `auto` (binary, then container), `binary`, `container` or `off`.                                           |
| `WIMI_SCANNER_PULL`                    | `false`        | Pull a missing scanner image (credentials from `docker login`).                                            |
| `WIMI_SCANNER_ENV`                     |                | More variables to pass to sidecars, comma separated (for example `SSL_CERT_FILE`).                         |
| `WIMI_VULNDB_MOUNT`                    | detected       | `SOURCE:/path[:ro\|rw]`, comma separated, to mount instead of the detected volumes. Read-only unless `rw`. |
| `WIMI_SCANNER_TIMEOUT`                 | `1800`         | Seconds before a sidecar is stopped.                                                                       |
| `WIMI_SCANNER_MEMORY`                  | none           | Memory limit for a sidecar, for example `512m`, `4g`, `4GiB`.                                              |
| `WIMI_SCANNER_USER`                    | image's user   | User the sidecar runs as, for example `1001:0`.                                                            |
| `WIMI_CONTAINER_ID`                    | detected       | `wimi`'s own container ID, if it can't be detected (used to find its volumes).                             |
