# Local testbed

`testbed/testbed.sh` sets up a Docker environment for trying `wimi` against real images: a local registry, images that
cover every ecosystem `wimi` reads, two demo "application" images built to trigger findings, a base image catalog, and
pinned scanners with their vulnerability databases.

```bash
testbed/testbed.sh            # set everything up (about 3 minutes the first time; safe to re-run)
testbed/testbed.sh scan       # run this checkout's wimi against every target
testbed/testbed.sh scan rpm   # only targets whose label contains "rpm"
testbed/testbed.sh status
```

It needs Docker with BuildKit (on Ubuntu or WSL: `docker.io` and `docker-buildx`), and your user in the `docker`
group. Reports, the catalog, archives and databases go to `testbed/.state/`, which git ignores.

## What it sets up

| Piece          | Details                                                                                                                                                                                                                                                          |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Local registry | `registry:3` at `localhost:5000`, bound to 127.0.0.1 and restarted with Docker. Use `--plain-http` to reach it.                                                                                                                                                  |
| Public images  | UBI 9 and UBI 8 minimal (RPM sqlite and Berkeley DB), UBI 9 Python (a base chain), Debian slim, Alpine, distroless Python, `python:3.12-slim`, Node Alpine (npm), Temurin JRE (Java), and the Trivy and Grype images (Go binaries, and scanner sidecars).        |
| Demo apps      | `rpm-python-app`: an older UBI 9 Python base, an added RPM, old pip packages with CVEs, an unowned binary, `curl \| sh` and `chmod 777`. `alpine-node-app`: Node Alpine with an added apk and old npm packages with CVEs. Both are pushed to the local registry. |
| Catalog        | The newest 15 releases of UBI 9 minimal and of UBI 9 Python 3.12 minimal, plus Node 22 Alpine and Alpine 3.22, so base chains and outdated bases are identified.                                                                                                 |
| Scanners       | Trivy and Grype at pinned versions, checksum verified, in `~/.local/bin`.                                                                                                                                                                                        |
| Databases      | Trivy and Grype databases in `testbed/.state/vulndb`, and copied into the `wimi-testbed-vulndb` volume for offline scanner sidecar tests.                                                                                                                        |

## Scan targets

`scan` covers each way `wimi` can read an image:

| Target                              | Source                                 |
|-------------------------------------|----------------------------------------|
| `rpm-python-app`, `alpine-node-app` | Local registry                         |
| `rpm-python-app`                    | `docker save` archive                  |
| `alpine-node-app`                   | Local Docker engine (`docker:` prefix) |
| Debian slim                         | Mirror in the local registry           |
| UBI 8 minimal                       | Red Hat registry                       |
| Distroless Python                   | gcr.io                                 |
| Temurin JRE, Trivy                  | Docker Hub                             |

## Other commands

| Command                         | Does                                                                                     |
|---------------------------------|------------------------------------------------------------------------------------------|
| `refresh`                       | Re-pull every public image, to pick up new releases and new CVEs.                        |
| `build`                         | Rebuild the demo apps and push them, with the mirrors, to the local registry.            |
| `catalog`, `scanners`, `vulndb` | Redo one step.                                                                           |
| `clean`                         | Remove the registry, volumes, demo images and `testbed/.state/`. Public images are kept. |

Set `WIMI_TESTBED_PORT` to use another registry port, and `WIMI_TESTBED_BIN` to install the scanners elsewhere.
