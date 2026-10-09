# Base image catalog

You don't need to know which base an image was built on, or have its Dockerfile. Catalogue the base images your
organisation uses once, and `wimi` recognises them in any image.

```bash
# Every recent release of a base repository (newest first; --match filters tags by regex)
wimi catalog crawl registry1.dso.mil/ironbank/redhat/ubi/ubi9 --limit 30 --name "Iron Bank UBI 9"
wimi catalog crawl registry.access.redhat.com/ubi9/ubi-minimal --match '^9\.[0-9]+-[0-9.]+$'

# Individual images
wimi catalog add "Iron Bank Python 3.11=registry1.dso.mil/ironbank/opensource/python/python311:3.11"

wimi catalog list
wimi registry.example.mil/team/api:2.4     # no --base needed
```

## Commands

| Command                             | What it does                                                                                                                                      |
|-------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| `wimi catalog add [NAME=]IMAGE ...` | Add one or more images (registry reference, archive or OCI layout).                                                                               |
| `wimi catalog crawl REPOSITORY`     | Add many tags of one repository. `--limit N` keeps the newest N (default 25, `0` for all), `--match REGEX` filters tags, `--name` sets the label. |
| `wimi catalog list`                 | Show the catalogued images.                                                                                                                       |
| `wimi catalog remove PATTERN`       | Remove entries whose reference matches exactly or by regular expression.                                                                          |

All catalog commands accept `--catalog FILE` and the same [registry access](registry-access.md) options as a scan.

## Where the catalog lives

The catalog stores only layer digests (about 0.4 KB per image), never image content, so it is small and safe to share.

* Default: `~/.config/whats-in-my-image/catalog.json` (or under `$XDG_CONFIG_HOME`).
* Override with the `WIMI_CATALOG` environment variable or `--catalog FILE`.

!!! tip "Share one catalog across a team"
    Commit the catalog to a repository (for example `ci/base-catalog.json`) and pass it with `--catalog`, so every
    pipeline and analyst identifies bases the same way.

## What the catalog adds to a report

* **The whole base chain is found**, for example UBI 9, then Iron Bank Python on top of it, even if you name only one
  base or none. A base nobody named can't be miscounted as the application team's work.
* **The exact base release is named**, for example `ubi-minimal:9.7-1778562320`, rather than "some UBI 9". Tags that
  point at identical layers are merged and listed together.
* **Outdated bases are flagged:** "built on a release from May; the catalog knows 33 newer releases". Old base
  releases are a common, easily fixed reason the base appears to have vulnerabilities.

Identification is exact: an image was built on a catalogued base only if its first layers are byte-for-byte identical
to that base's layers.
