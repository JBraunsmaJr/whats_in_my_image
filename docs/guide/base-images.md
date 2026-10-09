# Naming the base image

Attribution starts with one question: **which layers came from the base image?** `wimi` answers it in this order.

1. **`--base` images you name.** Matched by exact layer digest.
2. **The image's own annotation.** If no `--base` is given and the image records
   `org.opencontainers.image.base.name`, that image is checked. Turn this off with `--no-auto-base`.
3. **The [base image catalog](catalog.md).** Every catalogued base in the image's ancestry is found, even ones you did
   not name. Turn this off with `--no-catalog`.
4. **An estimate from build timestamps**, used only when nothing above matched, and always labelled as an estimate.

## Naming bases with `--base`

```bash
wimi registry.example.mil/team/api:2.4 \
     --base "Iron Bank Python 3.11=registry1.dso.mil/ironbank/opensource/python/python311:3.11" \
     --base "Iron Bank UBI 9=registry1.dso.mil/ironbank/redhat/ubi/ubi9:9.4" \
     --app-name "Payments team build"
```

* The format is `[NAME=]IMAGE`. `NAME` is the label shown in the report; without it, a label is derived from the reference.
* Repeat `--base` for a **chain** (for example Iron Bank Python, which is itself built on UBI 9). Order doesn't matter:
  each base claims the layers it shares with the image, shortest base first.
* `--app-name` labels everything above the base. The default is "Application build (your team)".

## How a match is decided

An image was built on a base **only if its first layers are byte-for-byte identical** (same SHA-256 digests) to that
base's layers. There is no fuzzy matching, so the result is proof rather than opinion.

| Result                          | What the report says                                                                                                                                     |
|---------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| All of the base's layers match  | Those layers are credited to the base: *exact layer-digest match*.                                                                                       |
| Only the first few layers match | The image was built from a different tag of that base that shares older layers. Only the shared layers are credited to it: *partial layer-digest match*. |
| No layers match                 | "The image was **NOT** built on ..." The base you named is wrong, or a different version.                                                                |

!!! warning "Base upgrades are credited to the application"
    If the application build upgrades a base package (for example `dnf update openssl`), that version is credited to
    the **application build**, because that is the layer that put it there.

## When no base is known

With no `--base`, no annotation and no catalog match, `wimi` estimates the boundary from the build times in the
image history (a long pause usually marks where the base ended). The origin is labelled "Base image (estimated)"
(or "Iron Bank base (estimated)" when Iron Bank labels are present), and the report recommends re-running with
`--base` for a definitive answer.

`wimi` also warns when the application layers look like they contain **another, unidentified base**, so a base
nobody named is not silently counted as the application team's work.
