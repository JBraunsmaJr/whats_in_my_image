# Verifying a release

Every release is built by GitHub Actions and ships with:

* signed **build provenance** (SLSA) for the wheel, the source distribution and the container image,
* **CycloneDX SBOMs** for the wheel and the image,
* a **cosign signature** on the image (keyless, Sigstore),
* a `SHA256SUMS` file,
* a `wimi` provenance report of the release's own container image.

The exact commands, filled in for that release, are in each release's notes. In general:

```bash
gh attestation verify whats_in_my_image-0.3.1-py3-none-any.whl --repo willj4945/whats_in_my_image
gh attestation verify oci://ghcr.io/willj4945/whats_in_my_image:0.3.1 --repo willj4945/whats_in_my_image
sha256sum --check SHA256SUMS
```

`gh attestation` needs GitHub CLI 2.49 or newer. Some Linux distributions package an older one; check with
`gh --version`.

!!! info "Release gate"
    The release workflow refuses to publish if the image has a critical vulnerability with a fix available, or if
    the tag does not match the package version.
