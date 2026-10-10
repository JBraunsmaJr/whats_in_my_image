# Limitations

`wimi` reports what it can prove and says plainly when it can't.

Attribution is per layer
:   If a team squashes the base and application into a single layer, the boundary cannot be proven, and the report
    will say so.

Programs installed without a package manager
:   Programs compiled from source or copied in without a package manager can only be traced to the build step that
    added them. The report lists each one with its SHA-256 so it can be followed up.

Supplier information comes from the image
:   Supplier details are read from the image's own package metadata. A package signature tells you which key signed
    it; checking that key against your trust policy happens outside this tool.

Ecosystems not yet itemized
:   Rust, .NET and Ruby dependencies are not yet itemized. Their binaries still appear as program files.

Estimated base boundary
:   With no `--base`, annotation or catalog match, the base boundary is estimated from build times and labeled as an
    estimate. See [Naming the base image](../guide/base-images.md#when-no-base-is-known).
