# Installation

`wimi` uses **only the Python standard library**, so it has no dependencies to vet and works on air-gapped or
locked-down hosts.

=== "From a release (recommended)"

    Download the wheel from the [Releases](https://github.com/willj4945/whats_in_my_image/releases) page,
    [verify it](verify.md), then install it:

    ```bash
    pip install whats_in_my_image-0.2.0-py3-none-any.whl
    wimi --version
    ```

    This provides the `wimi` command.

=== "Container image"

    The image is published at
    [`ghcr.io/willj4945/whats_in_my_image`](https://github.com/willj4945/whats_in_my_image/pkgs/container/whats_in_my_image).
    It is built on Red Hat UBI 9, runs as a non-root user and is signed with cosign.

    ```bash
    mkdir -p reports
    docker run --rm -u "$(id -u):0" -v "$PWD/reports:/out" \
      ghcr.io/willj4945/whats_in_my_image:latest \
      registry.example.mil/team/app:1.2 -o /out
    ```

    The report lands in `./reports`. Pass registry credentials with `-e WIMI_USERNAME -e WIMI_PASSWORD`.

    !!! tip
        Pin a version tag (for example `:0.2.0`) or a digest rather than `:latest` in pipelines, so every run uses
        the release you verified.

=== "From source"

    ```bash
    git clone https://github.com/willj4945/whats_in_my_image.git
    cd whats_in_my_image
    pip install .                          # installs the `wimi` command
    python3 -m whats_in_my_image --help    # or run without installing
    ```

## Optional extras

| Extra | When you need it |
| --- | --- |
| `zstd` (`pip install "whats-in-my-image[zstd]"`) | Images with zstd-compressed layers, on Python older than 3.14. Python 3.14 reads zstd natively. |
| Trivy or Grype on `PATH` | To run a vulnerability scan with `--scan`. Not needed if you import an existing report. |

## Next steps

Head to the [Quick start](quickstart.md) to run your first scan.
