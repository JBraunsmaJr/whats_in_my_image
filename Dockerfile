# Container image for wimi. `docker build -t wimi .` from a clean checkout is all it takes: the first stage
# builds the wheel from source. If dist/ already holds the wheel for this version (the release workflow builds it
# first), that wheel is used instead, so a released image contains exactly the artifact that was signed and attested.
#
# Base: Red Hat UBI 9 + Python 3.12 (minimal), pinned by digest so builds are reproducible.
# Dependabot does not update this pin; refresh it deliberately when cutting a release.
ARG BASE_IMAGE=registry.access.redhat.com/ubi9/python-312-minimal@sha256:bdfae86a800f2a1eb520a69e79e59f9f03ba5368dc54be5caf454dd5c0f382f2

# ---- build the wheel
FROM ${BASE_IMAGE} AS wheel

# Building from source fetches the build backend (setuptools) from a package index. On a disconnected network,
# point it at your mirror: docker build --build-arg PIP_INDEX_URL=https://nexus.example.mil/repository/pypi/simple .
ARG PIP_INDEX_URL
ARG PIP_EXTRA_INDEX_URL
ARG PIP_TRUSTED_HOST

USER 1001
WORKDIR /tmp/src
COPY --chown=1001:0 . .
RUN set -eu; \
    version="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"; \
    mkdir -p /tmp/wheels; \
    if ls "dist/whats_in_my_image-${version}-"*.whl >/dev/null 2>&1; then \
        echo "Using prebuilt wheel for ${version} from dist/"; \
        cp "dist/whats_in_my_image-${version}-"*.whl /tmp/wheels/; \
    else \
        echo "Building wheel ${version} from source"; \
        python3 -m pip wheel --no-cache-dir --no-deps --wheel-dir /tmp/wheels .; \
    fi; \
    ls -l /tmp/wheels

# ---- runtime image: the base plus the wheel, nothing else
FROM ${BASE_IMAGE}

ARG BASE_IMAGE
LABEL org.opencontainers.image.title="What's In My Image" \
      org.opencontainers.image.description="Trace every component of a container image to the base image or build step that put it there" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="${BASE_IMAGE}"

COPY LICENSE NOTICE /licenses/
COPY --from=wheel --chown=1001:0 /tmp/wheels/ /tmp/wheels/
RUN pip install --no-cache-dir --no-index /tmp/wheels/*.whl && rm -rf /tmp/wheels

USER 1001
ENV WIMI_CACHE=/tmp/wimi-cache
ENTRYPOINT ["wimi"]
CMD ["--help"]
