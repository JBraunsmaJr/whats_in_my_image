# Container image for wimi. `docker build -t wimi .` is all it takes: the first stage builds the wheel from the
# source in the build context, so the image always matches the checkout.
#
# The release workflow builds and signs the wheel first and passes --build-arg WHEEL=dist, so the published image
# contains exactly that artifact. Anything already in dist/ is ignored otherwise: an old local build can share the
# version number with newer code.
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
    mkdir -p /tmp/wheels; \
    python3 -m pip wheel --no-cache-dir --no-deps --wheel-dir /tmp/wheels . ;\
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
