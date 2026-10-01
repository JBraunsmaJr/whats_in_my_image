# Container image for wimi. The release workflow builds the wheel first, then copies it in here,
# so the image contains exactly the artifact that was signed and attested.
#
# Base: Red Hat UBI 9 + Python 3.12 (minimal), pinned by digest so builds are reproducible.
# Dependabot does not update this pin; refresh it deliberately when cutting a release.
ARG BASE_IMAGE=registry.access.redhat.com/ubi9/python-312-minimal@sha256:bdfae86a800f2a1eb520a69e79e59f9f03ba5368dc54be5caf454dd5c0f382f2
FROM ${BASE_IMAGE}

ARG BASE_IMAGE
LABEL org.opencontainers.image.title="What's In My Image" \
      org.opencontainers.image.description="Trace every component of a container image to the base image or build step that put it there" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="${BASE_IMAGE}"

COPY LICENSE NOTICE /licenses/
COPY --chown=1001:0 dist/*.whl /tmp/wheels/
RUN pip install --no-cache-dir --no-index /tmp/wheels/*.whl && rm -rf /tmp/wheels

USER 1001
ENV WIMI_CACHE=/tmp/wimi-cache
ENTRYPOINT ["wimi"]
CMD ["--help"]
