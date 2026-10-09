# Demo "application team" image for testing wimi. It deliberately does things wimi should flag.
# Built on Red Hat's Python image, which is itself built on UBI 9 minimal, so the catalog can find a base chain.
# The base is pinned to an older release so the "outdated base image" finding has something to report.
FROM registry.access.redhat.com/ubi9/python-312-minimal@sha256:bdfae86a800f2a1eb520a69e79e59f9f03ba5368dc54be5caf454dd5c0f382f2

USER 0
# An OS package added by the application team (credited to the application build, not the base)
RUN microdnf install -y --nodocs jq && microdnf clean all
# Old library versions with known CVEs, so vulnerability attribution has findings to credit to the application
RUN pip install --no-cache-dir requests==2.31.0 urllib3==1.26.18 jinja2==3.1.2
# A program no package manager installed (flagged as an unowned binary with its SHA-256)
COPY --from=busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e /bin/busybox /usr/local/bin/busybox
# Risky build steps (harmless here): piping a download into a shell, and a world-writable directory
RUN curl -fsSL file:///etc/os-release | sh -c 'cat > /dev/null'
RUN mkdir -p /srv/data && chmod 777 /srv/data
USER 1001
