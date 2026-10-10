#!/usr/bin/env bash
# Local Docker testbed for wimi: a local registry, a set of images covering every ecosystem wimi reads, two demo
# "application" images that trigger findings, a base image catalog, and scanners with their vulnerability databases.
#
#   testbed/testbed.sh            set everything up (safe to re-run; it only fills in what is missing)
#   testbed/testbed.sh scan       run the current checkout's wimi against every testbed target
#   testbed/testbed.sh status     show what is set up
#   testbed/testbed.sh help       list all commands
#
# Everything is labelled or named "wimi-testbed", and generated files go to testbed/.state/ (git-ignored).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
STATE="$HERE/.state"
CATALOG="$STATE/catalog.json"
REPORTS="$STATE/reports"
BIN="${WIMI_TESTBED_BIN:-$HOME/.local/bin}"

REGISTRY_NAME="wimi-testbed-registry"
REGISTRY_PORT="${WIMI_TESTBED_PORT:-5000}"
LOCAL="localhost:${REGISTRY_PORT}"
VULNDB_VOLUME="wimi-testbed-vulndb"

# Scanner releases, checksum verified. Same Trivy pin as the CI workflows.
TRIVY_VERSION="0.75.0"
TRIVY_SHA256="c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f"
GRYPE_VERSION="0.120.1"

# Public images, each chosen to exercise a different part of wimi.
PUBLIC_IMAGES=(
  "registry.access.redhat.com/ubi9/ubi-minimal:latest"           # RPM (sqlite database)
  "registry.access.redhat.com/ubi8/ubi-minimal:latest"           # RPM (Berkeley DB)
  "registry.access.redhat.com/ubi9/python-312-minimal:latest"    # base chain: Python on UBI 9 minimal
  "debian:bookworm-slim"                                          # dpkg
  "alpine:3.22"                                                   # apk
  "gcr.io/distroless/python3-debian12:latest"                     # distroless (dpkg status.d)
  "python:3.12-slim-bookworm"                                     # dpkg + pip (the sample report)
  "node:22-alpine"                                                # apk + npm
  "eclipse-temurin:21-jre-alpine"                                 # Java runtime
  "busybox:1.37"                                                  # used by the demo app build
  "registry:3"                                                    # the local registry itself
  "aquasec/trivy:${TRIVY_VERSION}"                                # scanner image (sidecars) + Go binary
  "anchore/grype:v${GRYPE_VERSION}"                               # scanner image (sidecars) + Go binary
)

# Copied into the local registry, so registry pulls can be tested without the internet or credentials.
MIRRORED=(
  "debian:bookworm-slim=library/debian:bookworm-slim"
  "alpine:3.22=library/alpine:3.22"
)

APPS=(rpm-python-app alpine-node-app)

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok() { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*" >&2; }

need_docker() {
  if ! docker info >/dev/null 2>&1; then
    echo "Cannot reach Docker. Is it running, and is $USER in the docker group (then restart WSL)?" >&2
    exit 1
  fi
}

have_image() { docker image inspect "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------------------------------------------ registry

cmd_registry() {
  say "Local registry at $LOCAL"
  if [ "$(docker inspect -f '{{.State.Running}}' "$REGISTRY_NAME" 2>/dev/null)" = "true" ]; then
    ok "already running"
    return
  fi
  if docker inspect "$REGISTRY_NAME" >/dev/null 2>&1; then
    docker start "$REGISTRY_NAME" >/dev/null
  else
    # Bound to 127.0.0.1 only, and restarted with Docker so it is always there for tests.
    have_image registry:3 || docker pull -q registry:3 >/dev/null
    docker run -d --name "$REGISTRY_NAME" --restart unless-stopped \
      -p "127.0.0.1:${REGISTRY_PORT}:5000" -v wimi-testbed-registry:/var/lib/registry \
      --label wimi-testbed=1 registry:3 >/dev/null
  fi
  ok "running (restarts automatically with Docker)"
}

# ------------------------------------------------------------------------------------------------ images

cmd_pull() {
  say "Public test images"
  for ref in "${PUBLIC_IMAGES[@]}"; do
    if have_image "$ref"; then
      ok "$ref"
    else
      docker pull -q "$ref" >/dev/null && ok "$ref (pulled)"
    fi
  done
}

cmd_refresh() {
  say "Re-pulling public test images"
  for ref in "${PUBLIC_IMAGES[@]}"; do
    docker pull -q "$ref" >/dev/null && ok "$ref"
  done
}

cmd_build() {
  say "Demo application images"
  for app in "${APPS[@]}"; do
    docker build -q -t "wimi-testbed/$app:1.0" "$HERE/apps/$app" >/dev/null
    docker tag "wimi-testbed/$app:1.0" "$LOCAL/testbed/$app:1.0"
    docker push -q "$LOCAL/testbed/$app:1.0" >/dev/null
    ok "wimi-testbed/$app:1.0  (also $LOCAL/testbed/$app:1.0)"
  done
  say "Mirroring into the local registry"
  for pair in "${MIRRORED[@]}"; do
    src="${pair%%=*}" dst="$LOCAL/${pair#*=}"
    docker tag "$src" "$dst" && docker push -q "$dst" >/dev/null && ok "$dst"
  done
  say "Archives for the file-based sources"
  mkdir -p "$STATE/archives"
  docker save -o "$STATE/archives/rpm-python-app.tar" wimi-testbed/rpm-python-app:1.0
  chmod 644 "$STATE/archives/rpm-python-app.tar"  # readable by the non-root user in the wimi container
  ok "$STATE/archives/rpm-python-app.tar (docker save)"
}

# ------------------------------------------------------------------------------------------------ catalog

wimi() { (cd "$REPO" && python3 -m whats_in_my_image "$@"); }

cmd_catalog() {
  say "Base image catalog ($CATALOG)"
  mkdir -p "$STATE"
  wimi catalog crawl registry.access.redhat.com/ubi9/ubi-minimal --catalog "$CATALOG" \
    --match '^9\.[0-9]+-[0-9.]+$' --limit 15 --name "UBI 9 minimal" >/dev/null 2>&1
  wimi catalog crawl registry.access.redhat.com/ubi9/python-312-minimal --catalog "$CATALOG" \
    --match '^9\.[0-9]+-[0-9.]+$' --limit 15 --name "UBI 9 Python 3.12 minimal" >/dev/null 2>&1
  wimi catalog add --catalog "$CATALOG" "Node 22 Alpine=node:22-alpine" "Alpine 3.22=alpine:3.22" >/dev/null 2>&1
  ok "$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["images"]))' "$CATALOG") base images catalogued"
}

# ------------------------------------------------------------------------------------------------ scanners

cmd_scanners() {
  say "Scanner binaries in $BIN"
  mkdir -p "$BIN"
  local tmp
  tmp="$(mktemp -d)"
  if [ "$("$BIN/trivy" --version 2>/dev/null | head -1)" = "Version: ${TRIVY_VERSION}" ]; then
    ok "trivy ${TRIVY_VERSION}"
  else
    curl -sSfL -o "$tmp/trivy.tgz" \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
    echo "${TRIVY_SHA256}  $tmp/trivy.tgz" | sha256sum --check --strict --quiet
    tar -xzf "$tmp/trivy.tgz" -C "$BIN" trivy
    ok "trivy ${TRIVY_VERSION} (installed, checksum verified)"
  fi
  if "$BIN/grype" version 2>/dev/null | grep -q "^Version: *${GRYPE_VERSION}$"; then
    ok "grype ${GRYPE_VERSION}"
  else
    local base="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}"
    local asset="grype_${GRYPE_VERSION}_linux_amd64.tar.gz"
    curl -sSfL -o "$tmp/$asset" "$base/$asset"
    curl -sSfL -o "$tmp/checksums.txt" "$base/grype_${GRYPE_VERSION}_checksums.txt"
    (cd "$tmp" && grep " ${asset}\$" checksums.txt | sha256sum --check --strict --quiet)
    tar -xzf "$tmp/$asset" -C "$BIN" grype
    ok "grype ${GRYPE_VERSION} (installed, checksum verified)"
  fi
  rm -rf "$tmp"
  case ":$PATH:" in *":$BIN:"*) ;; *) warn "$BIN is not on PATH; add it so 'wimi --scan' finds the scanners" ;; esac
}

cmd_vulndb() {
  say "Vulnerability databases"
  local db="$STATE/vulndb"
  mkdir -p "$db"
  "$BIN/trivy" image --download-db-only --cache-dir "$db/trivy" --quiet
  ok "Trivy database in $db/trivy"
  GRYPE_DB_CACHE_DIR="$db/grype" "$BIN/grype" db update >/dev/null
  ok "Grype database in $db/grype"
  chmod -R a+rX "$db"
  # The same databases in a volume, for offline ("air-gapped") scans with scanner sidecars.
  docker volume create --label wimi-testbed=1 "$VULNDB_VOLUME" >/dev/null
  docker run --rm -v "$VULNDB_VOLUME:/vulndb" -v "$db:/src:ro" busybox:1.37 \
    sh -c 'rm -rf /vulndb/trivy /vulndb/grype && cp -a /src/trivy /src/grype /vulndb/ && chmod -R a+rX /vulndb'
  ok "copied to volume $VULNDB_VOLUME (mount it read-only at /vulndb)"
}

# ------------------------------------------------------------------------------------------------ scan

# Each target exercises a different image source. Format: label|image|extra wimi options
targets() {
  cat <<EOF
rpm-python-app (registry)|$LOCAL/testbed/rpm-python-app:1.0|--plain-http
alpine-node-app (registry)|$LOCAL/testbed/alpine-node-app:1.0|--plain-http
rpm-python-app (docker save archive)|$STATE/archives/rpm-python-app.tar|
alpine-node-app (local Docker engine)|docker:wimi-testbed/alpine-node-app:1.0|
debian (local registry mirror)|$LOCAL/library/debian:bookworm-slim|--plain-http
ubi8-minimal (Red Hat registry)|registry.access.redhat.com/ubi8/ubi-minimal:latest|
distroless python (gcr.io)|gcr.io/distroless/python3-debian12:latest|
temurin JRE (Docker Hub)|eclipse-temurin:21-jre-alpine|
trivy (Go binaries)|aquasec/trivy:${TRIVY_VERSION}|
EOF
}

cmd_scan() {
  local filter="${1:-}"
  mkdir -p "$REPORTS"
  local env=(TRIVY_CACHE_DIR="$STATE/vulndb/trivy" TRIVY_SKIP_DB_UPDATE=true TRIVY_SKIP_JAVA_DB_UPDATE=true
    GRYPE_DB_CACHE_DIR="$STATE/vulndb/grype" GRYPE_DB_AUTO_UPDATE=false PATH="$BIN:$PATH")
  local passed=0 failed=()
  while IFS='|' read -r label ref extra; do
    [ -n "$filter" ] && [[ "$label" != *"$filter"* ]] && continue
    say "$label"
    # shellcheck disable=SC2086  # $extra holds zero or more options
    if (cd "$REPO" && env "${env[@]}" python3 -m whats_in_my_image "$ref" $extra --catalog "$CATALOG" \
      --scan -o "$REPORTS" -q); then
      passed=$((passed + 1))
    else
      failed+=("$label")
    fi
  done < <(targets)
  say "Reports in $REPORTS"
  ok "$passed target(s) scanned"
  if [ "${#failed[@]}" -gt 0 ]; then
    for f in "${failed[@]}"; do warn "failed: $f"; done
    return 1
  fi
}

# ------------------------------------------------------------------------------------------------ status / clean

cmd_status() {
  say "Testbed status"
  printf '    registry: %s\n' "$(docker ps -a --filter "name=$REGISTRY_NAME" --format '{{.Status}} ({{.Ports}})')"
  printf '    images: %s present of %s public, ' \
    "$(for r in "${PUBLIC_IMAGES[@]}"; do have_image "$r" && echo; done | wc -l)" "${#PUBLIC_IMAGES[@]}"
  printf '%s demo apps\n' "$(for a in "${APPS[@]}"; do have_image "wimi-testbed/$a:1.0" && echo; done | wc -l)"
  printf '    local registry repositories: %s\n' \
    "$(curl -s "http://$LOCAL/v2/_catalog" | python3 -c 'import json,sys;print(", ".join(json.load(sys.stdin)["repositories"]))' 2>/dev/null || echo unreachable)"
  [ -f "$CATALOG" ] && printf '    catalog: %s\n' "$CATALOG" || printf '    catalog: not built\n'
  printf '    trivy: %s, grype: %s\n' \
    "$("$BIN/trivy" --version 2>/dev/null | head -1 | cut -d' ' -f2 || echo missing)" \
    "$("$BIN/grype" version 2>/dev/null | awk '/^Version:/{print $2}' || echo missing)"
  docker volume inspect "$VULNDB_VOLUME" >/dev/null 2>&1 && echo "    vulndb volume: $VULNDB_VOLUME" ||
    echo "    vulndb volume: not created"
}

cmd_clean() {
  say "Removing the testbed (public images are kept; 'docker image prune' removes unused ones)"
  docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 && ok "registry container" || true
  docker volume rm wimi-testbed-registry "$VULNDB_VOLUME" >/dev/null 2>&1 && ok "volumes" || true
  for app in "${APPS[@]}"; do
    docker rmi -f "wimi-testbed/$app:1.0" "$LOCAL/testbed/$app:1.0" >/dev/null 2>&1 || true
  done
  for pair in "${MIRRORED[@]}"; do docker rmi "$LOCAL/${pair#*=}" >/dev/null 2>&1 || true; done
  ok "demo images"
  rm -rf "$STATE"
  ok "$STATE"
}

cmd_all() {
  cmd_registry
  cmd_pull
  cmd_build
  cmd_catalog
  cmd_scanners
  cmd_vulndb
  cmd_status
  say "Ready. Try: testbed/testbed.sh scan"
}

usage() {
  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
  cat <<EOF

Commands:
  all (default)  registry, pull, build, catalog, scanners, vulndb
  registry       start the local registry at $LOCAL
  pull           pull the public test images that are missing
  refresh        re-pull every public test image (newer tags, newer CVEs)
  build          build the demo apps, push them and the mirrors to the local registry
  catalog        build the base image catalog in $CATALOG
  scanners       install pinned, checksum-verified trivy and grype into $BIN
  vulndb         download the vulnerability databases (local dir and the $VULNDB_VOLUME volume)
  scan [FILTER]  run this checkout's wimi on every target (or those whose label contains FILTER)
  status         show what is set up
  clean          remove the registry, volumes, demo images and $STATE
EOF
}

main() {
  local cmd="${1:-all}"
  shift || true
  case "$cmd" in
    help | -h | --help) usage ;;
    all | registry | pull | refresh | build | catalog | scanners | vulndb | scan | status | clean)
      need_docker
      "cmd_$cmd" "$@"
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
