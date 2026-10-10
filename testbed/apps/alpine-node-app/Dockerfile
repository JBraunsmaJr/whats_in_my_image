# Demo "application team" image for testing wimi: Alpine (apk) plus npm packages with known CVEs.
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

# An OS package added by the application team
RUN apk add --no-cache tini
WORKDIR /app
# Old npm packages with known CVEs, credited to the application build
RUN npm init -y >/dev/null && npm install --no-audit --no-fund lodash@4.17.20 minimist@1.2.5 axios@0.21.1
USER node
ENTRYPOINT ["/sbin/tini", "--", "node"]
