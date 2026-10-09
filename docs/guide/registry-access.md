# Registry access

`wimi` works with any registry that speaks the OCI Distribution API: Iron Bank (registry1.dso.mil), Docker Hub, GHCR,
GitLab, Artifactory, Nexus, Quay, Red Hat, Harbor, and ECR/ACR/GAR (with a token as the password).

## Credentials

Credentials are looked up in this order:

1. `--username` with `--password-stdin`, or the `WIMI_USERNAME` and `WIMI_PASSWORD` environment variables (handy for CI
   service accounts).
2. Saved logins from `docker login` or `podman login`, including credential helpers. The files read are
   `$REGISTRY_AUTH_FILE`, `$DOCKER_CONFIG/config.json`, `~/.docker/config.json`,
   `$XDG_RUNTIME_DIR/containers/auth.json` and `~/.config/containers/auth.json`.

```bash
echo "$TOKEN" | wimi registry.example.mil/team/app:1.2 --username svc-scanner --password-stdin
```

!!! info "Credentials stay with their registry"
    Credentials are only sent to the registry they belong to. If a `--base` image is on a different registry from the
    target, the target's username and password are not sent to it.

## TLS and internal certificate authorities

| Option | Use |
| --- | --- |
| `--ca-cert bundle.pem` | Registries using an internal CA (for example DoD PKI). Preferred. |
| `--insecure` | Skip TLS verification. Lab registries only. |
| `--plain-http` | Use `http://` instead of `https://`. |

## Multi-arch images

Images published as a multi-arch index are resolved to one platform. The default is `linux/amd64`; choose another with
`--platform linux/arm64`.

## Cache

Downloaded layers are cached in `~/.cache/whats-in-my-image`. Change it with `--cache-dir` or the `WIMI_CACHE`
environment variable.
