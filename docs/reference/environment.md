# Environment variables

| Variable | Equivalent option | Purpose |
| --- | --- | --- |
| `WIMI_USERNAME` | `--username` | Registry username. |
| `WIMI_PASSWORD` | `--password-stdin` | Registry password or token. |
| `WIMI_CATALOG` | `--catalog` | Path to the [base image catalog](../guide/catalog.md). |
| `WIMI_CACHE` | `--cache-dir` | Where downloaded layers are cached. Default `~/.cache/whats-in-my-image`. |
| `XDG_CONFIG_HOME` | | Changes the default catalog location to `$XDG_CONFIG_HOME/whats-in-my-image/catalog.json`. |
| `REGISTRY_AUTH_FILE`, `DOCKER_CONFIG`, `XDG_RUNTIME_DIR` | | Where saved `docker login` / `podman login` credentials are looked for. See [Registry access](../guide/registry-access.md#credentials). |
