# Developer guide

`wimi` is a pure standard-library Python package. There is nothing to install to work on it beyond Python 3.9+ and the
lint tools.

## Layout

| Path                                            | Contents                                                                     |
|-------------------------------------------------|------------------------------------------------------------------------------|
| `whats_in_my_image/cli.py`                      | Command line, base resolution and output writing.                            |
| `whats_in_my_image/sources.py`, `registry.py`   | Reading images from registries, archives, OCI layouts and local engines.     |
| `whats_in_my_image/walker.py`                   | Walks the layers in build order and snapshots package databases at each one. |
| `whats_in_my_image/parsers/`                    | RPM, Go build info and language ecosystem parsers.                           |
| `whats_in_my_image/analyze.py`                  | Origins, component attribution, supplier evidence and findings.              |
| `whats_in_my_image/catalog.py`                  | The base image catalog.                                                      |
| `whats_in_my_image/vulns.py`                    | Scanner import and vulnerability attribution.                                |
| `whats_in_my_image/report.py`, `html_report.py` | The report model, and the HTML renderer.                                     |
| `tests/`                                        | Offline tests that build synthetic images.                                   |
| `docs/`, `mkdocs.yml`                           | This documentation site.                                                     |

## Checks

```bash
python3 -m unittest discover -s tests     # offline tests with synthetic images
ruff check . && ruff format --check .     # lint and formatting (ruff 0.16)
bandit -c pyproject.toml -r whats_in_my_image
```

GitHub Actions runs these on every push and pull request, along with tests on Python 3.9 to 3.14, CodeQL, Trivy,
Gitleaks, workflow security checks and OpenSSF Scorecard. Findings appear under the repository's
**Security → Code scanning** tab.

## Working on the documentation

The site is built with [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/). The pinned, hash-locked
build dependencies are in `docs/requirements.txt`.

```bash
python3 -m venv .venv-docs
.venv-docs/bin/pip install --require-hashes -r docs/requirements.txt
.venv-docs/bin/mkdocs serve                 # live preview at http://127.0.0.1:8000
.venv-docs/bin/mkdocs build --strict        # what CI runs
```

* The [command line reference](../reference/cli.md) is generated from `wimi --help` by `docs/hooks.py`, so update the
  help text in `cli.py` rather than the page.
* [Security](security.md) and the [Changelog](changelog.md) are included from `SECURITY.md` and `CHANGELOG.md`.
* `docs/sample-report.html` is a real report, linked from the site. Regenerate it when the report changes.
* Every pull request builds the site in strict mode, and merges to `main` publish it to GitHub Pages.

To update the docs dependencies, edit `docs/requirements.in` and regenerate the lock file:

```bash
pip-compile --generate-hashes --strip-extras docs/requirements.in -o docs/requirements.txt
```
