"""MkDocs hook: replace <!-- wimi-help: SUBCOMMAND --> markers with the live `wimi --help` output.

Running the real CLI at build time keeps the command line reference in step with the code.
"""

import os
import re
import subprocess  # nosec B404
import sys
from pathlib import Path

MARKER = re.compile(r"<!-- wimi-help(?::\s*([a-z ]+?))?\s*-->")


def _help(args: str) -> str:
    env = {**os.environ, "COLUMNS": "100"}
    cmd = [sys.executable, "-m", "whats_in_my_image", *args.split(), "--help"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True, env=env).stdout  # nosec B603
    # Defaults that contain the build machine's home directory read better as ~
    return out.replace(str(Path.home()), "~").rstrip()


def on_page_markdown(markdown, **kwargs):
    return MARKER.sub(lambda m: f"```text\n{_help(m.group(1) or '')}\n```", markdown)
