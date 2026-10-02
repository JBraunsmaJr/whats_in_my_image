"""A catalog of known base images, so the base of any image can be identified without being told.

Each entry stores only an image's layer digests (``diff_ids``), never its content, so a catalog of
hundreds of Iron Bank or vendor base images is a few hundred KB of JSON that can be shared across a
team or checked into a repository.

Identification is exact: an image was built on a catalogued base if and only if the image's first
N layers are byte-for-byte identical (same SHA-256 digests) to that base's N layers.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .suppliers import compare_versions


def default_path() -> Path:
    if os.environ.get("WIMI_CATALOG"):
        return Path(os.environ["WIMI_CATALOG"])
    config_home = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return config_home / "whats-in-my-image" / "catalog.json"


class Catalog:
    def __init__(self, path: Path, entries: list[dict] | None = None):
        self.path = path
        self.entries: list[dict] = entries or []

    @classmethod
    def load(cls, path: Path | None = None) -> Catalog:
        path = path or default_path()
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls(path)
        except (OSError, ValueError) as e:
            raise ValueError(f"Could not read the base image catalog {path}: {e}") from None
        return cls(path, [e for e in doc.get("images", []) if e.get("ref") and e.get("diff_ids")])

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        doc = {"version": 1, "images": sorted(self.entries, key=lambda e: e["ref"])}
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    def add(self, ref: str, diff_ids: list[str], *, label: str = "", digest: str = "", created: str = "") -> bool:
        """Add or refresh an entry. Returns True if the entry is new or its layers changed."""
        entry = {
            "ref": ref,
            "label": label,
            "digest": digest,
            "created": created,
            "diff_ids": list(diff_ids),
            "added": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        for i, old in enumerate(self.entries):
            if old["ref"] == ref:
                changed = old["diff_ids"] != entry["diff_ids"]
                entry["label"] = label or old.get("label", "")
                self.entries[i] = entry
                return changed
        self.entries.append(entry)
        return True

    def remove(self, pattern: str) -> int:
        before = len(self.entries)
        self.entries = [e for e in self.entries if not (e["ref"] == pattern or re.search(pattern, e["ref"]))]
        return before - len(self.entries)

    def match(self, diff_ids: list[str]) -> tuple[list[dict], list[dict]]:
        """Return (bases the image was built on, closest related bases).

        The first list holds every catalogued image whose layers are all the first layers of the
        target, shortest first; together they form the base chain. Images with identical layers
        (the same release under several tags) are merged into one entry with ``also`` tags.
        The second list holds images that share leading layers beyond the longest full match but
        diverge after that: usually a newer or older tag of the real base.
        """
        full: dict[tuple, dict] = {}
        partial: dict[tuple, dict] = {}
        for e in self.entries:
            ids = e["diff_ids"]
            prefix = _common_prefix(diff_ids, ids)
            if prefix == 0:
                continue
            if prefix == len(ids):
                key = tuple(ids)
                if key in full:
                    full[key].setdefault("also", []).append(e["ref"])
                else:
                    full[key] = {**e, "prefix": prefix}
            else:
                key = tuple(ids[:prefix])
                cur = partial.get(key)
                if cur is None or _newer(e, cur):
                    partial[key] = {**e, "prefix": prefix}
        chain = sorted(full.values(), key=lambda e: e["prefix"])
        longest = chain[-1]["prefix"] if chain else 0
        near = sorted((p for p in partial.values() if p["prefix"] > longest), key=lambda e: -e["prefix"])
        return chain, near[:1]

    def newer_releases(self, entry: dict) -> list[dict]:
        """Catalogued releases of the same repository built after ``entry``, newest first."""
        repo = _repository(entry["ref"])
        created = entry.get("created") or ""
        if not created:
            return []
        same = [e for e in self.entries if _repository(e["ref"]) == repo and (e.get("created") or "") > created]
        newest: dict[tuple, dict] = {}  # one entry per distinct release, even if tagged several ways
        for e in same:
            newest.setdefault(tuple(e["diff_ids"]), e)
        return sorted(newest.values(), key=lambda e: e["created"], reverse=True)


def _repository(ref: str) -> str:
    ref = ref.split("@", 1)[0]
    head, sep, tail = ref.rpartition(":")
    return head if sep and "/" not in tail else ref


def _common_prefix(a: list[str], b: list[str]) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def _newer(a: dict, b: dict) -> bool:
    if a.get("created") and b.get("created"):
        return a["created"] > b["created"]
    return compare_versions(a["ref"].rsplit(":", 1)[-1], b["ref"].rsplit(":", 1)[-1]) > 0


def pick_tags(tags: list[str], pattern: str | None, limit: int) -> list[str]:
    """Choose which tags of a repository to catalogue: newest-looking first."""
    chosen = [t for t in tags if not t.startswith("sha256-") and not t.endswith((".sig", ".att", ".sbom"))]
    if pattern:
        rx = re.compile(pattern)
        chosen = [t for t in chosen if rx.search(t)]
    ordered = sorted(chosen, key=_TagKey, reverse=True)
    return ordered[:limit] if limit else ordered


class _TagKey:
    def __init__(self, tag: str):
        self.tag = tag

    def __lt__(self, other: _TagKey) -> bool:
        return compare_versions(self.tag, other.tag) < 0
