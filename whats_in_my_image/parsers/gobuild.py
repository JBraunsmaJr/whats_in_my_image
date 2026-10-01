"""Read the dependency list that the Go toolchain embeds in every binary it builds (Go 1.18+)."""

from __future__ import annotations

MAGIC = b"\xff Go buildinf:"


def _uvarint(data: bytes, pos: int) -> tuple[int, int]:
    x = shift = 0
    while True:
        b = data[pos]
        pos += 1
        x |= (b & 0x7F) << shift
        if b < 0x80:
            return x, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint overflow")


def parse(data: bytes) -> dict | None:
    """Return {'go_version', 'path', 'main': (mod, ver), 'deps': [(mod, ver)], 'settings': {}} or None."""
    i = data.find(MAGIC)
    if i < 0 or len(data) < i + 32:
        return None
    flags = data[i + 15]
    if not flags & 2:
        # Pre-1.18 binaries store pointers instead of inline strings.
        return {"go_version": "unknown (built with Go older than 1.18)", "path": "", "main": None,
                "deps": [], "settings": {}, "legacy": True}
    try:
        pos = i + 32
        n, pos = _uvarint(data, pos)
        version = data[pos:pos + n].decode("utf-8", "replace")
        pos += n
        n, pos = _uvarint(data, pos)
        mod = data[pos:pos + n].decode("utf-8", "replace")
    except (IndexError, ValueError):
        return None
    if len(mod) >= 33 and mod[-17] == "\n":
        mod = mod[16:-16]
    else:
        mod = ""
    info = {"go_version": version, "path": "", "main": None, "deps": [], "settings": {}, "legacy": False}
    for line in mod.splitlines():
        parts = line.split("\t")
        kind = parts[0]
        if kind == "path" and len(parts) > 1:
            info["path"] = parts[1]
        elif kind == "mod" and len(parts) > 2:
            info["main"] = (parts[1], parts[2])
        elif kind == "dep" and len(parts) > 2:
            info["deps"].append((parts[1], parts[2]))
        elif kind == "=>" and len(parts) > 2 and info["deps"]:
            info["deps"][-1] = (parts[1], parts[2])  # replace directive
        elif kind == "build" and len(parts) > 1:
            k, _, v = parts[1].partition("=")
            info["settings"][k] = v
    return info
