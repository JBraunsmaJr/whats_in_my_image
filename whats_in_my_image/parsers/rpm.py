"""Read the RPM database (Red Hat UBI / RHEL / Rocky / Alma / Fedora / Amazon Linux / SUSE-sqlite).

Supports both on-disk formats used in container images:
  * ``rpmdb.sqlite``  - RHEL 9+/UBI 9+, Fedora 33+
  * ``Packages``      - Berkeley DB hash format, RHEL/UBI 7 and 8

Each package header also carries the OpenPGP signature that the vendor applied
when publishing it. We extract the signing key ID, which is the strongest piece of
evidence of who actually built and shipped a package.
"""

from __future__ import annotations

import sqlite3
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

NAME, VERSION, RELEASE, EPOCH, SUMMARY = 1000, 1001, 1002, 1003, 1004
BUILDTIME, BUILDHOST, VENDOR, LICENSE, PACKAGER, URL, ARCH = 1006, 1007, 1011, 1014, 1015, 1020, 1022
SOURCERPM = 1044
DIRINDEXES, BASENAMES, DIRNAMES = 1116, 1117, 1118
OLDFILENAMES = 1027
# RSAHEADER, DSAHEADER (header-only signatures), SIGPGP, SIGGPG (legacy header+payload signatures)
_SIG_TAGS = (268, 267, 259, 262)
_WANTED = {NAME, VERSION, RELEASE, EPOCH, SUMMARY, BUILDTIME, BUILDHOST, VENDOR, LICENSE, PACKAGER, URL, ARCH,
           SOURCERPM, DIRINDEXES, BASENAMES, DIRNAMES, OLDFILENAMES, *_SIG_TAGS}


@dataclass
class RpmPackage:
    name: str
    version: str
    release: str
    epoch: int | None
    arch: str
    vendor: str = ""
    summary: str = ""
    license: str = ""
    packager: str = ""
    url: str = ""
    buildhost: str = ""
    buildtime: int = 0
    sourcerpm: str = ""
    sig_key_id: str = ""
    files: list[str] = field(default_factory=list)

    @property
    def evr(self) -> str:
        return (f"{self.epoch}:" if self.epoch else "") + f"{self.version}-{self.release}"


# --------------------------------------------------------------------------- header blob

def parse_header(blob: bytes) -> RpmPackage | None:
    if len(blob) < 8:
        return None
    il, dl = struct.unpack_from(">ii", blob, 0)
    if il <= 0 or il > 100000 or 8 + il * 16 + dl > len(blob) + 16:
        return None
    store = 8 + il * 16
    tags: dict[int, object] = {}
    for i in range(il):
        tag, typ, off, cnt = struct.unpack_from(">iiii", blob, 8 + i * 16)
        if tag not in _WANTED:
            continue
        pos = store + off
        try:
            if typ == 4:  # INT32
                tags[tag] = list(struct.unpack_from(f">{cnt}i", blob, pos))
            elif typ == 6:  # STRING
                tags[tag] = blob[pos:blob.index(b"\0", pos)].decode("utf-8", "replace")
            elif typ in (8, 9):  # STRING_ARRAY / I18NSTRING
                out = []
                for _ in range(cnt):
                    end = blob.index(b"\0", pos)
                    out.append(blob[pos:end].decode("utf-8", "replace"))
                    pos = end + 1
                tags[tag] = out if typ == 8 else (out[0] if out else "")
            elif typ == 7:  # BIN
                tags[tag] = blob[pos:pos + cnt]
        except (ValueError, struct.error):
            continue
    name = tags.get(NAME)
    if not isinstance(name, str):
        return None

    def s(tag):
        v = tags.get(tag, "")
        return v if isinstance(v, str) else (v[0] if isinstance(v, list) and v and isinstance(v[0], str) else "")

    epoch = tags.get(EPOCH)
    pkg = RpmPackage(
        name=name, version=s(VERSION), release=s(RELEASE),
        epoch=epoch[0] if isinstance(epoch, list) and epoch else None,
        arch=s(ARCH) or "noarch", vendor=s(VENDOR), summary=s(SUMMARY), license=s(LICENSE),
        packager=s(PACKAGER), url=s(URL), buildhost=s(BUILDHOST), sourcerpm=s(SOURCERPM),
        buildtime=(tags.get(BUILDTIME) or [0])[0] if isinstance(tags.get(BUILDTIME), list) else 0,
    )
    for st in _SIG_TAGS:
        sig = tags.get(st)
        if isinstance(sig, (bytes, bytearray)):
            kid = pgp_issuer_key_id(bytes(sig))
            if kid:
                pkg.sig_key_id = kid
                break
    base, dirs, idx = tags.get(BASENAMES), tags.get(DIRNAMES), tags.get(DIRINDEXES)
    if isinstance(base, list) and isinstance(dirs, list) and isinstance(idx, list):
        pkg.files = [dirs[i] + b for b, i in zip(base, idx) if 0 <= i < len(dirs)]
    elif isinstance(tags.get(OLDFILENAMES), list):
        pkg.files = list(tags[OLDFILENAMES])
    return pkg


def pgp_issuer_key_id(data: bytes) -> str:
    """Return the 16-hex-digit issuer key ID of an OpenPGP signature packet ('' if unknown)."""
    try:
        b = data[0]
        if not b & 0x80:
            return ""
        if b & 0x40:  # new format
            l1 = data[1]
            if l1 < 192:
                start = 2
            elif l1 < 224:
                start = 3
            elif l1 == 255:
                start = 6
            else:
                return ""
        else:
            start = 1 + {0: 1, 1: 2, 2: 4}.get(b & 3, 0)
        body = data[start:]
        ver = body[0]
        if ver in (2, 3):
            return body[7:15].hex()
        if ver == 4:
            hlen = struct.unpack_from(">H", body, 4)[0]
            hashed = body[6:6 + hlen]
            ulen = struct.unpack_from(">H", body, 6 + hlen)[0]
            unhashed = body[8 + hlen:8 + hlen + ulen]
            for sub in (hashed, unhashed):
                kid = _subpacket_issuer(sub)
                if kid:
                    return kid
    except (IndexError, struct.error):
        pass
    return ""


def _subpacket_issuer(buf: bytes) -> str:
    i = 0
    fpr = ""
    while i < len(buf):
        l1 = buf[i]
        if l1 < 192:
            ln, i = l1, i + 1
        elif l1 < 255:
            ln, i = ((l1 - 192) << 8) + buf[i + 1] + 192, i + 2
        else:
            ln, i = struct.unpack_from(">I", buf, i + 1)[0], i + 5
        if ln == 0:
            break
        typ = buf[i] & 0x7F
        content = buf[i + 1:i + ln]
        if typ == 16 and len(content) >= 8:
            return content[:8].hex()
        if typ == 33 and len(content) >= 21:
            fpr = content[-8:].hex()
        i += ln
    return fpr


# --------------------------------------------------------------------------- database formats

def read_sqlite(db: bytes, wal: bytes | None = None) -> list[RpmPackage]:
    with tempfile.TemporaryDirectory(prefix="wimi-rpm-") as d:
        p = Path(d) / "rpmdb.sqlite"
        p.write_bytes(db)
        if wal:
            (Path(d) / "rpmdb.sqlite-wal").write_bytes(wal)
        con = sqlite3.connect(str(p))
        try:
            rows = con.execute("SELECT blob FROM Packages").fetchall()
        finally:
            con.close()
    return [pkg for (blob,) in rows if blob and (pkg := parse_header(bytes(blob)))]


def read_bdb(data: bytes) -> list[RpmPackage]:
    """Extract package headers from a Berkeley DB 'hash' database (rpm <= 4.15)."""
    if len(data) < 512:
        return []
    for endian in ("<", ">"):
        if struct.unpack_from(endian + "I", data, 12)[0] == 0x061561:
            break
    else:
        return []
    pagesize = struct.unpack_from(endian + "I", data, 20)[0]
    last = struct.unpack_from(endian + "I", data, 32)[0]
    if pagesize < 512 or pagesize > 65536:
        return []
    npages = min(last + 1, len(data) // pagesize)
    out = []
    for pg in range(1, npages):
        base = pg * pagesize
        ptype = data[base + 25]
        if ptype not in (2, 13):  # P_HASH_UNSORTED, P_HASH
            continue
        entries = struct.unpack_from(endian + "H", data, base + 20)[0]
        for e in range(1, entries, 2):  # odd entries are values
            off = struct.unpack_from(endian + "H", data, base + 26 + e * 2)[0]
            item = base + off
            if data[item] != 3:  # H_OFFPAGE
                continue
            ovpg, tlen = struct.unpack_from(endian + "II", data, item + 4)
            blob = _overflow(data, ovpg, tlen, pagesize, endian)
            if blob and (pkg := parse_header(blob)):
                out.append(pkg)
    return out


def _overflow(data: bytes, pg: int, total: int, pagesize: int, endian: str) -> bytes:
    chunks, got, seen = [], 0, set()
    while pg and got < total and pg not in seen:
        seen.add(pg)
        base = pg * pagesize
        if base + 26 > len(data) or data[base + 25] != 7:  # P_OVERFLOW
            return b""
        nxt = struct.unpack_from(endian + "I", data, base + 16)[0]
        used = struct.unpack_from(endian + "H", data, base + 22)[0]
        chunks.append(data[base + 26:base + 26 + used])
        got += used
        pg = nxt
    return b"".join(chunks)[:total]


# --------------------------------------------------------------------------- dnf history

def read_dnf_history(db: bytes, wal: bytes | None = None) -> dict[tuple[str, str, str], str]:
    """Map (name, version-release, arch) -> repository id the package was installed from."""
    with tempfile.TemporaryDirectory(prefix="wimi-dnf-") as d:
        p = Path(d) / "history.sqlite"
        p.write_bytes(db)
        if wal:
            (Path(d) / "history.sqlite-wal").write_bytes(wal)
        con = sqlite3.connect(str(p))
        try:
            rows = con.execute(
                "SELECT rpm.name, rpm.version, rpm.release, rpm.arch, repo.repoid "
                "FROM trans_item JOIN rpm ON trans_item.item_id = rpm.item_id "
                "JOIN repo ON trans_item.repo_id = repo.id ORDER BY trans_item.id").fetchall()
        except sqlite3.DatabaseError:
            rows = []
        finally:
            con.close()
    out = {}
    for name, ver, rel, arch, repo in rows:
        if repo and repo != "@System":
            out[(name, f"{ver}-{rel}", arch)] = repo
    return out
