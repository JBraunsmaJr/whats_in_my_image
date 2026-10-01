"""Minimal Docker / OCI registry client built only on the Python standard library.

Works with Harbor, Iron Bank (registry1.dso.mil), Docker Hub, Quay, Artifactory,
Nexus, GitLab and any other registry that speaks the OCI Distribution API.
Having no third-party dependencies keeps the tool usable on locked-down and
air-gapped analyst workstations.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)


class RegistryError(Exception):
    """A registry problem explained in words an operator can act on."""


@dataclass(frozen=True)
class ImageRef:
    registry: str
    repository: str
    tag: str | None = None
    digest: str | None = None

    @property
    def api_host(self) -> str:
        return "registry-1.docker.io" if self.registry == "docker.io" else self.registry

    @property
    def reference(self) -> str:
        return self.digest or self.tag or "latest"

    def __str__(self) -> str:
        s = f"{self.registry}/{self.repository}"
        if self.tag:
            s += f":{self.tag}"
        if self.digest:
            s += f"@{self.digest}"
        return s


def parse_ref(ref: str) -> ImageRef:
    """Parse ``[registry/]repo[:tag][@digest]`` the same way the docker CLI does."""
    ref = ref.strip()
    for prefix in ("docker://", "https://", "http://"):
        if ref.startswith(prefix):
            ref = ref[len(prefix) :]
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
        if not re.fullmatch(r"[a-z0-9]+:[a-fA-F0-9]{32,}", digest):
            raise RegistryError(f"Invalid digest in image reference: {digest}")
    first, sep, rest = ref.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        registry, remainder = first, rest
    else:
        registry, remainder = "docker.io", ref
    tag = None
    last = remainder.rsplit("/", 1)[-1]
    if ":" in last:
        remainder, tag = remainder.rsplit(":", 1)
    if registry in ("docker.io", "index.docker.io", "registry-1.docker.io"):
        registry = "docker.io"
        if "/" not in remainder:
            remainder = "library/" + remainder
    if not remainder:
        raise RegistryError(f"Could not understand image reference {ref!r}")
    if not tag and not digest:
        tag = "latest"
    return ImageRef(registry, remainder, tag, digest)


# --------------------------------------------------------------------------- credentials


def _auth_files() -> list[Path]:
    files = []
    if os.environ.get("REGISTRY_AUTH_FILE"):
        files.append(Path(os.environ["REGISTRY_AUTH_FILE"]))
    if os.environ.get("DOCKER_CONFIG"):
        files.append(Path(os.environ["DOCKER_CONFIG"]) / "config.json")
    files.append(Path.home() / ".docker" / "config.json")
    if os.environ.get("XDG_RUNTIME_DIR"):
        files.append(Path(os.environ["XDG_RUNTIME_DIR"]) / "containers" / "auth.json")
    files.append(Path.home() / ".config" / "containers" / "auth.json")
    return files


def find_credentials(registry: str) -> tuple[str, str] | None:
    """Look up saved credentials from `docker login` / `podman login`."""
    keys = {registry, f"https://{registry}", f"http://{registry}", f"https://{registry}/v1/", f"https://{registry}/v2/"}
    if registry == "docker.io":
        keys |= {"https://index.docker.io/v1/", "index.docker.io", "registry-1.docker.io"}
    for f in _auth_files():
        try:
            cfg = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        for key, entry in (cfg.get("auths") or {}).items():
            if key in keys or key.rstrip("/") in keys:
                if entry.get("auth"):
                    user, _, pw = base64.b64decode(entry["auth"]).decode().partition(":")
                    return user, pw
                if entry.get("username"):
                    return entry["username"], entry.get("password", "")
        store = (cfg.get("credHelpers") or {}).get(registry) or cfg.get("credsStore")
        if store:
            creds = _cred_helper(store, registry)
            if creds:
                return creds
    return None


def _cred_helper(store: str, registry: str) -> tuple[str, str] | None:
    exe = shutil.which(f"docker-credential-{store}")
    if not exe:
        return None
    servers = [registry, f"https://{registry}"]
    if registry == "docker.io":
        servers.append("https://index.docker.io/v1/")
    for server in servers:
        try:
            # fixed argv, no shell; exe is a docker-credential-* helper found on PATH
            out = subprocess.run(  # nosec B603
                [exe, "get"], input=server, capture_output=True, text=True, timeout=30
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if out.returncode == 0:
            try:
                d = json.loads(out.stdout)
                return d["Username"], d["Secret"]
            except (ValueError, KeyError):
                pass
    return None


# --------------------------------------------------------------------------- HTTP


class _StripAuthRedirect(urllib.request.HTTPRedirectHandler):
    """Blob downloads often redirect to S3/CDN; those reject our registry token."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(req.full_url).netloc:
            new.remove_header("Authorization")
        return new


def _explain_http(code: int, url: str, body: str) -> str:
    hints = {
        401: "authentication failed - check the username/password or robot account",
        403: "access denied - the account cannot pull this repository",
        404: "not found - check the repository name and tag",
        429: "rate limited by the registry - wait or log in",
    }
    return f"Registry returned HTTP {code} for {url}: {hints.get(code, body.strip()[:300])}"


def make_ssl_context(insecure: bool = False, ca_cert: str | None = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_cert) if ca_cert else ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class RegistryClient:
    def __init__(
        self,
        ref: ImageRef,
        *,
        username: str | None = None,
        password: str | None = None,
        insecure: bool = False,
        ca_cert: str | None = None,
        plain_http: bool = False,
        timeout: int = 120,
    ):
        self.ref = ref
        if username is None:
            found = find_credentials(ref.registry)
            if found:
                username, password = found
        self.username, self.password = username, password
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=make_ssl_context(insecure, ca_cert)), _StripAuthRedirect()
        )
        self._scheme = "http" if plain_http else "https"
        self._auth: str | None = None
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return f"{self._scheme}://{self.ref.api_host}/v2/{self.ref.repository}/{path}"

    def _basic(self) -> str | None:
        if self.username is None:
            return None
        raw = f"{self.username}:{self.password or ''}".encode()
        return "Basic " + base64.b64encode(raw).decode()

    def _open(self, url: str, accept: str | None = None):
        for attempt in range(2):
            req = urllib.request.Request(url)
            if accept:
                req.add_header("Accept", accept)
            if self._auth:
                req.add_header("Authorization", self._auth)
            try:
                return self._opener.open(req, timeout=self.timeout)
            except urllib.error.HTTPError as e:
                if e.code == 401 and attempt == 0:
                    challenge = e.headers.get("WWW-Authenticate", "")
                    e.close()
                    self._authenticate(challenge)
                    continue
                body = e.read(500).decode(errors="replace")
                e.close()
                raise RegistryError(_explain_http(e.code, url, body)) from None
            except urllib.error.URLError as e:
                raise RegistryError(f"Could not reach {url}: {e.reason}") from None
        raise RegistryError(f"Authentication to {self.ref.registry} failed")

    def _authenticate(self, challenge: str) -> None:
        scheme, _, rest = challenge.partition(" ")
        params = dict(re.findall(r'(\w+)="([^"]*)"', rest))
        basic = self._basic()
        if scheme.lower() == "basic":
            if not basic:
                raise RegistryError(
                    f"{self.ref.registry} requires a login. Run `docker login {self.ref.registry}` "
                    "or pass --username / --password-stdin."
                )
            self._auth = basic
            return
        if scheme.lower() != "bearer" or "realm" not in params:
            raise RegistryError(f"Unsupported authentication challenge from registry: {challenge!r}")
        query = {}
        if params.get("service"):
            query["service"] = params["service"]
        query["scope"] = params.get("scope") or f"repository:{self.ref.repository}:pull"
        realm = params["realm"]
        url = realm + ("&" if "?" in realm else "?") + urllib.parse.urlencode(query)
        req = urllib.request.Request(url)
        if basic:
            req.add_header("Authorization", basic)
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                data = json.load(r)
        except urllib.error.HTTPError as e:
            hint = "" if basic else " (no credentials were found - run `docker login` or pass --username)"
            raise RegistryError(f"Login to {self.ref.registry} failed with HTTP {e.code}{hint}") from None
        except urllib.error.URLError as e:
            raise RegistryError(f"Could not reach the token service {realm}: {e.reason}") from None
        token = data.get("token") or data.get("access_token")
        if not token:
            raise RegistryError("The registry token service returned no token")
        self._auth = "Bearer " + token

    # ---- API

    def get_manifest(self, reference: str) -> tuple[dict, str, str]:
        with self._open(self._url(f"manifests/{reference}"), accept=MANIFEST_ACCEPT) as r:
            body = r.read()
            ctype = r.headers.get("Content-Type", "").split(";")[0].strip()
            digest = r.headers.get("Docker-Content-Digest") or "sha256:" + hashlib.sha256(body).hexdigest()
        doc = json.loads(body)
        return doc, doc.get("mediaType") or ctype, digest

    def resolve(self, platform: str) -> tuple[dict, bytes, str, str | None]:
        """Return (manifest, raw config bytes, manifest digest, index digest)."""
        doc, mtype, digest = self.get_manifest(self.ref.reference)
        index_digest = None
        if mtype in INDEX_TYPES or "manifests" in doc:
            index_digest = digest
            chosen = pick_platform(doc["manifests"], platform)
            doc, mtype, digest = self.get_manifest(chosen["digest"])
        if doc.get("schemaVersion") == 1:
            raise RegistryError("This image uses the obsolete Docker schema 1 format, which is not supported")
        config = self.read_blob(doc["config"]["digest"])
        return doc, config, digest, index_digest

    def read_blob(self, digest: str) -> bytes:
        with self._open(self._url(f"blobs/{digest}")) as r:
            return r.read()

    def fetch_blob(self, digest: str, dest: Path, progress=None) -> Path:
        if dest.exists():
            return dest  # written atomically after verification
        dest.parent.mkdir(parents=True, exist_ok=True)
        algo, _, expected = digest.partition(":")
        tmp = dest.with_name(dest.name + ".part")
        for _attempt in range(3):  # CDNs occasionally cut a transfer short
            h = hashlib.new(algo)
            done = 0
            try:
                with self._open(self._url(f"blobs/{digest}")) as r, open(tmp, "wb") as f:
                    while chunk := r.read(1 << 20):
                        h.update(chunk)
                        f.write(chunk)
                        done += len(chunk)
                        if progress:
                            progress(done)
            except (OSError, http.client.HTTPException):
                pass
            if h.hexdigest() == expected:
                tmp.replace(dest)
                return dest
        tmp.unlink(missing_ok=True)
        raise RegistryError(
            f"Integrity check failed for layer {digest} after 3 attempts - the download was corrupted or tampered with"
        )

    def get_json(self, url: str) -> dict:
        """GET an arbitrary JSON URL on the same host with basic auth (used for the Harbor API)."""
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        if self._basic():
            req.add_header("Authorization", self._basic())
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise RegistryError(_explain_http(e.code, url, e.read(300).decode(errors="replace"))) from None
        except urllib.error.URLError as e:
            raise RegistryError(f"Could not reach {url}: {e.reason}") from None


def pick_platform(manifests: list[dict], platform: str) -> dict:
    os_, _, arch = platform.partition("/")
    arch, _, variant = arch.partition("/")
    for m in manifests:
        p = m.get("platform") or {}
        if p.get("os") == os_ and p.get("architecture") == arch and (not variant or p.get("variant") == variant):
            return m
    real = [m for m in manifests if (m.get("platform") or {}).get("os") != "unknown"]
    if len(real) == 1:
        return real[0]
    available = sorted(
        {f"{m['platform'].get('os')}/{m['platform'].get('architecture')}" for m in real if m.get("platform")}
    )
    raise RegistryError(f"Image has no {platform} variant. Available: {', '.join(available)}. Use --platform.")
