"""Scanner selection and sidecar containers, tested against a fake container engine API on a Unix socket.

No Docker needed: the fake engine records what wimi asks for (the container spec, the uploaded archive, removals)
and plays the scanner's part by producing a canned report.
"""

from __future__ import annotations

import io
import json
import os
import socketserver
import tarfile
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest import mock

from whats_in_my_image import engine as eng
from whats_in_my_image import report, scanners

TRIVY_DOC = {
    "SchemaVersion": 2,
    "Trivy": {"Version": "0.75.0"},
    "Results": [
        {
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2099-0001",
                    "PkgName": "busybox",
                    "InstalledVersion": "1.0",
                    "Severity": "HIGH",
                }
            ]
        }
    ],
}


def _tar(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class FakeEngine(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str):
        super().__init__(path, Handler)
        self.images: dict[str, dict] = {}  # ref or id -> inspect data
        self.self_container: dict | None = None
        self.stale: list[dict] = []
        self.requests: list[str] = []
        self.created: dict[str, dict] = {}
        self.uploads: dict[str, bytes] = {}
        self.removed: list[str] = []
        self.exit_code = 0
        self.result: bytes = json.dumps(TRIVY_DOC).encode()

    def add_image(self, image_id: str, tags: list[str], created: int, labels: dict | None = None) -> None:
        info = {
            "Id": image_id,
            "RepoTags": tags,
            "RepoDigests": [],
            "Created": created,
            "Config": {"Labels": labels or {}},
        }
        self.images[image_id] = info
        for t in tags:
            self.images[t] = info


class Handler(BaseHTTPRequestHandler):
    server: FakeEngine

    def log_message(self, *args):  # the client address of a Unix socket is not a tuple
        pass

    def _send(self, status: int, body: bytes = b"", ctype: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        self._send(status, json.dumps(obj).encode())

    def _route(self, method: str) -> None:
        url = urllib.parse.urlsplit(self.path)
        path, q = urllib.parse.unquote(url.path), dict(urllib.parse.parse_qsl(url.query))
        srv = self.server
        srv.requests.append(f"{method} {path}")
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if path == "/_ping":
            return self._send(200, b"OK", "text/plain")
        if method == "GET" and path == "/images/json":
            want = json.loads(q["filters"])["reference"][0]
            seen, out = set(), []
            for info in srv.images.values():
                if info["Id"] not in seen and any(t.rsplit(":", 1)[0] == want for t in info["RepoTags"]):
                    seen.add(info["Id"])
                    out.append({"Id": info["Id"], "RepoTags": info["RepoTags"], "Created": info["Created"]})
            return self._json(200, out)
        if method == "GET" and path.startswith("/images/") and path.endswith("/json"):
            info = srv.images.get(path[len("/images/") : -len("/json")])
            return self._json(200, info) if info else self._json(404, {"message": "No such image"})
        if method == "GET" and path == "/containers/json":
            return self._json(200, srv.stale)
        if method == "POST" and path == "/containers/create":
            cid = f"c{len(srv.created) + 1:063d}"
            srv.created[cid] = json.loads(body)
            return self._json(201, {"Id": cid})
        parts = path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "containers":
            cid, action = parts[1], (parts[2] if len(parts) > 2 else "")
            if method == "GET" and action == "json":
                if srv.self_container and cid in ("self", srv.self_container["Id"]):
                    return self._json(200, srv.self_container)
                return self._json(404, {"message": "No such container"})
            if method == "PUT" and action == "archive":
                srv.uploads[cid] = body
                return self._send(200)
            if method == "POST" and action == "start":
                return self._send(204)
            if method == "POST" and action == "wait":
                return self._json(200, {"StatusCode": srv.exit_code})
            if method == "GET" and action == "archive":
                if srv.exit_code:
                    return self._json(404, {"message": "no such file"})
                return self._send(200, _tar("result.json", srv.result), "application/x-tar")
            if method == "GET" and action == "logs":
                msg = b"\x1b[31mERROR\x1b[0m failed to load vulnerability db: database does not exist\n"
                return self._send(200, b"\x02\0\0\0" + len(msg).to_bytes(4, "big") + msg, "application/octet-stream")
            if method == "DELETE":
                srv.removed.append(cid)
                return self._send(204)
        self._json(404, {"message": f"unexpected {method} {path}"})

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")


class SidecarTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sock = os.path.join(self.tmp.name, "engine.sock")
        self.engine = FakeEngine(self.sock)
        threading.Thread(target=self.engine.serve_forever, daemon=True).start()
        self.addCleanup(self.engine.server_close)
        self.addCleanup(self.engine.shutdown)
        self.env = mock.patch.dict(os.environ, {"DOCKER_HOST": f"unix://{self.sock}"}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        # no scanner binaries on PATH unless a test says so
        p = mock.patch.object(scanners.shutil, "which", return_value=None)
        p.start()
        self.addCleanup(p.stop)
        self.archive_bytes = b"pretend docker-archive " * 100
        self.logs: list[str] = []

    def write_archive(self, path: Path) -> Path:
        path.write_bytes(self.archive_bytes)
        return path

    def run_scan(self, which="auto"):
        return scanners.run(which, self.write_archive, self.logs.append)

    def in_container(self, mounts: list[dict]):
        self.engine.self_container = {"Id": "a" * 64, "Mounts": mounts}
        for target, value in ((eng, "in_container"), (eng, "own_container_ids")):
            p = mock.patch.object(target, value, return_value=True if value == "in_container" else ["a" * 64])
            p.start()
            self.addCleanup(p.stop)


class SidecarRuns(SidecarTestCase):
    def test_sidecar_gets_scanner_env_and_shared_db_volume(self):
        self.engine.add_image("sha256:" + "1" * 64, ["registry.local/mirror/trivy:0.75.0"], 100)
        os.environ.update(
            {
                "WIMI_TRIVY_IMAGE": "registry.local/mirror/trivy:0.75.0",
                "TRIVY_CACHE_DIR": "/vulndb/trivy",
                "TRIVY_SKIP_DB_UPDATE": "true",
                "WIMI_PASSWORD": "secret",
                "HTTPS_PROXY": "http://proxy:3128",
                "WIMI_SCANNER_ENV": "HTTPS_PROXY",
            }
        )
        self.in_container(
            [
                {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": True},
                {"Type": "volume", "Name": "vulndb", "Source": "/var/lib/x", "Destination": "/vulndb", "RW": False},
                {"Type": "bind", "Source": "/home/me/reports", "Destination": "/out", "RW": True},
            ]
        )
        res = self.run_scan()
        self.assertIsNotNone(res, self.logs)
        self.assertEqual(res.tool, "trivy")
        self.assertEqual(res.doc["Trivy"]["Version"], "0.75.0")
        self.assertEqual(res.info["mode"], "container")
        self.assertEqual(res.info["image"], "registry.local/mirror/trivy:0.75.0")
        self.assertEqual(res.info["version"], "0.75.0")

        ((cid, spec),) = self.engine.created.items()
        env = dict(e.split("=", 1) for e in spec["Env"])
        self.assertEqual(env["TRIVY_CACHE_DIR"], "/vulndb/trivy")
        self.assertEqual(env["TRIVY_SKIP_DB_UPDATE"], "true")
        self.assertEqual(env["TRIVY_CACHE_BACKEND"], "memory")  # sidecar default
        self.assertEqual(env["HTTPS_PROXY"], "http://proxy:3128")  # named in WIMI_SCANNER_ENV
        self.assertNotIn("WIMI_PASSWORD", env)
        self.assertNotIn("DOCKER_HOST", env)
        host = spec["HostConfig"]
        self.assertEqual(host["CapDrop"], ["ALL"])
        self.assertIn("no-new-privileges", host["SecurityOpt"])
        # only the volume holding the database is shared: never the socket, never the report folder
        self.assertEqual(
            host["Mounts"], [{"Type": "volume", "Source": "vulndb", "Target": "/vulndb", "ReadOnly": True}]
        )
        self.assertEqual(spec["Image"], "sha256:" + "1" * 64)
        self.assertEqual(spec["Cmd"][:3], ["image", "--input", "/wimi-scan/image.tar"])
        self.assertIn("/wimi-scan/result.json", spec["Cmd"])

        with tarfile.open(fileobj=io.BytesIO(self.engine.uploads[cid])) as tf:
            self.assertEqual(tf.getmember("wimi-scan").mode, 0o1777)
            self.assertEqual(tf.extractfile("wimi-scan/image.tar").read(), self.archive_bytes)
        self.assertEqual(self.engine.removed, [cid])

    def test_network_can_be_chosen(self):
        self.engine.add_image("sha256:" + "1" * 64, ["aquasec/trivy:latest"], 1)
        os.environ["WIMI_SCANNER_NETWORK"] = "none"
        self.run_scan("trivy")
        (spec,) = self.engine.created.values()

    def test_untagged_image_name_uses_newest_local_tag(self):
        self.engine.add_image("sha256:" + "1" * 64, ["registry.local/mirror/grype:v0.119.0"], 100)
        self.engine.add_image("sha256:" + "2" * 64, ["registry.local/mirror/grype:v0.120.1"], 200)
        os.environ["WIMI_GRYPE_IMAGE"] = "registry.local/mirror/grype"
        self.engine.result = json.dumps(
            {"matches": [], "descriptor": {"version": "0.120.1", "db": {"status": {"built": "2026-09-30T04:00:00Z"}}}}
        ).encode()
        res = self.run_scan("grype")
        self.assertEqual(res.info["image"], "registry.local/mirror/grype:v0.120.1")
        self.assertEqual(res.info["db_built"], "2026-09-30T04:00:00Z")
        (spec,) = self.engine.created.values()
        self.assertEqual(spec["Image"], "sha256:" + "2" * 64)
        self.assertEqual(spec["Cmd"][0], "docker-archive:/wimi-scan/image.tar")

    def test_comma_list_of_images_first_present_wins(self):
        self.engine.add_image("sha256:" + "3" * 64, ["mirror-b/trivy:1"], 1)
        os.environ["WIMI_TRIVY_IMAGE"] = "mirror-a/trivy:1, mirror-b/trivy:1"
        self.assertEqual(self.run_scan("trivy").info["image"], "mirror-b/trivy:1")

    def test_missing_images_are_skipped_without_pulling(self):
        os.environ["WIMI_TRIVY_IMAGE"] = "registry.local/mirror/trivy:0.75.0"
        self.assertIsNone(self.run_scan())
        self.assertFalse(any("/images/create" in r for r in self.engine.requests))
        self.assertTrue(any("trivy: not installed and no image found locally" in m for m in self.logs))
        self.assertTrue(any("grype: not installed and no image found locally" in m for m in self.logs))
        self.assertTrue(any("set WIMI_GRYPE_IMAGE" in m for m in self.logs))

    def test_failed_scan_reports_scanner_output_and_removes_container(self):
        self.engine.add_image("sha256:" + "1" * 64, ["anchore/grype:latest"], 1)
        self.engine.exit_code = 1
        self.assertIsNone(self.run_scan("grype"))
        failure = next(m for m in self.logs if "container failed" in m)
        self.assertIn("database does not exist", failure)
        self.assertNotIn("\x1b[", failure)
        self.assertTrue(any("GRYPE_DB_AUTO_UPDATE=false" in m for m in self.logs))
        self.assertEqual(len(self.engine.removed), 1)

    def test_stale_sidecars_from_killed_runs_are_removed(self):
        self.engine.stale = [{"Id": "old1", "State": "exited"}, {"Id": "busy", "State": "running"}]
        self.engine.add_image("sha256:" + "1" * 64, ["aquasec/trivy:latest"], 1)
        self.run_scan("trivy")
        self.assertIn("old1", self.engine.removed)
        self.assertNotIn("busy", self.engine.removed)

    def test_path_not_on_a_volume_is_reported(self):
        self.engine.add_image("sha256:" + "1" * 64, ["aquasec/trivy:latest"], 1)
        os.environ["TRIVY_CACHE_DIR"] = "/home/wimi/.cache/trivy"
        self.in_container([{"Type": "volume", "Name": "vulndb", "Destination": "/vulndb", "RW": True}])
        self.run_scan("trivy")
        (spec,) = self.engine.created.values()
        self.assertEqual(spec["HostConfig"]["Mounts"], [])
        expected = "TRIVY_CACHE_DIR=/home/wimi/.cache/trivy is not on a mounted volume"
        self.assertTrue(any(expected in m for m in self.logs))

    def test_mount_override(self):
        self.engine.add_image("sha256:" + "1" * 64, ["aquasec/trivy:latest"], 1)
        os.environ["WIMI_VULNDB_MOUNT"] = "vulndb:/vulndb,/srv/certs:/certs:rw"
        self.run_scan("trivy")
        (spec,) = self.engine.created.values()
        self.assertEqual(
            spec["HostConfig"]["Mounts"],
            [
                {"Type": "volume", "Source": "vulndb", "Target": "/vulndb", "ReadOnly": True},
                {"Type": "bind", "Source": "/srv/certs", "Target": "/certs", "ReadOnly": False},
            ],
        )


class ScannerSelection(SidecarTestCase):
    def test_installed_binary_wins_and_engine_is_not_contacted(self):
        self.engine.add_image("sha256:" + "1" * 64, ["aquasec/trivy:latest"], 1)
        done = mock.Mock(returncode=0, stdout=json.dumps(TRIVY_DOC), stderr="")
        with (
            mock.patch.object(scanners.shutil, "which", return_value="/usr/bin/trivy"),
            mock.patch.object(scanners.subprocess, "run", return_value=done) as run,
        ):
            res = self.run_scan()
        self.assertEqual(res.info["mode"], "binary")
        self.assertEqual(run.call_args[0][0][:2], ["/usr/bin/trivy", "image"])
        self.assertEqual(self.engine.requests, [])

    def test_mode_binary_never_uses_containers(self):
        self.engine.add_image("sha256:" + "1" * 64, ["aquasec/trivy:latest"], 1)
        os.environ["WIMI_SCANNER_MODE"] = "binary"
        self.assertIsNone(self.run_scan())
        self.assertEqual(self.engine.requests, [])

    def test_mode_off_and_invalid_mode(self):
        os.environ["WIMI_SCANNER_MODE"] = "off"
        self.assertIsNone(self.run_scan())
        os.environ["WIMI_SCANNER_MODE"] = "sometimes"
        self.assertIsNone(self.run_scan())
        self.assertTrue(any("WIMI_SCANNER_MODE must be one of" in m for m in self.logs))
        self.assertEqual(self.engine.requests, [])

    def test_no_engine_socket(self):
        os.environ["DOCKER_HOST"] = "tcp://10.0.0.1:2375"
        self.assertIsNone(self.run_scan("trivy"))
        self.assertTrue(any("not a unix:// socket" in m for m in self.logs))


class Helpers(unittest.TestCase):
    def test_tar_stream_length_and_contents(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "image.tar"
            for size in (0, 1, 511, 512, 513, 70000):
                p.write_bytes(b"x" * size)
                stream, length = scanners.tar_stream(p)
                data = b"".join(stream)
                self.assertEqual(len(data), length)
                with tarfile.open(fileobj=io.BytesIO(data)) as tf:
                    self.assertEqual(len(tf.extractfile("wimi-scan/image.tar").read()), size)

    def test_mount_override_rejects_bad_entries(self):
        for bad in ("vulndb", "vulndb:relative", "vulndb:/x:rx"):
            with self.assertRaises(ValueError):
                scanners.parse_mount_override(bad)

    def test_demux_log_frames(self):
        frames = b"\x01\0\0\0\0\0\0\x03out" + b"\x02\0\0\0\0\0\0\x03err"
        self.assertEqual(eng._demux(frames), "outerr")
        self.assertEqual(eng._demux(b"plain tty output"), "plain tty output")

    def test_scan_details_and_source_sentence(self):
        info = report._scan_details(
            {
                "tool": "Trivy",
                "version": "0.75.0",
                "mode": "container",
                "image": "registry.local/trivy:0.75.0",
                "image_digest": "registry.local/trivy@sha256:abcdef0123456789abcdef",
                "db_built": "2000-01-01T00:00:00.123456789Z",
            }
        )
        self.assertEqual(info["db_date"], "2000-01-01")
        self.assertGreater(info["db_age_days"], 9000)
        text = report.scan_source({"vuln_scan": info, "vuln_tool": "Trivy 0.75.0"})
        self.assertIn("container image registry.local/trivy:0.75.0 (sha256:abcdef012345)", text)
        self.assertIn("vulnerability data built 2000-01-01", text)
        self.assertEqual(report.scan_source({"vuln_scan": {}, "vuln_tool": ""}), "imported report")


if __name__ == "__main__":
    unittest.main()
