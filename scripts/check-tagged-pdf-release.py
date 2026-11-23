# SPDX-License-Identifier: MIT
"""Exercise the release executable's tagged PDF download over loopback."""

from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import urlopen
import json
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


class OSVProbeHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        if self.path != "api.osv.dev:443":
            self.send_error(403)
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        with self.server.probe_tls.wrap_socket(self.connection, server_side=True) as tunnel:
            tunnel.settimeout(5)
            with tunnel.makefile("rb") as request:
                if request.readline() != b"POST /v1/query HTTP/1.1\r\n":
                    return
                while request.readline() not in (b"\r\n", b""):
                    pass
                tunnel.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}")

    def log_message(self, *_args):
        pass


def wait_until_ready(process, origin, log):
    for _ in range(100):
        if process.poll() is not None:
            break
        try:
            with urlopen(origin + "/", timeout=1) as response:
                if response.status == 200:
                    return
        except URLError:
            time.sleep(0.1)
    raise RuntimeError("Release executable did not start:\n" + log.read_text())


def verify_download(origin, manifest, lang, label, work):
    project = manifest["target_project_id"]
    version = quote(manifest["first_version"], safe="")
    with urlopen(f"{origin}/projects/{project}/sboms/{version}/report?lang={lang}", timeout=30) as response:
        assert response.headers.get_content_type() == "application/pdf"
        assert response.headers["Content-Language"] == lang
        pdf = work / f"report-{lang}.pdf"
        pdf.write_bytes(response.read())
    properties = subprocess.check_output(["pdfinfo", str(pdf)], text=True)
    assert re.search(r"(?m)^Tagged:\s+yes$", properties), properties
    structure = subprocess.check_output(["pdfinfo", "-struct-text", str(pdf)])
    assert b"H1 " in structure and b"Table" in structure and b"TH " in structure
    content = subprocess.check_output(["pdftotext", "-raw", str(pdf), "-"], text=True)
    assert label in content and manifest["search_term"] in content and manifest["first_version"] in content
    print(f"{lang}: tagged download from the release executable")


def main(binary, db, manifest):
    with tempfile.TemporaryDirectory(prefix="exsbom-release-") as directory:
        work = Path(directory)
        cert, key = work / "probe.crt", work / "probe.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=api.osv.dev",
            "-addext", "subjectAltName=DNS:api.osv.dev",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, capture_output=True)
        with socket.socket() as port:
            port.bind(("127.0.0.1", 0))
            app_port = port.getsockname()[1]
        origin = f"http://127.0.0.1:{app_port}"
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        with ThreadingHTTPServer(("127.0.0.1", 0), OSVProbeHandler) as proxy:
            proxy.probe_tls = tls
            server = threading.Thread(target=proxy.serve_forever, daemon=True)
            server.start()
            log = work / "app.log"
            env = {
                "PATH": "", "HOME": directory, "TMPDIR": directory,
                "DB_PATH": str(db), "PORT": str(app_port),
                "BIND_ADDR": "127.0.0.1", "AUTO_OPEN_BROWSER": "false",
                "HTTPS_PROXY": f"http://127.0.0.1:{proxy.server_port}",
                "SSL_CERT_FILE": str(cert),
            }
            try:
                with log.open("w") as output, subprocess.Popen(
                    [str(binary)], env=env, cwd=work, stdout=output, stderr=subprocess.STDOUT,
                ) as process:
                    try:
                        wait_until_ready(process, origin, log)
                        verify_download(origin, manifest, "zh-Hant", "軟體物料清單", work)
                        verify_download(origin, manifest, "en", "Software Bill of Materials", work)
                    finally:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
            finally:
                proxy.shutdown()
                server.join()
    digest = sha256()
    with binary.open("rb") as executable:
        for block in iter(lambda: executable.read(1024 * 1024), b""):
            digest.update(block)
    print("Release executable SHA-256:", digest.hexdigest())


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("Usage: check-tagged-pdf-release.py EXECUTABLE FIXTURE.duckdb MANIFEST.json")
    executable, database, manifest_file = [Path(path).resolve(strict=True) for path in sys.argv[1:]]
    main(executable, database, json.loads(manifest_file.read_text()))
