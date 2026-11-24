# SPDX-License-Identifier: MIT
"""Exercise the release executable's tagged PDF download over loopback."""

from contextlib import contextmanager
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import urlopen
import json
import os
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
                    if "OSV preflight query succeeded" not in log.read_text(encoding="utf-8", errors="replace"):
                        raise RuntimeError("Release executable started without a successful OSV preflight")
                    return
        except URLError:
            time.sleep(0.1)
    raise RuntimeError("Release executable did not start:\n" + log.read_text(encoding="utf-8", errors="replace"))


def verify_download(origin, manifest, lang, label, work):
    project = manifest["target_project_id"]
    version = quote(manifest["first_version"], safe="")
    with urlopen(f"{origin}/projects/{project}/sboms/{version}/report?lang={lang}", timeout=40) as response:
        if (
            response.status != 200
            or response.headers.get_content_type() != "application/pdf"
            or response.headers.get_content_disposition() != "attachment"
            or response.headers["Content-Language"] != lang
        ):
            raise RuntimeError(f"Unexpected report response for {lang}: HTTP {response.status}\n{response.headers}")
        pdf = work / f"report-{lang}.pdf"
        pdf.write_bytes(response.read())
    properties = subprocess.check_output(["pdfinfo", "-enc", "UTF-8", str(pdf)], encoding="utf-8")
    if not re.search(r"(?m)^Tagged:\s+yes$", properties):
        raise RuntimeError(f"Report for {lang} is missing PDF tags:\n{properties}")
    structure = subprocess.check_output(["pdfinfo", "-struct-text", str(pdf)])
    if any(tag not in structure for tag in (b"H1 ", b"Table", b"TH ")):
        raise RuntimeError(f"Report for {lang} is missing headings or table headers")
    content = subprocess.check_output(["pdftotext", "-enc", "UTF-8", "-raw", str(pdf), "-"], encoding="utf-8")
    if any(value not in content for value in (label, manifest["search_term"], manifest["first_version"])):
        raise RuntimeError(f"Report for {lang} is missing the expected searchable text")
    fonts = subprocess.check_output(["pdffonts", str(pdf)], text=True)
    if "NotoSansCJKtc-Bold" not in fonts:
        raise RuntimeError(f"Report for {lang} is missing the embedded bold font:\n{fonts}")
    print(f"{lang}: tagged download from the release executable")


def file_sha256(path):
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_pe(path, log):
    report = subprocess.check_output(["objdump", "-p", str(path)], text=True)
    with log.open("a", encoding="utf-8") as output:
        output.write(report)
    imports = {name.lower() for name in re.findall(r"(?m)^\s*DLL Name:\s*(\S+)", report)}
    no_delay_imports = re.search(r"(?m)^Entry d\s+0+\s+0+\b", report)
    if "file format pei-x86-64" not in report or not imports or not no_delay_imports:
        raise RuntimeError(f"Expected an amd64 Windows executable with regular imports: {path.name}")
    system_libraries = {
        "advapi32", "bcrypt", "bcryptprimitives", "crypt32", "dbghelp", "gdi32", "iphlpapi",
        "kernel32", "msvcrt", "ncrypt", "netapi32", "normaliz", "ntdll", "ole32", "oleaut32",
        "psapi", "rpcrt4", "secur32", "shell32", "shlwapi", "ucrtbase", "user32", "userenv",
        "version", "winhttp", "winmm", "ws2_32", "wtsapi32",
    }
    unknown = sorted(name for name in imports if not (
        name.endswith(".dll") and (
            name[:-4] in system_libraries or re.fullmatch(r"api-ms-win-(?:core|crt)-[a-z0-9-]+", name[:-4])
        )
    ))
    if unknown:
        raise RuntimeError(f"Unexpected Windows DLL imports in {path.name}: {', '.join(unknown)}")


@contextmanager
def osv_environment(work):
    if sys.platform in ("darwin", "win32"):
        # Go uses the OS trust store here, so run the normal public OSV preflight.
        yield {}
    else:
        cert, key = work / "probe.crt", work / "probe.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=api.osv.dev",
            "-addext", "subjectAltName=DNS:api.osv.dev",
            "-keyout", str(key), "-out", str(cert),
        ], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        with ThreadingHTTPServer(("127.0.0.1", 0), OSVProbeHandler) as proxy:
            proxy.probe_tls = tls
            server = threading.Thread(target=proxy.serve_forever, daemon=True)
            server.start()
            try:
                yield {
                    "HTTPS_PROXY": f"http://127.0.0.1:{proxy.server_port}",
                    "SSL_CERT_FILE": str(cert),
                }
            finally:
                proxy.shutdown()
                server.join()


def main(binary, db, manifest, work):
    work.mkdir(parents=True, exist_ok=True)
    log = work / "app.log"
    evidence = {"executable_sha256": file_sha256(binary)}
    if sys.platform == "win32":
        pe_log = work / "windows-pe-imports.log"
        inspect_pe(binary, pe_log)
    with socket.socket() as port:
        port.bind(("127.0.0.1", 0))
        app_port = port.getsockname()[1]
    origin = f"http://127.0.0.1:{app_port}"
    cache_parent = Path(os.environ["LOCALAPPDATA"]) if sys.platform == "win32" else work
    with osv_environment(work) as proxy_env, tempfile.TemporaryDirectory(
        prefix="exsbom-render-", dir=os.environ.get("EX_SBOM_PDF_TEST_TMPDIR", work),
    ) as render_tmp, tempfile.TemporaryDirectory(prefix="exsbom-cache-", dir=cache_parent) as renderer_cache:
        profile = Path(renderer_cache)
        env = {
            "PATH": "", "HOME": str(profile), "TMPDIR": render_tmp,
            "DB_PATH": str(db), "PORT": str(app_port),
            "BIND_ADDR": "127.0.0.1", "AUTO_OPEN_BROWSER": "false",
            **proxy_env,
        }
        if sys.platform == "win32":
            env.update(SystemRoot=os.environ["SystemRoot"], TEMP=render_tmp, TMP=render_tmp, LOCALAPPDATA=renderer_cache)
            cache = profile / "ex-sbom" / "typst"
        elif sys.platform == "darwin":
            cache = profile / "Library" / "Caches" / "ex-sbom" / "typst"
        else:
            cache = profile / ".cache" / "ex-sbom" / "typst"
        cached_typst = "typst-*.exe" if sys.platform == "win32" else "typst-*"
        with log.open("w") as output, subprocess.Popen(
            [str(binary)], env=env, cwd=work, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
        ) as process:
            try:
                wait_until_ready(process, origin, log)
                verify_download(origin, manifest, "zh-Hant", "軟體物料清單", work)
                cached = list(cache.glob(cached_typst))
                if len(cached) != 1:
                    raise RuntimeError(f"Expected one cached Typst executable, found {len(cached)}")
                cached_digest = file_sha256(cached[0])
                expected = "typst-" + cached_digest + (".exe" if sys.platform == "win32" else "")
                if cached[0].name != expected:
                    raise RuntimeError("Cached Typst file name does not match the content SHA-256")
                evidence["typst_sha256"] = cached_digest
                if sys.platform == "win32":
                    inspect_pe(cached[0], pe_log)
                first = cached[0].stat()
                verify_download(origin, manifest, "en", "Software Bill of Materials", work)
                if not os.path.samestat(first, cached[0].stat()):
                    raise RuntimeError("The second report did not reuse the cached Typst executable")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    evidence["reports"] = {
        name: file_sha256(work / name) for name in ("report-en.pdf", "report-zh-Hant.pdf")
    }
    (work / "verified-downloads.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print("Release executable SHA-256:", evidence["executable_sha256"])


if __name__ == "__main__":
    if len(sys.argv) not in (4, 5):
        sys.exit("Usage: check-tagged-pdf-release.py EXECUTABLE FIXTURE.duckdb MANIFEST.json [EVIDENCE_DIR]")
    executable, database, manifest_file = [Path(path).resolve(strict=True) for path in sys.argv[1:4]]
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    if len(sys.argv) == 5:
        main(executable, database, manifest, Path(sys.argv[4]).resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="exsbom-release-") as directory:
            main(executable, database, manifest, Path(directory))
