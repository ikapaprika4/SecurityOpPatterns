"""
The workbench's local HTTP server (standard library only).

Security posture -- this process reads attacker-supplied files and serves a
UI that renders their contents, so:

* binds 127.0.0.1 only, on a random free port;
* every /api call must carry the per-session random token (the page gets it
  embedded; other sites can neither read it nor set the custom header
  without a CORS preflight, which is never granted), and the Host header
  must be this loopback origin (blocks DNS-rebinding);
* uploads are streamed into a private temporary folder under generated
  names -- a dropped "../../x" can't escape it -- and the folder is deleted
  on exit;
* nothing is ever executed or opened; attachments are hashed in memory and
  never written to disk; zip members are only extracted if they are
  evidence (see engine._expand_zip).
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, unquote, urlsplit

from . import __version__
from .engine import analyze_batch, sample_paths
from .export import EXPORTS, filename as export_filename, render as render_export

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
MAX_UPLOAD = 8 * 1024 ** 3                     # per file
IDLE_SHUTDOWN_S = 15 * 60                      # browser mode: no page open, no work
log = logging.getLogger("socworkbench")


class Session:
    def __init__(self):
        self.token = secrets.token_urlsafe(24)
        self.workdir = tempfile.mkdtemp(prefix="socwb-")
        self.lock = threading.RLock()
        self.cases: dict[str, dict] = {}
        self.batches: dict[str, dict] = {}
        self.jobs: dict[str, dict] = {}
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="analysis")
        self.last_ping = time.time()
        self.server: Optional[ThreadingHTTPServer] = None

    # ---- batches & jobs ------------------------------------------------
    def new_batch(self, label: str = "") -> str:
        bid = uuid.uuid4().hex[:10]
        d = os.path.join(self.workdir, "b-" + bid)
        os.makedirs(d, exist_ok=True)
        with self.lock:
            self.batches[bid] = {"id": bid, "dir": d, "files": [], "names": {}, "label": label}
        return bid

    def add_path(self, bid: str, path: str, display: str) -> None:
        with self.lock:
            b = self.batches[bid]
            b["files"].append(path)
            b["names"][path] = display

    def start_job(self, bid: str, label: str = "") -> str:
        jid = uuid.uuid4().hex[:10]
        b = self.batches[bid]
        job = {"id": jid, "batch": bid, "label": label or b.get("label") or "analysis",
               "status": "queued", "messages": [], "cases": [], "skipped": [], "notes": [],
               "error": None, "started": time.time(), "finished": None}
        with self.lock:
            self.jobs[jid] = job

        def progress(msg: str) -> None:
            with self.lock:
                job["messages"].append(msg)
                del job["messages"][:-40]

        def run() -> None:
            job["status"] = "running"
            try:
                out = analyze_batch(list(b["files"]), dict(b["names"]), self.workdir, progress)
                with self.lock:
                    for c in out["cases"]:
                        c["batch"] = bid
                        self.cases[c["id"]] = c
                    job["cases"] = [c["id"] for c in out["cases"]]
                    job["skipped"] = out["skipped"]
                    job["notes"] = out["notes"]
                    job["status"] = "done"
                log.info("job %s (%s): %d file(s) -> %d case(s) [%s], %d skipped, %.2fs",
                         jid, job["label"], len(b["files"]), len(out["cases"]),
                         ", ".join(f"{c['kit']}:{c['verdict'].get('label')}" for c in out["cases"])[:300],
                         len(out["skipped"]), time.time() - job["started"])
                for c in out["cases"]:
                    if c["status"] == "error":
                        log.warning("job %s: %s failed on %s:\n%s", jid, c["kit"], c["title"],
                                    c.get("_trace") or "; ".join(c["notes"]))
            except Exception as exc:  # noqa: BLE001
                job["status"] = "error"
                job["error"] = f"{type(exc).__name__}: {exc}"
                job["trace"] = traceback.format_exc()[-2000:]
                log.error("job %s (%s) failed:\n%s", jid, job["label"], traceback.format_exc())
            finally:
                job["finished"] = time.time()

        self.pool.submit(run)
        return jid

    def analyze_paths(self, paths: list[str], label: str = "") -> Optional[str]:
        """Analyse files already on disk (dropped on the launcher, picked in
        the native dialog) in place -- no copy."""
        paths = [p for p in paths if os.path.exists(p)]
        if not paths:
            return None
        bid = self.new_batch(label)
        for p in paths:
            self.add_path(bid, os.path.abspath(p), os.path.basename(p.rstrip("\\/")) or p)
        return self.start_job(bid, label or ", ".join(os.path.basename(p) for p in paths)[:80])

    def running_jobs(self) -> int:
        with self.lock:
            return sum(1 for j in self.jobs.values() if j["status"] in ("queued", "running"))

    def cleanup(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)
        shutil.rmtree(self.workdir, ignore_errors=True)


def case_summary(c: dict) -> dict:
    return {k: c.get(k) for k in ("id", "kit", "kit_label", "title", "subtitle", "status",
                                  "verdict", "counts", "created", "batch")} | {
        "sources": [s["name"] for s in c.get("sources", [])],
        "n_findings": len(c.get("findings", [])), "n_iocs": len(c.get("iocs", []))}


def _safe_name(name: str) -> str:
    base = re.split(r"[\\/]", name)[-1]
    base = re.sub(r"[^A-Za-z0-9._ ()\-]", "_", base).strip(" .")
    return base[:120] or "file"


# --------------------------------------------------------------------------
# HTTP handler
# --------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    session: Session = None  # type: ignore[assignment]
    server_version = f"SOCWorkbench/{__version__}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):                  # keep the console quiet
        pass

    # ---- plumbing -------------------------------------------------------
    def _send(self, status: int, body: bytes, ctype: str, extra: Optional[dict] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _error(self, status: int, msg: str) -> None:
        self._json({"error": msg}, status)

    def _host_ok(self) -> bool:
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _authorised(self, query: dict) -> bool:
        token = self.headers.get("X-SOCWB-Token") or (query.get("t") or [""])[0]
        return secrets.compare_digest(token, self.session.token)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 10 * 1024 * 1024:
            raise ValueError("request too large")
        raw = self.rfile.read(n) if n else b"{}"
        return json.loads(raw or b"{}")

    def _route(self, method: str):
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        parts = [unquote(p) for p in url.path.strip("/").split("/") if p]
        if not self._host_ok():
            return self._error(HTTPStatus.FORBIDDEN, "bad host")
        if method == "GET" and not parts:
            return self._index()
        if method == "GET" and parts == ["favicon.svg"]:
            return self._send(200, _FAVICON, "image/svg+xml")
        if not parts or parts[0] != "api":
            return self._error(HTTPStatus.NOT_FOUND, "not found")
        if not self._authorised(query):
            return self._error(HTTPStatus.UNAUTHORIZED, "missing or wrong session token")
        try:
            return self._api(method, parts[1:], query)
        except (KeyError, ValueError) as exc:
            return self._error(HTTPStatus.BAD_REQUEST, f"{type(exc).__name__}: {exc}")

    def do_GET(self):
        self._route("GET")

    def do_HEAD(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    # ---- pages ------------------------------------------------------------
    def _index(self):
        with open(os.path.join(WEB_DIR, "index.html"), "rb") as fh:
            page = fh.read().replace(b"__SOCWB_TOKEN__", self.session.token.encode())
        csp = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
               "img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; "
               "form-action 'none'; frame-ancestors 'none'")
        self._send(200, page, "text/html; charset=utf-8", {"Content-Security-Policy": csp})

    # ---- API ---------------------------------------------------------------
    def _api(self, method: str, parts: list[str], query: dict):
        s = self.session
        if parts == ["info"] and method == "GET":
            return self._json({"version": __version__, "token_ok": True,
                               "native_window": bool(os.environ.get("SOCWB_WINDOW")),
                               "evtx_native": os.name == "nt" and bool(shutil.which("wevtutil")),
                               "exports": {k: v[0] for k, v in EXPORTS.items()}})
        if parts == ["ping"]:
            s.last_ping = time.time()
            return self._json({"ok": True, "running": s.running_jobs()})
        if parts == ["batch"] and method == "POST":
            body = self._read_json()
            return self._json({"batch": s.new_batch(str(body.get("label", ""))[:120])})
        if len(parts) == 3 and parts[0] == "batch" and parts[2] == "file" and method == "PUT":
            return self._upload(parts[1], query)
        if len(parts) == 3 and parts[0] == "batch" and parts[2] == "analyze" and method == "POST":
            if parts[1] not in s.batches:
                raise KeyError("unknown batch")
            body = self._read_json()
            return self._json({"job": s.start_job(parts[1], str(body.get("label", ""))[:120])})
        if parts == ["samples"] and method == "POST":
            return self._json({"jobs": self._samples(str(self._read_json().get("kit", "all")))})
        if parts == ["paste"] and method == "POST":
            body = self._read_json()
            text = str(body.get("text", ""))
            if not text.strip():
                raise ValueError("nothing pasted")
            bid = s.new_batch("pasted text")
            name = _safe_name(str(body.get("name") or "pasted.txt"))
            path = os.path.join(s.batches[bid]["dir"], f"0000_{name}")
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
            s.add_path(bid, path, name)
            return self._json({"job": s.start_job(bid, "pasted text")})
        if parts == ["jobs"] and method == "GET":
            with s.lock:
                jobs = sorted(s.jobs.values(), key=lambda j: j["started"])
                return self._json([self._job_view(j) for j in jobs])
        if len(parts) == 2 and parts[0] == "job" and method == "GET":
            with s.lock:
                return self._json(self._job_view(s.jobs[parts[1]]))
        if parts == ["cases"] and method == "GET":
            with s.lock:
                return self._json([case_summary(c) for c in s.cases.values()])
        if parts == ["cases"] and method == "DELETE":
            with s.lock:
                s.cases.clear()
            return self._json({"ok": True})
        if len(parts) == 2 and parts[0] == "case":
            with s.lock:
                case = s.cases[parts[1]]
                if method == "DELETE":
                    del s.cases[parts[1]]
                    return self._json({"ok": True})
                return self._json({k: v for k, v in case.items() if not k.startswith("_")})
        if len(parts) == 4 and parts[0] == "case" and parts[2] == "export" and method == "GET":
            case = s.cases[parts[1]]
            body, ctype = render_export(case, parts[3])
            inline = query.get("inline") == ["1"] and parts[3] == "html"
            disp = "inline" if inline else f'attachment; filename="{export_filename(case, parts[3])}"'
            return self._send(200, body, ctype, {"Content-Disposition": disp})
        if parts == ["shutdown"] and method == "POST":
            self._json({"ok": True})
            threading.Thread(target=s.server.shutdown, daemon=True).start()
            return None
        return self._error(HTTPStatus.NOT_FOUND, "no such endpoint")

    def _job_view(self, j: dict) -> dict:
        view = {k: j.get(k) for k in ("id", "batch", "label", "status", "skipped", "notes", "error")}
        view["message"] = j["messages"][-1] if j["messages"] else ""
        view["cases"] = [case_summary(self.session.cases[c]) for c in j["cases"]
                         if c in self.session.cases]
        view["elapsed"] = round((j["finished"] or time.time()) - j["started"], 2)
        return view

    def _upload(self, bid: str, query: dict):
        s = self.session
        if bid not in s.batches:
            raise KeyError("unknown batch")
        display = (query.get("name") or ["upload"])[0][:300]
        length = int(self.headers.get("Content-Length") or -1)
        if length < 0:
            return self._error(HTTPStatus.LENGTH_REQUIRED, "Content-Length required")
        if length > MAX_UPLOAD:
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "file too large")
        b = s.batches[bid]
        with s.lock:
            n = len(b["files"])
        path = os.path.join(b["dir"], f"{n:04d}_{_safe_name(display)}")
        remaining = length
        with open(path, "wb") as fh:
            while remaining > 0:
                chunk = self.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    break
                fh.write(chunk)
                remaining -= len(chunk)
        if remaining:
            os.remove(path)
            return self._error(HTTPStatus.BAD_REQUEST, "upload interrupted")
        s.add_path(bid, path, display)
        return self._json({"ok": True, "size": length})

    def _samples(self, kit: str) -> list[str]:
        """Bundled samples, one job per scenario so each becomes its own case
        (the evtx scenarios share a host name and would otherwise merge; the
        network logs are one incident across five devices and stay together)."""
        s = self.session
        paths = sample_paths(kit)
        groups: list[list[str]] = []
        nsm = [p for p in paths if os.sep + "nsmkit" + os.sep in p and not p.endswith(".pcap")]
        if nsm:
            groups.append(nsm)
        groups += [[p] for p in paths if p not in nsm]
        return [jid for g in groups if (jid := s.analyze_paths(g, "sample: " + (
            "network logs" if g is nsm else os.path.basename(g[0]))))]


_FAVICON = (b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" '
            b'rx="14" fill="#20242b"/><path d="M32 12l16 6v12c0 11-7 19-16 22-9-3-16-11-16-22V18z" '
            b'fill="none" stroke="#e9e6dd" stroke-width="4" stroke-linejoin="round"/><path d="M25 32l5 5 '
            b'10-11" fill="none" stroke="#dda84e" stroke-width="4" stroke-linecap="round" '
            b'stroke-linejoin="round"/></svg>')


def make_server(port: int = 0) -> tuple[ThreadingHTTPServer, Session]:
    session = Session()
    handler = type("BoundHandler", (Handler,), {"session": session})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    session.server = httpd
    return httpd, session


def url_for(httpd: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{httpd.server_address[1]}/"
