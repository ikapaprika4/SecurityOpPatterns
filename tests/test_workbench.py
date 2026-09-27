"""
SOC Workbench test suite: evidence recognition, the analysis engine (routing,
grouping, zip/folder expansion, damaged input), exports, and the local HTTP
server's API and security checks.

Run with: python tests/test_workbench.py
"""

from __future__ import annotations

import gzip
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from socworkbench.detect import EVTX, NSM, PHISH, TRAF, sniff  # noqa: E402
from socworkbench.engine import analyze_batch  # noqa: E402
from socworkbench.export import EXPORTS, filename, render  # noqa: E402
from socworkbench.server import make_server  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(ROOT, "samples")


def sample(kit: str, name: str) -> str:
    return os.path.join(SAMPLES, kit, name)


def read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def write(folder: str, name: str, data: bytes) -> str:
    path = os.path.join(folder, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def public(case: dict) -> dict:
    return {k: v for k, v in case.items() if not k.startswith("_")}


BEC = sample("phishkit", "7_bec_wire.eml")
LEGIT = sample("phishkit", "8_legitimate.eml")
MSG = sample("phishkit", "9_m365_expiry.msg")
MBOX = sample("phishkit", "10_campaign.mbox")
HTTP_PCAP = sample("trafkit", "http_traffic.pcapng")
CLEAN_PCAP = sample("trafkit", "clean_baseline.pcapng")
FIN02 = sample("evtxkit", "security_only.jsonl")             # host WIN-FIN02
RDP = sample("evtxkit", "rdp_brute_force.jsonl")             # host WIN-VICTIM01
PERSIST = sample("evtxkit", "persistence.jsonl")             # host WIN-VICTIM01
FIREWALL = sample("nsmkit", "firewall.log")
VPN = sample("nsmkit", "vpn_auth.log")


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="socwb-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


# --------------------------------------------------------------------------
# Evidence recognition
# --------------------------------------------------------------------------

class TestSniff(TempDirCase):
    def test_every_bundled_sample_is_routed_to_its_kit(self):
        for kit in (PHISH, EVTX, NSM, TRAF):
            for name in sorted(os.listdir(os.path.join(SAMPLES, kit))):
                want = TRAF if name.endswith((".pcap", ".pcapng")) else kit
                self.assertEqual(sniff(sample(kit, name)).kit, want, f"{kit}/{name}")

    def test_content_beats_the_extension(self):
        cases = {
            "capture.bin": (read(HTTP_PCAP), TRAF),
            "outlook_saved_as.eml": (read(MSG), PHISH),
            "mail.txt": (read(BEC), PHISH),
            "events.log": (read(FIN02), EVTX),
            "fw_export.txt": (read(FIREWALL), NSM),
        }
        for name, (data, kit) in cases.items():
            self.assertEqual(sniff(write(self.tmp, name, data)).kit, kit, name)
        self.assertEqual(sniff(write(self.tmp, "x.eml", read(MSG))).fmt, "msg")

    def test_gzip_compressed_capture(self):
        s = sniff(write(self.tmp, "cap.pcapng.gz", gzip.compress(read(HTTP_PCAP))))
        self.assertEqual((s.kit, s.fmt), (TRAF, "pcapng.gz"))

    def test_non_evidence_is_rejected_with_a_reason(self):
        from phishkit.msg import _write_cfb
        rejects = {
            "empty.eml": b"",
            "random.bin": bytes(range(256)) * 16,
            "notes.eml": b"Hi team,\nnotes from today's meeting below.\n",
            "report.doc": _write_cfb({"WordDocument": b"\x00" * 600}, {}),
        }
        for name, data in rejects.items():
            s = sniff(write(self.tmp, name, data))
            self.assertIsNone(s.kit, name)
            self.assertTrue(s.reason, name)


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------

REQUIRED = {"id", "kit", "kit_label", "title", "subtitle", "sources", "status", "verdict",
            "counts", "findings", "iocs", "sections", "notes", "exports"}


class TestEngine(TempDirCase):
    def test_mixed_drop_is_routed_and_grouped(self):
        out = analyze_batch([BEC, HTTP_PCAP, FIN02, FIREWALL, VPN])
        by_kit = {c["kit"]: c for c in out["cases"]}
        self.assertEqual(sorted(by_kit), sorted([PHISH, TRAF, EVTX, NSM]))
        self.assertEqual(len(out["cases"]), 4)                     # both network logs -> one case
        self.assertEqual(len(by_kit[NSM]["sources"]), 2)
        for c in out["cases"]:
            self.assertTrue(REQUIRED <= set(c), c["kit"])
            self.assertEqual(sum(c["counts"].values()), len(c["findings"]), c["kit"])
            json.dumps(public(c))                                 # JSON-safe for the UI
            self.assertEqual(c["status"], "ok", c["notes"])

    def test_windows_logs_are_grouped_per_host(self):
        out = analyze_batch([FIN02, RDP, PERSIST])
        hosts = sorted((c["title"].split(" ")[0], len(c["sources"])) for c in out["cases"])
        self.assertEqual(hosts, [("WIN-FIN02", 1), ("WIN-VICTIM01", 2)])

    def test_mailbox_becomes_one_case_per_message(self):
        cases = analyze_batch([MBOX])["cases"]
        self.assertGreater(len(cases), 1)
        self.assertTrue(all(c["sources"][0]["name"].endswith(f"#{i}")
                            for i, c in enumerate(cases, start=1)))

    def test_benign_mail_puts_nothing_on_the_blocklist(self):
        case = analyze_batch([LEGIT])["cases"][0]
        self.assertEqual(case["verdict"]["level"], "clean")
        self.assertFalse([i for i in case["iocs"] if i["block"]])
        self.assertIn("(no block-worthy indicators)", render(case, "blocklist")[0].decode())

    def test_zip_writes_out_only_evidence(self):
        z = os.path.join(self.tmp, "incident.zip")
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("mail/7_bec_wire.eml", read(BEC))
            zf.writestr("net/http_traffic.pcapng", read(HTTP_PCAP))
            zf.writestr("tools/dropper.exe", b"MZ" + b"\x00" * 200)
            zf.writestr("readme.txt", b"Collected by the on-call analyst.\n")
        work = os.path.join(self.tmp, "work")
        out = analyze_batch([z], workdir=work)
        self.assertEqual(sorted(c["kit"] for c in out["cases"]), sorted([PHISH, TRAF]))
        self.assertEqual(sorted(s["name"] for s in out["skipped"]),
                         ["incident.zip/readme.txt", "incident.zip/tools/dropper.exe"])
        written = [f for _r, _d, files in os.walk(work) for f in files]
        self.assertFalse([f for f in written if "dropper" in f or "readme" in f], written)

    def test_folder_is_walked_recursively(self):
        folder = os.path.join(self.tmp, "case-42")
        write(folder, "mail/7_bec_wire.eml", read(BEC))
        write(folder, "pcaps/deep/http_traffic.pcapng", read(HTTP_PCAP))
        out = analyze_batch([folder])
        names = sorted(c["sources"][0]["name"].replace("\\", "/") for c in out["cases"])
        self.assertEqual(names, ["case-42/mail/7_bec_wire.eml", "case-42/pcaps/deep/http_traffic.pcapng"])

    def test_damaged_capture_is_never_reported_clean(self):
        broken = write(self.tmp, "broken.pcapng", b"\x0a\x0d\x0d\x0a" + bytes(range(200)))
        data = read(CLEAN_PCAP)
        cut = write(self.tmp, "cut.pcapng", data[:-50])
        cases = {c["title"]: c for c in analyze_batch([broken, cut])["cases"]}
        self.assertEqual(cases["broken.pcapng"]["status"], "error")
        self.assertEqual(cases["broken.pcapng"]["verdict"]["label"], "ERROR")
        self.assertIn("no packets could be read", cases["broken.pcapng"]["notes"][0])
        self.assertIn("damaged", cases["cut.pcapng"]["notes"][0])
        self.assertIn("damaged", cases["cut.pcapng"]["verdict"]["summary"])

    def test_empty_event_export_is_an_error_not_a_clean_host(self):
        p = write(self.tmp, "empty.xml", b'<?xml version="1.0"?>\n<Events xmlns='
                  b'"http://schemas.microsoft.com/win/2004/08/events/event">\n</Events>\n')
        case = analyze_batch([p])["cases"][0]
        self.assertEqual((case["status"], case["verdict"]["label"]), ("error", "ERROR"))

    def test_non_evidence_is_skipped_not_analysed(self):
        out = analyze_batch([write(self.tmp, "notes.eml", b"just some text\n"),
                             write(self.tmp, "blob.bin", os.urandom(4096))])
        self.assertEqual(out["cases"], [])
        self.assertEqual(len(out["skipped"]), 2)
        self.assertTrue(all(s["reason"] for s in out["skipped"]))


# --------------------------------------------------------------------------
# Exports
# --------------------------------------------------------------------------

class TestExports(TempDirCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = analyze_batch([BEC, MSG, HTTP_PCAP, FIN02, FIREWALL])["cases"]

    def test_every_advertised_export_renders(self):
        for c in self.cases:
            for fmt in c["exports"]:
                body, ctype = render(c, fmt)
                self.assertTrue(body, f"{c['kit']} {fmt}")
                self.assertEqual(ctype, EXPORTS[fmt][1])
                self.assertRegex(filename(c, fmt), r"^[A-Za-z0-9._-]+$")

    def test_unadvertised_export_is_refused(self):
        email = next(c for c in self.cases if c["kit"] == PHISH)
        with self.assertRaises(KeyError):
            render(email, "acl_iptables")

    def test_json_export_keeps_private_fields_out(self):
        for c in self.cases:
            self.assertFalse([k for k in json.loads(render(c, "json")[0]) if k.startswith("_")])

    def test_report_escapes_attacker_controlled_text(self):
        from email.message import EmailMessage
        m = EmailMessage()
        m["From"] = "Support <help@paypa1-secure.example>"
        m["To"] = "victim@example.org"
        m["Subject"] = "<script>alert('subject')</script>"
        m["Message-ID"] = "<x@paypa1-secure.example>"
        m.set_content("Log in now")
        m.add_alternative('<p>Verify <a href="http://paypa1-secure.example/login">here</a>'
                          '<img src=x onerror="alert(1)"></p>', subtype="html")
        case = analyze_batch([write(self.tmp, "xss.eml", m.as_bytes())])["cases"][0]
        html = render(case, "html")[0].decode()
        self.assertNotIn("<script>alert", html)
        self.assertNotIn("onerror=\"alert", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn('href="http://paypa1', html)             # links are shown defanged, never live


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd, cls.session = make_server(0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        workdir = cls.session.workdir
        cls.session.cleanup()
        assert not os.path.exists(workdir), "session folder left behind"

    def req(self, method: str, path: str, body=None, token=True, host=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = dict(headers or {})
        if token:
            h["X-SOCWB-Token"] = self.session.token if token is True else token
        if host:
            h["Host"] = host
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data

    def api(self, method: str, path: str, body=None):
        status, _h, data = self.req(method, path, body)
        self.assertEqual(status, 200, data[:300])
        return json.loads(data)

    def wait(self, job_id: str) -> dict:
        deadline = time.time() + 60
        while time.time() < deadline:
            job = self.api("GET", f"/api/job/{job_id}")
            if job["status"] in ("done", "error"):
                return job
            time.sleep(0.05)
        self.fail(f"job {job_id} did not finish")

    def test_page_embeds_the_token_under_a_strict_csp(self):
        status, h, body = self.req("GET", "/", token=False)
        self.assertEqual(status, 200)
        self.assertIn(self.session.token.encode(), body)
        self.assertNotIn(b"__SOCWB_TOKEN__", body)
        self.assertIn("default-src 'none'", h["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", h["content-security-policy"])

    def test_api_requires_the_session_token(self):
        self.assertEqual(self.req("GET", "/api/info", token=False)[0], 401)
        self.assertEqual(self.req("GET", "/api/info", token="guess")[0], 401)
        self.assertEqual(self.req("GET", "/api/cases?t=guess", token=False)[0], 401)
        self.assertEqual(self.api("GET", "/api/info")["token_ok"], True)

    def test_foreign_host_header_is_refused(self):                 # DNS rebinding
        for path in ("/", "/api/info"):
            self.assertEqual(self.req("GET", path, host=f"attacker.example:{self.port}")[0], 403)

    def test_upload_analyse_export_round_trip(self):
        bid = self.api("POST", "/api/batch", {"label": "round trip"})["batch"]
        name = quote("../../../outside/7_bec_wire.eml")
        status, _h, _b = self.req("PUT", f"/api/batch/{bid}/file?name={name}", read(BEC))
        self.assertEqual(status, 200)
        stored = self.session.batches[bid]["files"][0]
        self.assertEqual(os.path.dirname(stored), self.session.batches[bid]["dir"])
        self.assertTrue(stored.endswith("_7_bec_wire.eml"), stored)

        job = self.wait(self.api("POST", f"/api/batch/{bid}/analyze", {})["job"])
        self.assertEqual((job["status"], len(job["cases"])), ("done", 1))
        cid = job["cases"][0]["id"]
        self.assertEqual(job["cases"][0]["kit"], PHISH)

        case = self.api("GET", f"/api/case/{cid}")
        self.assertTrue(case["findings"])
        self.assertFalse([k for k in case if k.startswith("_")])

        status, h, body = self.req("GET", f"/api/case/{cid}/export/blocklist")
        self.assertEqual(status, 200)
        self.assertTrue(h["content-disposition"].startswith("attachment; filename="))
        self.assertIn(b"m_ellis.finance@gmail.com", body)       # the BEC reply-to
        status, h, _b = self.req("GET", f"/api/case/{cid}/export/html?inline=1")
        self.assertEqual((status, h["content-disposition"]), (200, "inline"))
        self.assertEqual(self.req("GET", f"/api/case/{cid}/export/acl_iptables")[0], 400)

        self.assertEqual(self.api("DELETE", f"/api/case/{cid}"), {"ok": True})
        self.assertEqual(self.req("GET", f"/api/case/{cid}")[0], 400)

    def test_pasted_text_is_analysed(self):
        with open(BEC, encoding="utf-8") as fh:
            text = fh.read()
        job = self.wait(self.api("POST", "/api/paste", {"text": text, "name": "pasted.eml"})["job"])
        self.assertEqual([c["kit"] for c in job["cases"]], [PHISH])
        status, _h, _b = self.req("POST", "/api/paste", {"text": "   "})
        self.assertEqual(status, 400)

    def test_unknown_ids_are_rejected(self):
        self.assertEqual(self.req("PUT", "/api/batch/nope/file?name=x.eml", b"x")[0], 400)
        self.assertEqual(self.req("POST", "/api/batch/nope/analyze", {})[0], 400)
        self.assertEqual(self.req("GET", "/api/job/nope")[0], 400)
        self.assertEqual(self.req("GET", "/api/case/nope/export/json")[0], 400)
        self.assertEqual(self.req("GET", "/api/nothing-here")[0], 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
