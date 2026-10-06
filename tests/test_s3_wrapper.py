"""
Tests for s3_wrapper.py, the evtxkit image's entry point.

Run with: python tests/test_s3_wrapper.py

S3 is replaced by an in-memory stand-in, so these run anywhere without AWS
credentials or boto3; evtxkit itself is run for real on the bundled samples.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import s3_wrapper  # noqa: E402

UPLOADS, REPORTS = "uploads-bucket", "reports-bucket"


def sample(name: str) -> bytes:
    with open(os.path.join(ROOT, "samples", "evtxkit", name), "rb") as fh:
        return fh.read()


class FakeS3:
    """The four calls the wrapper makes, over a dict."""

    def __init__(self, objects: dict | None = None):
        self.objects = dict(objects or {})
        self.downloads = 0
        self.deleted: list = []

    def delete_object(self, Bucket, Key):
        self.objects.pop((Bucket, Key), None)               # like S3: deleting what is not there is not an error
        self.deleted.append((Bucket, Key))

    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise LookupError("An error occurred (404) when calling the HeadObject operation: Not Found")
        return {"ContentLength": len(self.objects[(Bucket, Key)])}

    def download_file(self, Bucket, Key, Filename):
        self.downloads += 1
        with open(Filename, "wb") as fh:
            fh.write(self.objects[(Bucket, Key)])

    def put_object(self, Bucket, Key, Body, ContentType=None):
        self.objects[(Bucket, Key)] = Body

    def text(self, key: str) -> str:
        return self.objects[(REPORTS, key)].decode("utf-8")

    def status(self, job_id: str) -> dict:
        return json.loads(self.text(f"reports/{job_id}/status.json"))


def run(argv=(), env=None, s3=None):
    """(exit code, stdout, stderr) of one wrapper run."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = s3_wrapper.main(list(argv), dict(env or {}), s3)
    return code, out.getvalue(), err.getvalue()


def job_env(key: str, **extra) -> dict:
    return {"INPUT_BUCKET": UPLOADS, "INPUT_KEY": key, "REPORT_BUCKET": REPORTS, **extra}


class TestAnalysisJob(unittest.TestCase):
    def test_upload_is_analysed_and_the_report_traces_back_to_it(self):
        key = "uploads/20261005-7f3a9c/Security export (1).jsonl"
        s3 = FakeS3({(UPLOADS, key): sample("rdp_brute_force.jsonl")})
        code, out, _err = run(env=job_env(key), s3=s3)
        self.assertEqual(code, 0)                               # findings are a result, not a failure
        report = s3.text("reports/20261005-7f3a9c/report.md")
        self.assertIn("EVTX-LOGON-BRUTE-01", report)
        self.assertIn("`Security_export_1.jsonl`", report)      # the upload's name, not a temp path
        self.assertNotIn("evtxkit-job-", report)
        st = s3.status("20261005-7f3a9c")
        self.assertEqual((st["state"], st["report_key"], st["error"]),
                         ("done", "reports/20261005-7f3a9c/report.md", None))
        self.assertEqual(st["input"], {"bucket": UPLOADS, "key": key, "bytes": len(sample("rdp_brute_force.jsonl"))})
        self.assertTrue(st["high_or_critical_findings"])
        self.assertTrue(st["started"] and st["finished"])
        # The file is gone as soon as it has been analysed, and the log has the facts, not the data.
        self.assertNotIn((UPLOADS, key), s3.objects)
        self.assertTrue(st["input_deleted"])
        self.assertIn("job 20261005-7f3a9c analysed: exit=1 events=21 findings=2 worst=critical input_deleted=True", out)

    def test_the_log_holds_counts_and_timings_never_the_customers_data(self):
        text = sample("rdp_brute_force.jsonl").decode("utf-8")
        address = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text).group(0)
        key = "uploads/job-log/rdp_brute_force.jsonl"
        s3 = FakeS3({(UPLOADS, key): sample("rdp_brute_force.jsonl")})
        _code, out, err = run(env=job_env(key), s3=s3)
        self.assertIn(address, s3.text("reports/job-log/report.md"))     # the report does quote the log...
        for logged in (out, err):                                        # ...and the log must not
            self.assertNotIn(address, logged)
            self.assertNotIn("# evtxkit analysis", logged)
            self.assertNotIn("EVTX-LOGON-BRUTE", logged)
        # A file that cannot be analysed: its content is not echoed either.
        bad = b'{"marker": "SECRET-MARKER-12345", "note": "not an event"}\n' * 5
        s3 = FakeS3({(UPLOADS, "uploads/job-bad2/x.jsonl"): bad})
        _code, out, err = run(env=job_env("uploads/job-bad2/x.jsonl"), s3=s3)
        self.assertEqual(s3.status("job-bad2")["state"], "failed")
        self.assertNotIn("SECRET-MARKER-12345", out + err + json.dumps(s3.status("job-bad2")))

    def test_the_upload_is_deleted_whatever_happens_to_the_job(self):
        class ReportsRefused(FakeS3):
            def put_object(self, Bucket, Key, Body, ContentType=None):
                if Key.endswith("report.md"):
                    raise RuntimeError("AccessDenied")
                super().put_object(Bucket, Key, Body, ContentType)

        real = s3_wrapper.run_evtxkit

        def too_slow(args, cwd, timeout=None):
            raise subprocess.TimeoutExpired(cmd="evtxkit", timeout=timeout)

        cases = {                                    # name: (storage, content, extra environment, expected state)
            "worked": (FakeS3, sample("clean_baseline.jsonl"), {}, "done"),
            "not a log": (FakeS3, b"this is not an event log\n" * 20, {}, "failed"),
            "too large": (FakeS3, sample("rdp_brute_force.jsonl"), {"MAX_INPUT_BYTES": "100"}, "failed"),
            "empty": (FakeS3, b"", {}, "failed"),
            "report refused": (ReportsRefused, sample("clean_baseline.jsonl"), {}, "failed"),
        }
        for name, (storage, content, extra, state) in cases.items():
            key = "uploads/job-gone/x.jsonl"
            s3 = storage({(UPLOADS, key): content})
            run(env=job_env(key, **extra), s3=s3)
            self.assertEqual(s3.status("job-gone")["state"], state, name)
            self.assertNotIn((UPLOADS, key), s3.objects, name)
            self.assertTrue(s3.status("job-gone")["input_deleted"], name)
        s3_wrapper.run_evtxkit = too_slow            # the analysis runs out of time
        try:
            s3 = FakeS3({(UPLOADS, key): sample("clean_baseline.jsonl")})
            run(env=job_env(key), s3=s3)
        finally:
            s3_wrapper.run_evtxkit = real
        self.assertEqual((s3.status("job-gone")["state"], (UPLOADS, key) in s3.objects), ("failed", False))

    def test_a_deletion_that_fails_does_not_fail_the_job(self):
        class CannotDelete(FakeS3):
            def delete_object(self, Bucket, Key):
                raise PermissionError("AccessDenied: s3:DeleteObject")

        key = "uploads/job-keep/clean_baseline.jsonl"
        s3 = CannotDelete({(UPLOADS, key): sample("clean_baseline.jsonl")})
        code, _out, err = run(env=job_env(key), s3=s3)
        st = s3.status("job-keep")
        self.assertEqual((code, st["state"], st["input_deleted"]), (0, "done", False))
        self.assertIn("could not delete the upload: PermissionError", err)
        self.assertIn((UPLOADS, key), s3.objects)            # left for the bucket's lifecycle rule

    def test_clean_log_is_done_without_findings(self):
        key = "uploads/job-clean/clean_baseline.jsonl"
        s3 = FakeS3({(UPLOADS, key): sample("clean_baseline.jsonl")})
        self.assertEqual(run(env=job_env(key), s3=s3)[0], 0)
        st = s3.status("job-clean")
        self.assertEqual((st["state"], st["high_or_critical_findings"], st["analysis_exit_code"]), ("done", False, 0))

    def test_event_viewer_xml_upload(self):
        key = "uploads/job-xml/log_cleared.xml"
        s3 = FakeS3({(UPLOADS, key): sample("log_cleared.xml")})
        self.assertEqual(run(env=job_env(key), s3=s3)[0], 0)
        self.assertIn("EVTX-DEFENSE-LOGCLEAR-01", s3.text("reports/job-xml/report.md"))

    def test_report_format_can_be_json(self):
        key = "uploads/job-json/rdp_brute_force.jsonl"
        s3 = FakeS3({(UPLOADS, key): sample("rdp_brute_force.jsonl")})
        self.assertEqual(run(env=job_env(key, REPORT_FORMAT="json"), s3=s3)[0], 0)
        self.assertTrue(json.loads(s3.text("reports/job-json/report.json"))["findings"])
        self.assertEqual(s3.status("job-json")["report_key"], "reports/job-json/report.json")

    def test_job_id_can_be_given_explicitly(self):
        key = "somewhere/else.jsonl"
        s3 = FakeS3({(UPLOADS, key): sample("clean_baseline.jsonl")})
        self.assertEqual(run(env=job_env(key, JOB_ID="abc-123"), s3=s3)[0], 0)
        self.assertEqual(s3.status("abc-123")["state"], "done")

    def test_a_file_that_is_not_an_event_log_fails_and_says_so(self):
        key = "uploads/job-bad/holiday.jsonl"
        s3 = FakeS3({(UPLOADS, key): b"this is not an event log\n" * 20})
        code, _out, err = run(env=job_env(key), s3=s3)
        self.assertEqual(code, 1)
        st = s3.status("job-bad")
        self.assertEqual(st["state"], "failed")
        # Never "0 events, no findings": that would read as a clean system.
        self.assertEqual(st["error"], "The file could not be analysed as a Windows event log: "
                                      "no events found in holiday.jsonl")
        self.assertNotIn("evtxkit-job-", st["error"])           # no temp paths in what a customer sees
        self.assertNotIn((REPORTS, "reports/job-bad/report.md"), s3.objects)
        self.assertIn("failed", err)

    def test_missing_upload_fails_cleanly(self):
        s3 = FakeS3()
        self.assertEqual(run(env=job_env("uploads/job-none/x.evtx"), s3=s3)[0], 1)
        st = s3.status("job-none")
        self.assertEqual((st["state"], st["error"]), ("failed", "The uploaded file could not be found."))

    def test_oversized_upload_is_refused_before_downloading(self):
        key = "uploads/job-big/big.jsonl"
        s3 = FakeS3({(UPLOADS, key): sample("rdp_brute_force.jsonl")})
        self.assertEqual(run(env=job_env(key, MAX_INPUT_BYTES="100"), s3=s3)[0], 1)
        self.assertEqual(s3.downloads, 0)
        self.assertIn("too large", s3.status("job-big")["error"])

    def test_empty_upload_is_refused(self):
        key = "uploads/job-empty/empty.evtx"
        s3 = FakeS3({(UPLOADS, key): b""})
        self.assertEqual(run(env=job_env(key), s3=s3)[0], 1)
        self.assertEqual(s3.status("job-empty")["error"], "The uploaded file is empty.")

    def test_analysis_that_runs_too_long_is_stopped(self):
        key = "uploads/job-slow/slow.jsonl"
        s3 = FakeS3({(UPLOADS, key): sample("clean_baseline.jsonl")})
        real = s3_wrapper.run_evtxkit

        def too_slow(args, cwd, timeout=None):
            raise subprocess.TimeoutExpired(cmd="evtxkit", timeout=timeout)

        s3_wrapper.run_evtxkit = too_slow
        try:
            code = run(env=job_env(key, ANALYSIS_TIMEOUT_SECONDS="7"), s3=s3)[0]
        finally:
            s3_wrapper.run_evtxkit = real
        self.assertEqual(code, 1)
        self.assertIn("within 7 seconds", s3.status("job-slow")["error"])

    def test_an_unexpected_error_never_leaves_the_job_running(self):
        # Here the report cannot be stored. Whatever the cause, the uploader must
        # get an answer, and the details belong in the log, not in that answer.
        class ReportsRefused(FakeS3):
            def put_object(self, Bucket, Key, Body, ContentType=None):
                if Key.endswith("report.md"):
                    raise RuntimeError("AccessDenied on arn:aws:s3:::reports-bucket/reports/job-odd/report.md")
                super().put_object(Bucket, Key, Body, ContentType)

        key = "uploads/job-odd/clean_baseline.jsonl"
        s3 = ReportsRefused({(UPLOADS, key): sample("clean_baseline.jsonl")})
        code, _out, err = run(env=job_env(key), s3=s3)
        self.assertEqual(code, 1)
        st = s3.status("job-odd")
        self.assertEqual((st["state"], st["error"]), ("failed", "The analysis could not be completed."))
        self.assertTrue(st["finished"])
        self.assertIn("AccessDenied on arn:aws:s3", err)

    def test_a_job_needs_a_report_bucket(self):
        key = "uploads/job-x/x.jsonl"
        s3 = FakeS3({(UPLOADS, key): sample("clean_baseline.jsonl")})
        code, _out, err = run(env={"INPUT_BUCKET": UPLOADS, "INPUT_KEY": key}, s3=s3)
        self.assertEqual(code, 1)
        self.assertIn("REPORT_BUCKET", err)
        self.assertEqual(list(s3.objects), [(UPLOADS, key)])    # nothing was written anywhere


class TestNames(unittest.TestCase):
    def test_job_id_comes_from_the_upload_key(self):
        cases = {
            "uploads/20261005-7f3a9c/Security.evtx": "20261005-7f3a9c",
            "uploads/Security.evtx": "Security",
            "Security.evtx": "Security",
            "uploads/a b/../x.evtx": "a-b",
            "uploads/../../etc/passwd": "job",                   # nothing usable: the safe fallback
            "": "job",
        }
        for key, want in cases.items():
            self.assertEqual(s3_wrapper.job_id_from_key(key), want, key)
            self.assertRegex(s3_wrapper.job_id_from_key(key), r"^[A-Za-z0-9._-]+$")

    def test_local_name_is_never_a_path(self):
        cases = {
            "uploads/j/Security.EVTX": "Security.evtx",
            "uploads/j/weird name (1).evtx": "weird_name_1.evtx",
            "uploads/j/..\\..\\windows\\system32\\evil.evtx": "evil.evtx",
            "uploads/j/../../etc/passwd": "passwd",
            "uploads/j/payload.exe": "payload",                  # unknown extensions are dropped
            "uploads/j/...": "upload",
        }
        for key, want in cases.items():
            self.assertEqual(s3_wrapper.local_name(key), want, key)


class TestPassThrough(unittest.TestCase):
    """No INPUT_* variables: the image behaves like plain evtxkit."""

    def setUp(self):
        self._client = s3_wrapper._s3_client
        s3_wrapper._s3_client = lambda: self.fail("S3 must not be touched without REPORT_BUCKET")

    def tearDown(self):
        s3_wrapper._s3_client = self._client

    def test_runs_without_any_aws_configuration(self):
        # What CI's smoke test and the Kubernetes job do: no bucket, no credentials.
        code, out, _err = run(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("EVTX-LOGON-BRUTE", out)
        self.assertEqual(run(["--help"])[0], 0)

    def test_exit_code_is_evtxkits(self):
        self.assertEqual(run(["analyze", os.path.join(ROOT, "samples", "evtxkit", "rdp_brute_force.jsonl")])[0], 1)
        self.assertEqual(run(["analyze", "no-such-file.jsonl"])[0], 2)

    def test_output_is_uploaded_when_a_bucket_is_set(self):
        s3 = FakeS3()
        code, out, _err = run(["rules"], {"REPORT_BUCKET": REPORTS}, s3)
        self.assertEqual(code, 0)
        (bucket, key), = s3.objects
        self.assertEqual(bucket, REPORTS)
        self.assertRegex(key, r"^reports/report-\d{8}-\d{6}\.txt$")
        self.assertIn("EVTX-LOGON-BRUTE", s3.objects[(bucket, key)].decode())
        self.assertIn(f"Uploaded to s3://{REPORTS}/{key}", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
