"""
Tests for the upload flow: the two Lambda functions, the page, the AWS
configuration files, and all of it running together.

Run with: python tests/test_upload_flow.py

AWS is replaced by the stand-ins in tools/local_upload_flow.py (S3 as a dict,
the Fargate task as s3_wrapper.py run in-process), so these need no
credentials, no boto3 and no network. evtxkit runs for real on the bundled
samples. What they cannot show is that the real account accepts the policies
and settings; aws/UPLOAD-FLOW.md covers that.
"""

from __future__ import annotations

import base64
import contextlib
import datetime
import hashlib
import html as html_module
import http.client
import importlib.util
import io
import json
import math
import os
import re
import sys
import tempfile
import threading
import unittest
import zipfile

ROOT =os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import access_codes  # noqa: E402
import build_lambdas  # noqa: E402
import local_upload_flow as local  # noqa: E402
import s3_wrapper  # noqa: E402

AWS = os.path.join(ROOT, "aws")
UPLOADS, REPORTS = "evtxkit-uploads-test", "evtxkit-reports-test"
CODE = "correct-horse-battery"                    # alice's code
BOB_CODE = "battery-staple-horse"
JOB = "alice-0123456789abcdef0123456789abcdef"    # a job of alice's
BOB_JOB = "bob-fedcba9876543210fedcba9876543210"  # a job of bob's

start_analysis = local.load_lambda("start_analysis")
upload_api = local.load_lambda("upload_api")
start_analysis.print = upload_api.print = lambda *args, **kwargs: None      # their CloudWatch logs


def read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as fh:
        return fh.read()


def sample(name: str) -> bytes:
    with open(os.path.join(ROOT, "samples", "evtxkit", name), "rb") as fh:
        return fh.read()


def as_list(value) -> list:
    return value if isinstance(value, list) else [value]


# --------------------------------------------------------------------------
# start_analysis: S3 event -> ecs.run_task
# --------------------------------------------------------------------------

TRIGGER_ENV = {"ECS_CLUSTER": "evtxkit-cluster", "TASK_DEFINITION": "evtxkit-task",
               "SUBNETS": "subnet-aaa, subnet-bbb", "SECURITY_GROUPS": "sg-ccc", "UPLOADS_BUCKET": UPLOADS}


def s3_event(key: str, bucket: str = UPLOADS, name: str = "ObjectCreated:Post",
             sequencer: str = "0055AED6DCD90281E5") -> dict:
    """What S3 sends for one object. `key` is as S3 sends it: URL-encoded."""
    return {"Records": [{"eventSource": "aws:s3", "eventName": name, "awsRegion": "eu-north-1",
                         "s3": {"bucket": {"name": bucket},
                                "object": {"key": key, "size": 1024, "sequencer": sequencer}}}]}


class RecordingECS:
    def __init__(self, failures: list | None = None):
        self.calls: list[dict] = []
        self.failures = failures or []

    def run_task(self, **request):
        self.calls.append(request)
        if self.failures:
            return {"tasks": [], "failures": self.failures}
        return {"tasks": [{"taskArn": f"arn:aws:ecs:eu-north-1:111122223333:task/evtxkit-cluster/{len(self.calls)}"}],
                "failures": []}


class TestStartAnalysis(unittest.TestCase):
    def test_an_upload_starts_one_task_with_the_two_overrides(self):
        ecs = RecordingECS()
        key = f"uploads/{JOB}/Security.evtx"
        result = start_analysis.handle(s3_event(key), TRIGGER_ENV, ecs)
        (request,) = ecs.calls
        token = request.pop("clientToken")
        self.assertEqual(request, {
            "cluster": "evtxkit-cluster",
            "taskDefinition": "evtxkit-task",
            "launchType": "FARGATE",
            "count": 1,
            "networkConfiguration": {"awsvpcConfiguration": {
                "subnets": ["subnet-aaa", "subnet-bbb"], "securityGroups": ["sg-ccc"], "assignPublicIp": "ENABLED"}},
            # Only where the file is. Downloading and analysing it is the container's job.
            "overrides": {"containerOverrides": [{"name": "evtxkit", "environment": [
                {"name": "INPUT_BUCKET", "value": UPLOADS}, {"name": "INPUT_KEY", "value": key}]}]},
        })
        self.assertRegex(token, r"^[0-9a-f]{32}$")
        self.assertEqual(result["started"], [{"job_id": JOB, "key": key,
                                              "task_arn": "arn:aws:ecs:eu-north-1:111122223333:task/evtxkit-cluster/1"}])

    def test_keys_arrive_url_encoded(self):
        for sent, real in {"uploads/abc123/Security+export+%281%29.evtx": "uploads/abc123/Security export (1).evtx",
                           "uploads/abc123/a%2Bb.evtx": "uploads/abc123/a+b.evtx"}.items():
            ecs = RecordingECS()
            start_analysis.handle(s3_event(sent), TRIGGER_ENV, ecs)
            environment = ecs.calls[0]["overrides"]["containerOverrides"][0]["environment"]
            self.assertEqual(environment[1], {"name": "INPUT_KEY", "value": real})

    def test_only_uploads_in_the_uploads_bucket_start_a_task(self):
        ignored = [
            s3_event(f"uploads/{JOB}/x.evtx", bucket="some-other-bucket"),
            s3_event(f"uploads/{JOB}/x.evtx", name="ObjectRemoved:Delete"),
            s3_event(f"reports/{JOB}/report.md"),
            s3_event("uploads/x.evtx"),                         # no job folder
            s3_event(f"uploads/{JOB}/deeper/x.evtx"),
            s3_event(f"uploads/{JOB}/"),                        # a "folder" made in the console
            s3_event("uploads/.hidden/x.evtx"),
            s3_event("uploads/-dash/x.evtx"),
            s3_event("uploads/ends-with-a-dot./x.evtx"),
            s3_event("uploads/a%20b/x.evtx"),
            s3_event("uploads/../x.evtx"),
            s3_event("uploads/" + "j" * 81 + "/x.evtx"),
            s3_event(f"uploads/{JOB}/" + "n" * 600 + ".evtx"),
            {"Service": "Amazon S3", "Event": "s3:TestEvent"},  # sent when the notification is set up
            {},
        ]
        for event in ignored:
            ecs = RecordingECS()
            result = start_analysis.handle(event, TRIGGER_ENV, ecs)
            self.assertEqual((ecs.calls, result["started"]), ([], []), event)
            self.assertEqual(len(result["ignored"]), len(event.get("Records", [])))
        self.assertEqual(start_analysis.handle(None, TRIGGER_ENV, RecordingECS())["started"], [])

    def test_job_ids_it_accepts_are_ones_the_wrapper_keeps(self):
        # Otherwise the report would land under a different id than the page is waiting for.
        for job_id in (JOB, "manual-test-1", "20261005-7f3a9c", "a", "A.b_c-9", "x" * 80):
            key = f"uploads/{job_id}/Security.evtx"
            self.assertTrue(start_analysis.UPLOAD_KEY.match(key), key)
            self.assertEqual(s3_wrapper.job_id_from_key(key), job_id)

    def test_ecs_not_starting_the_task_fails_the_invocation(self):
        # run_task reports this in its answer instead of raising; a failed invocation is what makes Lambda retry.
        ecs = RecordingECS(failures=[{"reason": "Capacity is unavailable at this time", "arn": "arn:aws:ecs:..."}])
        with self.assertRaisesRegex(RuntimeError, "Capacity is unavailable"):
            start_analysis.handle(s3_event(f"uploads/{JOB}/x.evtx"), TRIGGER_ENV, ecs)

    def test_one_failing_upload_does_not_stop_the_others(self):
        class RefusesOne(RecordingECS):
            def run_task(self, **request):
                if "bad" in request["overrides"]["containerOverrides"][0]["environment"][1]["value"]:
                    self.calls.append(request)
                    raise RuntimeError("AccessDeniedException")
                return super().run_task(**request)

        event = {"Records": s3_event("uploads/job-1/bad.evtx")["Records"] + s3_event("uploads/job-2/good.evtx")["Records"]}
        ecs = RefusesOne()
        with self.assertRaisesRegex(RuntimeError, "AccessDeniedException"):
            start_analysis.handle(event, TRIGGER_ENV, ecs)
        self.assertEqual(len(ecs.calls), 2)

    def test_a_repeated_event_is_the_same_request_and_a_new_upload_is_not(self):
        def token(key, sequencer):
            ecs = RecordingECS()
            start_analysis.handle(s3_event(key, sequencer=sequencer), TRIGGER_ENV, ecs)
            return ecs.calls[0]["clientToken"]

        key = f"uploads/{JOB}/x.evtx"
        self.assertEqual(token(key, "A1"), token(key, "A1"))       # S3 delivered the event twice
        self.assertNotEqual(token(key, "A1"), token(key, "B2"))    # the file was uploaded again
        self.assertNotEqual(token(key, "A1"), token(f"uploads/{JOB}/y.evtx", "A1"))

    def test_missing_settings_are_named(self):
        env = {k: v for k, v in TRIGGER_ENV.items() if k not in ("SUBNETS", "UPLOADS_BUCKET")}
        with self.assertRaisesRegex(start_analysis.ConfigError, "SUBNETS, UPLOADS_BUCKET"):
            start_analysis.handle(s3_event(f"uploads/{JOB}/x.evtx"), env, RecordingECS())

    def test_container_name_and_public_ip_can_be_set(self):
        ecs = RecordingECS()
        env = dict(TRIGGER_ENV, CONTAINER_NAME="analyser", ASSIGN_PUBLIC_IP="disabled")
        start_analysis.handle(s3_event(f"uploads/{JOB}/x.evtx"), env, ecs)
        self.assertEqual(ecs.calls[0]["overrides"]["containerOverrides"][0]["name"], "analyser")
        self.assertEqual(ecs.calls[0]["networkConfiguration"]["awsvpcConfiguration"]["assignPublicIp"], "DISABLED")


# --------------------------------------------------------------------------
# upload_api: the page, pre-signed uploads, job status
# --------------------------------------------------------------------------

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# The function is given fingerprints, never codes.
API_ENV = {"UPLOADS_BUCKET": UPLOADS, "REPORT_BUCKET": REPORTS,
           "USERS": json.dumps({"alice": sha256(CODE), "bob": sha256(BOB_CODE)})}


def call(method: str, path: str, body=None, code: str | None = CODE, env: dict | None = None, s3=None, **event):
    """(status, body, whole response) of one request to the function; a JSON body comes back parsed."""
    request = {"version": "2.0", "rawPath": path, "isBase64Encoded": False,
               "headers": {"x-access-code": code} if code is not None else {},
               "requestContext": {"http": {"method": method, "path": path}},
               "body": json.dumps(body) if isinstance(body, dict) else body}
    request.update(event)
    response = upload_api.handle(request, API_ENV if env is None else env, s3 if s3 is not None else local.LocalS3())
    content = response["body"]
    if response["headers"]["Content-Type"].startswith("application/json"):
        content = json.loads(content)
    return response["statusCode"], content, response


def policy(fields: dict) -> dict:
    return json.loads(base64.b64decode(fields["policy"]))


def write_status(s3, job_id: str = JOB, **fields) -> None:
    status = {"job_id": job_id, "state": "running", "input": {"bucket": UPLOADS, "key": f"uploads/{job_id}/x.evtx"},
              "format": "markdown", "report_key": None, "error": None, "started": "2026-10-05T10:00:00Z",
              "finished": None, **fields}
    s3.put_object(REPORTS, f"reports/{job_id}/status.json", json.dumps(status).encode())


class TestUploadApi(unittest.TestCase):
    def setUp(self):
        upload_api._origins.clear()

    # ---- the page ---------------------------------------------------------
    def test_the_page_and_its_two_files_are_served(self):
        s3 = local.LocalS3(base_url="https://evtxkit-uploads-test.s3.eu-north-1.amazonaws.com")
        status, page, response = call("GET", "/", code=None, s3=s3)
        self.assertEqual(status, 200)
        self.assertIn("<title>Windows event log analysis</title>", page)
        self.assertEqual(response["headers"]["Content-Type"], "text/html; charset=utf-8")
        csp = response["headers"]["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("script-src 'self';", csp)
        self.assertNotIn("unsafe", csp)
        # The one other place the page talks to: the bucket the file is sent to.
        self.assertIn("connect-src 'self' https://evtxkit-uploads-test.s3.eu-north-1.amazonaws.com;", csp)
        for path, kind in (("/app.js", "text/javascript"), ("/app.css", "text/css")):
            status, _text, response = call("GET", path, code=None)
            self.assertEqual((status, response["headers"]["Content-Type"]), (200, kind + "; charset=utf-8"))
        self.assertEqual(call("POST", "/", code=None)[0], 405)

    def test_every_answer_carries_the_safety_headers(self):
        for method, path in (("GET", "/"), ("GET", "/app.js"), ("GET", "/nope"), ("GET", f"/api/jobs/{JOB}")):
            headers = call(method, path)[2]["headers"]
            self.assertEqual((headers["X-Content-Type-Options"], headers["Cache-Control"], headers["X-Frame-Options"]),
                             ("nosniff", "no-store", "DENY"), path)

    def test_only_what_the_page_links_to_is_served(self):
        html = read("aws", "lambda", "upload_api", "web", "index.html")
        linked = set(re.findall(r'(?:src|href)="([^"]+)"', html)) - {"data:,"}
        self.assertEqual({"/" + name for name in linked} | {"/"}, set(upload_api.STATIC))
        for path in ("/index.html", "/handler.py", "/web/app.js", "/../handler.py", "/favicon.ico"):
            self.assertEqual(call("GET", path, code=None)[0], 404, path)

    # ---- the access code ---------------------------------------------------
    def test_the_api_needs_the_access_code(self):
        for code in (None, "", "wrong", CODE + "x", CODE[:-1]):
            status, body, _ = call("POST", "/api/uploads", {"filename": "a.evtx"}, code=code)
            self.assertEqual((status, body), (401, {"error": "The access code is missing or wrong."}), code)
            self.assertEqual(call("GET", f"/api/jobs/{JOB}", code=code)[0], 401)
        self.assertEqual(call("POST", "/api/uploads", {"filename": "a.evtx"})[0], 201)
        # Function URLs lower-case header names; do not depend on it.
        self.assertEqual(call("GET", f"/api/jobs/{JOB}", code=None, headers={"X-Access-Code": CODE})[0], 200)

    def test_without_its_settings_the_api_refuses_everything(self):
        for missing in API_ENV:
            env = {k: v for k, v in API_ENV.items() if k != missing}
            self.assertEqual(call("POST", "/api/uploads", {"filename": "a.evtx"}, env=env)[0], 503, missing)
            self.assertEqual(call("GET", f"/api/jobs/{JOB}", code="", env=env)[0], 503, missing)
            self.assertEqual(call("GET", "/", code=None, env=env)[0], 200)     # the page itself still loads

    def test_a_wrong_users_setting_refuses_everything(self):
        fp = sha256(CODE)
        wrong = ["", "   ", "not json", "[]", "{}", '"alice"',
                 json.dumps({"Alice": fp}), json.dumps({"a": fp}), json.dumps({"alice-b": fp}),
                 json.dumps({"alice": "short"}), json.dumps({"alice": fp.upper()}), json.dumps({"alice": 7}),
                 json.dumps({"alice": fp, "bob": fp})]                          # two people, one code
        for users in wrong:
            env = dict(API_ENV, USERS=users)
            for code in (CODE, None):
                self.assertEqual(call("POST", "/api/uploads", {"filename": "a.evtx"}, code=code, env=env)[:2],
                                 (503, {"error": "The service is not set up yet."}), users)

    def test_the_setting_holds_fingerprints_and_never_a_code(self):
        users = json.loads(API_ENV["USERS"])
        self.assertEqual(set(users), {"alice", "bob"})
        for code in (CODE, BOB_CODE):
            self.assertNotIn(code, API_ENV["USERS"])
            self.assertIn(sha256(code), users.values())
        self.assertEqual(upload_api.fingerprint(CODE), sha256(CODE))

    def test_each_person_has_their_own_code_and_sees_only_their_own_jobs(self):
        s3 = local.LocalS3()
        mine = call("POST", "/api/uploads", {"filename": "a.evtx"}, s3=s3)[1]
        theirs = call("POST", "/api/uploads", {"filename": "a.evtx"}, code=BOB_CODE, s3=s3)[1]
        self.assertRegex(mine["job_id"], r"^alice-[0-9a-f]{32}$")
        self.assertRegex(theirs["job_id"], r"^bob-[0-9a-f]{32}$")
        for job_id, owner_code, other_code in ((mine["job_id"], CODE, BOB_CODE), (theirs["job_id"], BOB_CODE, CODE)):
            write_status(s3, job_id=job_id)
            self.assertEqual(call("GET", f"/api/jobs/{job_id}", code=owner_code, s3=s3)[1]["state"], "running")
            # Someone else's job answers exactly like one that does not exist.
            self.assertEqual(call("GET", f"/api/jobs/{job_id}", code=other_code, s3=s3)[:2],
                             (404, {"error": "No such job."}))
        self.assertEqual(call("GET", f"/api/jobs/alice-{'0' * 32}", code=BOB_CODE, s3=s3)[:2],
                         (404, {"error": "No such job."}))

    def test_a_code_that_is_far_too_long_is_refused_not_hashed(self):
        self.assertEqual(call("POST", "/api/uploads", {"filename": "a.evtx"}, code="x" * 5000)[0], 401)

    def test_what_is_logged_has_no_code_in_it(self):
        lines = []
        upload_api.print = lambda *args, **kwargs: lines.append(" ".join(map(str, args)))
        try:
            call("POST", "/api/uploads", {"filename": "a.evtx"}, code="a-wrong-code-12345",
                 requestContext={"http": {"method": "POST", "path": "/api/uploads", "sourceIp": "203.0.113.7"}})
            call("POST", "/api/uploads", {"filename": "a.evtx"}, code=CODE)
            call("POST", "/api/uploads", {"filename": "a.evtx"}, code=BOB_CODE)
        finally:
            upload_api.print = lambda *args, **kwargs: None
        text = "\n".join(lines)
        self.assertIn('"auth_failed": {"ip": "203.0.113.7"}', text)
        self.assertIn('"upload_signed": {"user": "alice"', text)
        self.assertIn('"upload_signed": {"user": "bob"', text)
        for secret in ("a-wrong-code-12345", CODE, BOB_CODE, sha256(CODE)):
            self.assertNotIn(secret, text)

    # ---- codes that expire --------------------------------------------------
    def test_a_code_with_an_expiry_works_through_its_last_day_and_then_stops(self):
        users = json.dumps({"alice": {"sha256": sha256(CODE), "expires": "2026-10-20"}, "bob": sha256(BOB_CODE)})
        env = dict(API_ENV, USERS=users)
        lines, real = [], upload_api.today
        upload_api.print = lambda *args, **kwargs: lines.append(" ".join(map(str, args)))
        try:
            for day, still_works in (("2026-10-06", True), ("2026-10-20", True), ("2026-10-21", False), ("2027-01-01", False)):
                upload_api.today = lambda day=day: datetime.date.fromisoformat(day)
                status, body, _ = call("POST", "/api/uploads", {"filename": "a.evtx"}, env=env)
                if still_works:
                    self.assertEqual(status, 201, day)
                else:
                    self.assertEqual((status, body), (401, {"error": "This access code has expired. Ask for a new one."}), day)
                self.assertEqual(call("POST", "/api/uploads", {"filename": "a.evtx"}, code=BOB_CODE, env=env)[0], 201, day)
                self.assertEqual(call("GET", "/api/samples", env=env)[0], 200 if still_works else 401, day)
            # A wrong code still gets the plain answer: only a real code learns that it ran out.
            self.assertEqual(call("POST", "/api/uploads", {"filename": "a.evtx"}, code="wrong", env=env)[:2],
                             (401, {"error": "The access code is missing or wrong."}))
        finally:
            upload_api.today = real
            upload_api.print = lambda *args, **kwargs: None
        text = "\n".join(lines)
        self.assertIn('"auth_expired": {"user": "alice"', text)
        self.assertNotIn(CODE, text)

    def test_the_expiry_in_the_setting_must_be_a_real_date(self):
        fp = sha256(CODE)
        wrong = [{"sha256": fp, "expires": "20-10-2026"}, {"sha256": fp, "expires": "2026-13-40"}, {"sha256": fp, "expires": 20261020},
                 {"sha256": fp, "expires": "20261020"}, {"sha256": fp, "expires": "2026-10-20T10:00"}, {"sha256": fp, "extra": 1},
                 {"expires": "2026-10-20"}, {"sha256": "short", "expires": "2026-10-20"}]
        for entry in wrong:
            env = dict(API_ENV, USERS=json.dumps({"alice": entry}))
            self.assertEqual(call("POST", "/api/uploads", {"filename": "a.evtx"}, env=env)[0], 503, entry)
        for entry in ({"sha256": fp, "expires": None}, {"sha256": fp}, fp):              # no expiry
            env = dict(API_ENV, USERS=json.dumps({"alice": entry}))
            self.assertEqual(call("POST", "/api/uploads", {"filename": "a.evtx"}, env=env)[0], 201, entry)

    def test_the_page_answers_head_with_its_headers_and_no_body(self):
        for path in ("/", "/app.js", "/app.css"):
            status, body, response = call("HEAD", path, code=None)
            self.assertEqual((status, body), (200, ""), path)
            self.assertEqual(response["headers"]["X-Content-Type-Options"], "nosniff")
        self.assertIn("Content-Security-Policy", call("HEAD", "/", code=None)[2]["headers"])
        self.assertEqual(call("HEAD", "/api/samples")[0], 405)
        self.assertEqual(call("DELETE", "/", code=None)[0], 405)

    # ---- signing an upload --------------------------------------------------
    def test_an_upload_is_signed_for_one_key_one_size_range_and_a_few_minutes(self):
        s3 = local.LocalS3()
        status, body, _ = call("POST", "/api/uploads", {"filename": "Security.evtx", "size": 4096}, s3=s3)
        self.assertEqual(status, 201)
        self.assertRegex(body["job_id"], r"^alice-[0-9a-f]{32}$")
        self.assertEqual(body["upload"]["fields"]["key"], f"uploads/{body['job_id']}/Security.evtx")
        self.assertEqual(body["upload"]["url"], f"{local.S3_PATH}/{UPLOADS}")
        self.assertEqual((body["max_bytes"], body["expires_in"]), (64 * 1024 * 1024, 300))
        conditions = policy(body["upload"]["fields"])["conditions"]
        self.assertIn(["content-length-range", 1, 64 * 1024 * 1024], conditions)
        self.assertIn({"key": f"uploads/{body['job_id']}/Security.evtx"}, conditions)
        self.assertIn({"bucket": UPLOADS}, conditions)
        other = call("POST", "/api/uploads", {"filename": "Security.evtx"}, s3=s3)[1]
        self.assertNotEqual(other["job_id"], body["job_id"])

    def test_the_stored_name_is_safe_and_is_what_the_wrapper_will_show(self):
        cases = {
            "Security.evtx": "Security.evtx",
            "Security export (1).EVTX": "Security_export_1.evtx",
            "C:\\Users\\ana\\Desktop\\dc01 security.evtx": "dc01_security.evtx",
            "..\\..\\windows\\system32\\evil.evtx": "evil.evtx",
            "../../etc/passwd.log": "passwd.log",
            "ünïcödé logs.jsonl": "n_c_d_logs.jsonl",
            "###.xml": "upload.xml",
            "a" * 300 + ".json": "a" * 80 + ".json",
        }
        for given, stored in cases.items():
            status, body, _ = call("POST", "/api/uploads", {"filename": given})
            self.assertEqual(status, 201, given)
            key = body["upload"]["fields"]["key"]
            self.assertEqual(key, f"uploads/{body['job_id']}/{stored}")
            self.assertEqual(s3_wrapper.local_name(key), stored)
            self.assertTrue(start_analysis.UPLOAD_KEY.match(key), key)     # and the trigger accepts it

    def test_files_evtxkit_cannot_read_are_turned_away(self):
        self.assertEqual(upload_api.ALLOWED_EXTENSIONS, s3_wrapper.KNOWN_EXTENSIONS)
        for name in ("payload.exe", "report.pdf", "Security.evtx.zip", "no-extension", "", ".evtx", "....xml",
                     "Security.evtx/", None, 7):
            status, body, _ = call("POST", "/api/uploads", {"filename": name})
            self.assertEqual(status, 400, name)
            self.assertIn(".evtx", body["error"])

    def test_size_is_checked_early_and_enforced_by_the_signature(self):
        env = dict(API_ENV, MAX_UPLOAD_BYTES="1000", UPLOAD_EXPIRES_SECONDS="60")
        status, body, _ = call("POST", "/api/uploads", {"filename": "a.evtx", "size": 1001}, env=env)
        self.assertEqual(status, 413)
        self.assertIn("too large", body["error"])
        self.assertEqual(call("POST", "/api/uploads", {"filename": "a.evtx", "size": 0}, env=env)[0], 400)
        # Whatever the page claims about the size, the limit is in what S3 checks.
        for claimed in (1000, None, "12", True):
            status, body, _ = call("POST", "/api/uploads", {"filename": "a.evtx", "size": claimed}, env=env)
            self.assertEqual(status, 201, claimed)
            self.assertIn(["content-length-range", 1, 1000], policy(body["upload"]["fields"])["conditions"])
            self.assertEqual(body["expires_in"], 60)

    def test_request_bodies(self):
        for bad in ("{not json", "[1, 2]", '"text"'):
            self.assertEqual(call("POST", "/api/uploads", bad)[0], 400, bad)
        encoded = base64.b64encode(json.dumps({"filename": "a.xml"}).encode()).decode()
        self.assertEqual(call("POST", "/api/uploads", encoded, isBase64Encoded=True)[0], 201)
        self.assertEqual(call("POST", "/api/uploads", "%%%not-base64", isBase64Encoded=True)[0], 400)

    # ---- job status ---------------------------------------------------------
    def test_a_job_with_no_status_yet_is_queued(self):
        # Without permission to list the bucket, S3 answers 403 for a missing key, not 404.
        for missing_status in (404, 403):
            s3 = local.LocalS3(missing_status=missing_status)
            self.assertEqual(call("GET", f"/api/jobs/{JOB}", s3=s3)[:2], (200, {"job_id": JOB, "state": "queued"}))

    def test_other_s3_errors_are_not_mistaken_for_queued(self):
        class Unwell(local.LocalS3):
            def get_object(self, Bucket, Key):
                raise local.S3Error("SlowDown", 503)

        with self.assertRaises(local.S3Error):
            call("GET", f"/api/jobs/{JOB}", s3=Unwell())

    def test_running_and_failed_jobs(self):
        s3 = local.LocalS3()
        write_status(s3)
        self.assertEqual(call("GET", f"/api/jobs/{JOB}", s3=s3)[1],
                         {"job_id": JOB, "state": "running", "started": "2026-10-05T10:00:00Z", "finished": None})
        write_status(s3, state="failed", error="The uploaded file is empty.", finished="2026-10-05T10:00:09Z")
        self.assertEqual(call("GET", f"/api/jobs/{JOB}", s3=s3)[1],
                         {"job_id": JOB, "state": "failed", "started": "2026-10-05T10:00:00Z",
                          "finished": "2026-10-05T10:00:09Z", "error": "The uploaded file is empty."})

    def test_a_finished_job_comes_with_its_report(self):
        s3 = local.LocalS3()
        report = "# evtxkit analysis: `Security.evtx`\n\n<script>alert(1)</script> caf\u00e9\n"
        s3.put_object(REPORTS, f"reports/{JOB}/report.md", report.encode("utf-8"))
        write_status(s3, state="done", report_key=f"reports/{JOB}/report.md", finished="2026-10-05T10:01:00Z",
                     analysis_exit_code=1, high_or_critical_findings=True)
        status, body, _ = call("GET", f"/api/jobs/{JOB}", s3=s3)
        self.assertEqual(status, 200)
        self.assertEqual((body["state"], body["report"], body["high_or_critical_findings"]), ("done", report, True))
        self.assertEqual(body["report_name"], "evtxkit-report-01234567.md")
        # The download link is for that report only, and makes the browser save it rather than open it.
        bucket, key = REPORTS, f"reports/{JOB}/report.md"
        signature = body["download_url"].split("X-Amz-Signature=")[1]
        self.assertEqual(s3.open_link(bucket, key, signature),
                         (report.encode("utf-8"), 'attachment; filename="evtxkit-report-01234567.md"'))
        # Nothing about where things are stored reaches the page.
        self.assertEqual(set(body), {"job_id", "state", "started", "finished", "high_or_critical_findings",
                                     "report_name", "report", "download_url"})
        self.assertNotIn(UPLOADS, json.dumps(body))

    def test_a_large_report_is_download_only(self):
        s3 = local.LocalS3()
        s3.put_object(REPORTS, f"reports/{JOB}/report.md", b"x" * 5000)
        write_status(s3, state="done", report_key=f"reports/{JOB}/report.md")
        body = call("GET", f"/api/jobs/{JOB}", s3=s3, env=dict(API_ENV, MAX_INLINE_REPORT_BYTES="4999"))[1]
        self.assertEqual((body["state"], body["report"]), ("done", None))
        self.assertIn("X-Amz-Signature=", body["download_url"])
        body = call("GET", f"/api/jobs/{JOB}", s3=s3, env=dict(API_ENV, MAX_INLINE_REPORT_BYTES="5000"))[1]
        self.assertEqual(len(body["report"]), 5000)

    def test_only_ids_this_api_made_can_be_asked_about(self):
        s3 = local.LocalS3()
        for job_id in ("manual-test-1", JOB.upper(), JOB[:-1], JOB + "0", JOB.split("-", 1)[1],   # no owner in front
                       BOB_JOB, "carol-" + "0" * 32,                       # someone else's, and nobody's
                       "..", "%2e%2e", "status.json"):
            write_status(s3, job_id=job_id, state="done", report_key=f"reports/{job_id}/report.md")
            self.assertEqual(call("GET", f"/api/jobs/{job_id}", s3=s3)[0], 404, job_id)
        self.assertEqual(call("GET", f"/api/jobs/{JOB}/report.md", s3=s3)[0], 404)

    def test_a_status_file_cannot_point_the_api_at_another_object(self):
        s3 = local.LocalS3()
        s3.put_object(REPORTS, "reports/someone-else/report.md", b"not yours")
        for elsewhere in ("reports/someone-else/report.md", "report.md", f"reports/{JOB}0/report.md",
                          f"reports/{JOB}/../someone-else/report.md", None):
            write_status(s3, state="done", report_key=elsewhere)
            status, body, _ = call("GET", f"/api/jobs/{JOB}", s3=s3)
            self.assertEqual(status, 502, elsewhere)
            self.assertNotIn("not yours", json.dumps(body))
        s3.put_object(REPORTS, f"reports/{JOB}/status.json", b"{broken")
        self.assertEqual(call("GET", f"/api/jobs/{JOB}", s3=s3)[0], 502)
        write_status(s3, state="done", report_key=f"reports/{JOB}/report.md")      # says done, but no report
        self.assertEqual(call("GET", f"/api/jobs/{JOB}", s3=s3)[0], 502)

    def test_routes_and_methods(self):
        self.assertEqual(call("GET", "/api/uploads")[0], 405)
        self.assertEqual(call("POST", f"/api/jobs/{JOB}")[0], 405)
        self.assertEqual(call("DELETE", f"/api/jobs/{JOB}")[0], 405)
        for path in ("/api/", "/api/jobs", "/api/jobs/", "/api/nope", "/nope"):
            self.assertEqual(call("GET", path)[0], 404, path)


# --------------------------------------------------------------------------
# The page's files
# --------------------------------------------------------------------------

class TestPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html, cls.js = (read("aws", "lambda", "upload_api", "web", name) for name in ("index.html", "app.js"))

    def test_every_element_the_script_uses_is_on_the_page(self):
        ids = re.findall(r'\bid="([^"]+)"', self.html)
        self.assertEqual(len(ids), len(set(ids)), "an id is used twice")
        used = set(re.findall(r'\$\("([^"]+)"\)', self.js))
        self.assertGreater(len(used), 10)
        self.assertEqual(used - set(ids), set())

    def test_nothing_is_inline(self):
        # The page's Content-Security-Policy only allows scripts and styles from its own origin.
        self.assertNotRegex(self.html, r"<style|\sstyle=|\son\w+=|javascript:")
        scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", self.html, re.S)
        self.assertEqual([(attrs.strip(), body.strip()) for attrs, body in scripts], [('src="app.js"', "")])

    def test_what_the_server_sends_is_never_treated_as_html(self):
        # A report quotes the uploaded log, and a log holds whatever an attacker typed.
        for risky in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            self.assertNotIn(risky, self.js)
        self.assertIn("els.report.textContent = view.report", self.js)

    def test_the_page_the_api_and_the_wrapper_accept_the_same_files(self):
        accept = tuple(re.search(r'accept="([^"]+)"', self.html).group(1).split(","))
        in_script = tuple(json.loads("[" + re.search(r"const EXTENSIONS = \[([^\]]+)\]", self.js).group(1) + "]"))
        self.assertEqual(accept, upload_api.ALLOWED_EXTENSIONS)
        self.assertEqual(in_script, upload_api.ALLOWED_EXTENSIONS)

    def test_the_page_says_how_long_files_are_kept_and_what_a_clean_report_means(self):
        text = re.sub(r"\s+", " ", html_module.unescape(re.sub(r"<[^>]+>", " ", self.html)))   # as a browser shows it
        days = {json.loads(read("aws", name))["Rules"][0]["Expiration"]["Days"]
                for name in ("uploads-bucket-lifecycle.json", "reports-bucket-lifecycle.json")}
        self.assertEqual(days, {1})                               # S3's smallest: gone within two days
        self.assertIn("we don’t keep your files", text)
        self.assertIn("deleted as soon as it has been analysed", text)   # what the task really does
        self.assertIn("removed automatically within two days", text)     # what the lifecycle rule really does
        self.assertNotIn("7 days", text)
        self.assertIn("does not prove that a system is clean", text)
        self.assertIn("only logs you are allowed to share", text)

    def test_the_page_waits_longer_than_the_task_may_run(self):
        factors = re.search(r"const TOTAL_TIMEOUT_MS = ([\d *]+);", self.js).group(1).split("*")
        self.assertGreater(math.prod(int(f) for f in factors) / 1000, s3_wrapper.DEFAULT_TIMEOUT_SECONDS + 120)


# --------------------------------------------------------------------------
# aws/*.json and the runbook
# --------------------------------------------------------------------------

ACCOUNT, REGION = "772325758655", "eu-north-1"


def policy_file(name: str) -> dict:
    """{action: statement} for a permissions policy in aws/."""
    statements = json.loads(read("aws", name))["Statement"]
    by_action = {}
    for statement in statements:
        assert statement["Effect"] == "Allow", name
        for action in as_list(statement["Action"]):
            assert action not in by_action, f"{name}: {action} is granted twice"
            by_action[action] = statement
    return by_action


class TestAwsFiles(unittest.TestCase):
    PERMISSIONS = ("s3-write-policy.json", "s3-read-uploads-policy.json",
                   "lambda-start-analysis-policy.json", "lambda-upload-api-policy.json")

    def test_every_file_parses_and_stays_in_one_region_and_account(self):
        names = [name for name in sorted(os.listdir(AWS)) if name.endswith(".json")]
        self.assertGreaterEqual(len(names), 12)
        for name in names:
            text = read("aws", name)
            json.loads(text)
            for region, account in re.findall(r"arn:aws:[a-z0-9-]+:([a-z0-9-]*):(\d*):", text):
                self.assertIn(region, ("", REGION), name)
                self.assertIn(account, ("", ACCOUNT), name)
        self.assertIn(f'"awslogs-region": "{REGION}"', read("aws", "task-definition.json"))

    def test_no_policy_grants_a_wildcard(self):
        for name in self.PERMISSIONS:
            for action, statement in policy_file(name).items():
                self.assertNotIn("*", action, name)
                for resource in as_list(statement["Resource"]):
                    self.assertRegex(resource, r"^arn:aws:[a-z0-9]+:[a-z0-9-]*:\d*:.+", name)
                    self.assertNotRegex(resource, r"^arn:aws:[a-z0-9]+:[a-z0-9-]*:\d*:\*$", name)

    def test_the_task_reads_and_deletes_uploads_and_writes_reports_and_nothing_else(self):
        read_policy, write_policy = policy_file("s3-read-uploads-policy.json"), policy_file("s3-write-policy.json")
        self.assertEqual({a: s["Resource"] for a, s in read_policy.items()},
                         {"s3:GetObject": f"arn:aws:s3:::evtxkit-uploads-{ACCOUNT}/*",
                          "s3:DeleteObject": f"arn:aws:s3:::evtxkit-uploads-{ACCOUNT}/uploads/*"})   # delete: only what was uploaded
        self.assertEqual({a: s["Resource"] for a, s in write_policy.items()},
                         {"s3:PutObject": f"arn:aws:s3:::evtxkit-reports-{ACCOUNT}/*"})

    def test_the_trigger_may_start_this_task_and_pass_its_two_roles_and_nothing_else(self):
        task = json.loads(read("aws", "task-definition.json"))
        granted = policy_file("lambda-start-analysis-policy.json")
        self.assertEqual(set(granted), {"ecs:RunTask", "iam:PassRole", "logs:CreateLogStream", "logs:PutLogEvents"})
        family = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{task['family']}"
        # Both spellings: the function names the family, and ECS then checks the ARN without a revision.
        self.assertEqual(sorted(granted["ecs:RunTask"]["Resource"]), [family, family + ":*"])
        self.assertEqual(granted["ecs:RunTask"]["Condition"],
                         {"ArnEquals": {"ecs:cluster": f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/evtxkit-cluster"}})
        # Exactly the two roles the task definition names, and only to hand them to ECS tasks.
        self.assertEqual(sorted(granted["iam:PassRole"]["Resource"]),
                         sorted([task["executionRoleArn"], task["taskRoleArn"]]))
        self.assertEqual(granted["iam:PassRole"]["Condition"],
                         {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}})
        self.assertEqual(granted["logs:PutLogEvents"]["Resource"],
                         f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/evtxkit-start-analysis:*")

    def test_the_page_may_sign_uploads_and_read_reports_and_nothing_else(self):
        granted = policy_file("lambda-upload-api-policy.json")
        self.assertEqual(set(granted), {"s3:PutObject", "s3:GetObject", "logs:CreateLogStream", "logs:PutLogEvents"})
        self.assertEqual(granted["s3:PutObject"]["Resource"], f"arn:aws:s3:::evtxkit-uploads-{ACCOUNT}/uploads/*")
        self.assertEqual(granted["s3:GetObject"]["Resource"], f"arn:aws:s3:::evtxkit-reports-{ACCOUNT}/reports/*")
        self.assertEqual(granted["logs:PutLogEvents"]["Resource"],
                         f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/evtxkit-upload-api:*")

    def test_the_ci_key_can_push_register_and_run_the_test_task_and_nothing_else(self):
        granted = policy_file("ci-deploy-policy.json")
        self.assertEqual(set(granted), {
            "ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload",
            "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:PutImage",
            "ecs:RegisterTaskDefinition", "ecs:RunTask", "iam:PassRole"})
        # Only the two calls AWS cannot scope to a resource may name "*".
        self.assertEqual({a for a, s in granted.items() if s["Resource"] == "*"},
                         {"ecr:GetAuthorizationToken", "ecs:RegisterTaskDefinition"})
        # The takeover paths a deploy key must never have: writing IAM, reading data, touching the functions.
        for action in granted:
            self.assertFalse(action.startswith(("iam:Create", "iam:Put", "iam:Attach", "iam:Update", "s3:", "lambda:", "sts:")), action)
        task = json.loads(read("aws", "task-definition.json"))
        self.assertEqual(sorted(granted["ecs:RunTask"]["Resource"]),
                         [f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{task['family']}",
                          f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{task['family']}:*"])
        self.assertEqual(granted["ecs:RunTask"]["Condition"],
                         {"ArnEquals": {"ecs:cluster": f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/evtxkit-cluster"}})
        self.assertEqual(sorted(granted["iam:PassRole"]["Resource"]), sorted([task["executionRoleArn"], task["taskRoleArn"]]))
        self.assertEqual(granted["iam:PassRole"]["Condition"], {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}})
        self.assertEqual(granted["ecr:PutImage"]["Resource"], f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/evtxkit")
        # And it is what the workflow really uses.
        workflow = read(".github", "workflows", "ci.yml")
        for used in (f"--task-definition {task['family']}", "evtxkit-cluster", "/evtxkit:", "register-task-definition", "ecr-login"):
            self.assertIn(used, workflow)

    def test_both_functions_are_assumed_by_lambda_only(self):
        (statement,) = json.loads(read("aws", "lambda-trust-policy.json"))["Statement"]
        self.assertEqual((statement["Principal"], statement["Action"]),
                         ({"Service": "lambda.amazonaws.com"}, "sts:AssumeRole"))

    def test_the_bucket_notifies_the_trigger_for_uploads_only(self):
        (rule,) = json.loads(read("aws", "uploads-bucket-notification.json"))["LambdaFunctionConfigurations"]
        self.assertEqual(rule["LambdaFunctionArn"], f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:evtxkit-start-analysis")
        self.assertEqual(rule["Events"], ["s3:ObjectCreated:*"])
        self.assertEqual(rule["Filter"]["Key"]["FilterRules"], [{"Name": "prefix", "Value": "uploads/"}])

    def test_uploads_and_reports_both_expire_after_one_day(self):
        # The task deletes an upload when it has analysed it; the rule is the backstop for a task that dies first.
        # Reports quote the customer's log, so they must not be kept either. One day is S3's smallest, and means gone within two.
        for name, prefix in (("uploads-bucket-lifecycle.json", ""), ("reports-bucket-lifecycle.json", "reports/")):
            (rule,) = json.loads(read("aws", name))["Rules"]
            self.assertEqual((rule["Status"], rule["Expiration"], rule["Filter"]), ("Enabled", {"Days": 1}, {"Prefix": prefix}), name)
            self.assertEqual(rule["AbortIncompleteMultipartUpload"], {"DaysAfterInitiation": 1}, name)

    def test_the_bucket_lets_one_origin_post_and_nothing_else(self):
        (rule,) = json.loads(read("aws", "uploads-bucket-cors.json"))["CORSRules"]
        self.assertEqual(rule["AllowedMethods"], ["POST"])
        self.assertEqual(len(rule["AllowedOrigins"]), 1)
        self.assertNotIn("*", rule["AllowedOrigins"][0])

    def test_the_task_definition_fits_the_flow(self):
        task = json.loads(read("aws", "task-definition.json"))
        (container,) = task["containerDefinitions"]
        self.assertEqual(container["name"], "evtxkit")       # the name the trigger's override is addressed to
        self.assertIn({"name": "REPORT_BUCKET", "value": f"evtxkit-reports-{ACCOUNT}"}, container["environment"])
        self.assertTrue(task["executionRoleArn"].endswith(":role/ecsTaskExecutionRole"))
        self.assertTrue(task["taskRoleArn"].endswith(":role/evtxkitTaskRole"))
        overrides = json.loads(read("aws", "run-task-overrides.example.json"))["containerOverrides"][0]
        self.assertEqual((overrides["name"], [e["name"] for e in overrides["environment"]]),
                         ("evtxkit", ["INPUT_BUCKET", "INPUT_KEY"]))

    def test_the_runbook_names_things_that_exist(self):
        runbook = read("aws", "UPLOAD-FLOW.md")
        referenced = set(re.findall(r"file://aws/([\w.-]+\.json)", runbook)) - {"task-definition-updated.json"}
        self.assertGreaterEqual(len(referenced), 7)
        for name in referenced:
            self.assertTrue(os.path.exists(os.path.join(AWS, name)), name)
        for setting in start_analysis.REQUIRED + ("USERS", "REPORT_BUCKET", "handler.handler",
                                                  "evtxkit-start-analysis", "evtxkit-upload-api",
                                                  "tools/local_upload_flow.py", "tools/access_codes.py",
                                                  "tools/build_lambdas.py"):
            self.assertIn(setting, runbook)
        for folder in re.findall(r"cd (aws/lambda/\w+)", runbook):
            self.assertTrue(os.path.exists(os.path.join(ROOT, folder, "handler.py")), folder)


# --------------------------------------------------------------------------
# All of it together, over HTTP, the way a browser drives it
# --------------------------------------------------------------------------

def multipart(fields: dict, filename: str, data: bytes) -> tuple[str, bytes]:
    """A browser's form upload: (Content-Type, body). The file goes last, as S3 requires."""
    boundary = "----evtxkitTestBoundary7MA4YWxkTrZu0gW"
    lines: list[bytes] = []
    for name, value in fields.items():
        lines += [f"--{boundary}".encode(), f'Content-Disposition: form-data; name="{name}"'.encode(), b"",
                  str(value).encode()]
    lines += [f"--{boundary}".encode(),
              f'Content-Disposition: form-data; name="file"; filename="{filename}"'.encode(),
              b"Content-Type: application/octet-stream", b"", data, f"--{boundary}--".encode(), b""]
    return f"multipart/form-data; boundary={boundary}", b"\r\n".join(lines)


class TestLocalFlow(unittest.TestCase):
    """tools/local_upload_flow.py with the "task" run inline, so a job is finished when its upload returns."""

    @classmethod
    def setUpClass(cls):
        cls.logs: list[str] = []
        cls.httpd, cls.flow = local.make_server(0, access_code=CODE, background=False,
                                                log=lambda *args, **kwargs: cls.logs.append(" ".join(map(str, args))))
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        self.flow.ecs.calls.clear()
        self.flow.ecs.failures = []
        self.flow.trigger_errors.clear()

    def http(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        """(status, headers, body) of one request to the local server."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
        finally:
            conn.close()

    def api(self, method: str, path: str, body: dict | None = None, code: str | None = CODE):
        headers = {"X-Access-Code": code} if code is not None else {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        status, _headers, data = self.http(method, path, json.dumps(body).encode() if body is not None else None, headers)
        return status, json.loads(data)

    def upload(self, filename: str, data: bytes, claimed_size: int | None = None, **changed_fields):
        """Ask for an upload and send the file, as the page does: (job id, key, status and body of the S3 answer)."""
        size = len(data) if claimed_size is None else claimed_size
        status, made = self.api("POST", "/api/uploads", {"filename": filename, "size": size})
        self.assertEqual(status, 201)
        fields = dict(made["upload"]["fields"], **changed_fields)
        content_type, body = multipart(fields, filename, data)
        status, _headers, answer = self.http("POST", made["upload"]["url"], body, {"Content-Type": content_type})
        return made["job_id"], made["upload"]["fields"]["key"], status, answer.decode()

    def test_from_upload_to_report(self):
        status, headers, page = self.http("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Windows event log analysis", page)
        self.assertIn("connect-src 'self';", headers["content-security-policy"])   # the local "S3" is this server
        self.assertEqual(self.http("GET", "/app.js")[0], 200)

        data = sample("rdp_brute_force.jsonl")
        job_id, key, status, _ = self.upload("RDP brute force (1).jsonl", data)
        self.assertEqual(status, 204)
        self.assertEqual(key, f"uploads/{job_id}/RDP_brute_force_1.jsonl")
        self.assertEqual(self.flow.s3.uploaded[(local.UPLOADS_BUCKET, key)], data)      # it arrived byte for byte...
        self.assertNotIn((local.UPLOADS_BUCKET, key), self.flow.s3.objects)             # ...and is gone once analysed

        # The upload itself started exactly one task, told only where the file is.
        (request,) = self.flow.ecs.calls
        self.assertEqual(request["overrides"]["containerOverrides"][0]["environment"],
                         [{"name": "INPUT_BUCKET", "value": local.UPLOADS_BUCKET}, {"name": "INPUT_KEY", "value": key}])
        self.assertEqual(self.flow.trigger_errors, [])

        status, job = self.api("GET", f"/api/jobs/{job_id}")
        self.assertEqual((status, job["state"], job["high_or_critical_findings"]), (200, "done", True))
        self.assertIn("EVTX-LOGON-BRUTE-01", job["report"])
        self.assertIn("`RDP_brute_force_1.jsonl`", job["report"])

        status, headers, downloaded = self.http("GET", job["download_url"])
        self.assertEqual((status, downloaded.decode("utf-8")), (200, job["report"]))
        self.assertEqual(headers["content-disposition"], f'attachment; filename="evtxkit-report-{job_id.split("-", 1)[1][:8]}.md"')

        # The task's log has the facts and no data; S3 holds only the report and the status.
        transcript = self.flow.ecs.transcripts[-1]
        self.assertIn(f"Uploaded to s3://{local.REPORT_BUCKET}/reports/{job_id}/report.md", transcript)
        self.assertIn("analysed: exit=1 events=21 findings=2 worst=critical input_deleted=True", transcript)
        self.assertNotIn("EVTX-LOGON-BRUTE", transcript)
        self.assertNotIn("# evtxkit analysis", transcript)
        self.assertEqual(sorted(k for b, k in self.flow.s3.objects if b == local.REPORT_BUCKET and job_id in k),
                         [f"reports/{job_id}/report.md", f"reports/{job_id}/status.json"])
        self.assertTrue(any("upload_signed" in line for line in self.logs))

    def test_a_file_that_is_not_a_log_fails_with_a_reason_and_arrives_byte_for_byte(self):
        data = b"\r\n--not-the-boundary\r\n\x00\xff\xfe MZ not an event log \r\n" * 40
        job_id, key, status, _ = self.upload("holiday photos.evtx", data)
        self.assertEqual(status, 204)
        self.assertEqual(self.flow.s3.uploaded[(local.UPLOADS_BUCKET, key)], data)
        self.assertNotIn((local.UPLOADS_BUCKET, key), self.flow.s3.objects)             # a failed job deletes it too
        status, job = self.api("GET", f"/api/jobs/{job_id}")
        self.assertEqual((status, job["state"]), (200, "failed"))
        self.assertTrue(job["error"].startswith("The file could not be analysed as a Windows event log"), job["error"])
        self.assertNotIn("report", job)
        self.assertNotIn((local.REPORT_BUCKET, f"reports/{job_id}/report.md"), self.flow.s3.objects)

    def test_s3_refuses_what_the_upload_was_not_signed_for(self):
        data = sample("clean_baseline.jsonl")
        stored_before = len(self.flow.s3.objects)
        self.flow.api_env["MAX_UPLOAD_BYTES"] = str(len(data) - 1)
        try:                                            # a page that lies about the size gets a link, and no further
            job_id, _key, status, answer = self.upload("a.jsonl", data, claimed_size=10)
            self.assertEqual((status, "<Code>EntityTooLarge</Code>" in answer), (400, True))
        finally:
            del self.flow.api_env["MAX_UPLOAD_BYTES"]
        for changed, code in (({"key": "uploads/someone-else/a.jsonl"}, "AccessDenied"),
                              ({"key": "reports/x/status.json"}, "AccessDenied"),
                              ({"x-amz-signature": "0" * 64}, "AccessDenied")):
            _job, _key, status, answer = self.upload("a.jsonl", data, **changed)
            self.assertEqual((status, f"<Code>{code}</Code>" in answer), (403, True), changed)
        _job, _key, status, answer = self.upload("a.jsonl", b"", claimed_size=10)
        self.assertEqual((status, "<Code>EntityTooSmall</Code>" in answer), (400, True))
        # None of those stored anything or started a task.
        self.assertEqual((len(self.flow.s3.objects), self.flow.ecs.calls), (stored_before, []))
        self.assertEqual(self.api("GET", f"/api/jobs/{job_id}")[1], {"job_id": job_id, "state": "queued"})

    def test_the_task_not_starting_leaves_the_job_queued(self):
        # The uploader cannot see the trigger fail; the page gives up waiting after a few minutes.
        self.flow.ecs.failures = [{"reason": "Capacity is unavailable at this time"}]
        job_id, _key, status, _ = self.upload("a.jsonl", sample("clean_baseline.jsonl"))
        self.assertEqual(status, 204)
        self.assertEqual(self.api("GET", f"/api/jobs/{job_id}")[1], {"job_id": job_id, "state": "queued"})
        (error,) = self.flow.trigger_errors
        self.assertIn("Capacity is unavailable", str(error))

    def test_the_api_over_http_needs_the_code_and_the_right_host(self):
        self.assertEqual(self.api("POST", "/api/uploads", {"filename": "a.evtx"}, code=None)[0], 401)
        self.assertEqual(self.api("GET", f"/api/jobs/{JOB}", code="wrong")[0], 401)
        self.assertEqual(self.http("GET", "/", headers={"Host": "attacker.example"})[0], 403)
        self.assertEqual(self.http("GET", f"{local.S3_PATH}/{local.REPORT_BUCKET}/reports/{JOB}/report.md")[0], 403)
        self.assertEqual(self.http("PUT", f"{local.S3_PATH}/{local.UPLOADS_BUCKET}")[0], 405)


# --------------------------------------------------------------------------
# The sample logs the page offers
# --------------------------------------------------------------------------

class TestSamples(unittest.TestCase):
    def test_what_the_page_says_to_expect_is_what_evtxkit_really_finds(self):
        catalog = upload_api.sample_catalog()
        listed = json.loads(read("aws", "lambda", "upload_api", "samples.json"))
        self.assertEqual(set(catalog), {e["file"] for e in listed})      # every listed file is there and accepted
        outcomes = set()
        for name, entry in catalog.items():
            result = s3_wrapper.run_evtxkit(["analyze", entry["path"], "-f", "json"], cwd=ROOT)
            report = json.loads(result.stdout)
            self.assertEqual(entry["worst"], report["worst_severity"], name)
            self.assertEqual(sorted(entry["rules"]), sorted({f["rule_id"] for f in report["findings"]}), name)
            high = entry["worst"] in ("high", "critical")
            self.assertEqual(result.returncode, 1 if high else 0, name)   # the exit code is what the verdict is made from
            outcomes.add("high" if high else "below" if entry["rules"] else "none")
        # A tester sees all three kinds of answer: findings, findings below high, and a clean log.
        self.assertEqual(outcomes, {"high", "below", "none"})

    def test_the_list_and_the_files_need_a_code(self):
        for path in ("/api/samples", "/api/samples/rdp_brute_force.jsonl"):
            for code in (None, "", "wrong"):
                self.assertEqual(call("GET", path, code=code)[0], 401, (path, code))

    def test_the_list_says_what_each_sample_is_and_hides_where_it_is_kept(self):
        status, body, _ = call("GET", "/api/samples")
        self.assertEqual(status, 200)
        self.assertIn("rdp_brute_force.jsonl", [s["file"] for s in body["samples"]])
        for entry in body["samples"]:
            self.assertEqual(set(entry), {"file", "title", "about", "worst", "rules", "bytes"})
        self.assertNotIn(ROOT, json.dumps(body))
        self.assertEqual(call("POST", "/api/samples")[0], 405)

    def test_a_sample_arrives_byte_for_byte(self):
        self.assertIn(b"\r\n", sample("log_cleared.xml"))        # the line endings are part of the evidence
        for name in upload_api.sample_catalog():
            status, _body, response = call("GET", f"/api/samples/{name}")
            self.assertEqual(status, 200, name)
            self.assertTrue(response["isBase64Encoded"], name)
            self.assertEqual(base64.b64decode(response["body"]), sample(name), name)
            self.assertEqual(response["headers"]["Content-Disposition"], f'attachment; filename="{name}"')
        self.assertEqual(call("POST", "/api/samples/log_cleared.xml")[0], 405)

    def test_only_listed_samples_can_be_asked_for(self):
        for name in ("nope.jsonl", "../handler.py", "..%2Fhandler.py", "..%5Chandler.py", "handler.py", "samples.json",
                     "RDP_BRUTE_FORCE.JSONL", "rdp_brute_force.jsonl/", "%2e%2e", "", "clean_baseline_ConsoleHost_history.txt"):
            self.assertEqual(call("GET", f"/api/samples/{name}")[0], 404, name)

    def test_a_bad_or_missing_listing_never_reaches_the_file_system(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "samples"))
            for path, data in ((("samples", "ok.jsonl"), b"{}"), (("secret.txt",), b"secret")):
                with open(os.path.join(tmp, *path), "wb") as fh:
                    fh.write(data)
            listing = os.path.join(tmp, "samples.json")
            saved = (upload_api.HERE, upload_api.SAMPLE_FOLDERS)
            upload_api.HERE, upload_api.SAMPLE_FOLDERS = tmp, (os.path.join(tmp, "samples"),)
            try:
                def catalog(text: str | None) -> set:
                    if text is None:
                        if os.path.exists(listing):
                            os.remove(listing)
                    else:
                        with open(listing, "w", encoding="utf-8") as fh:
                            fh.write(text)
                    upload_api._samples.clear()
                    return set(upload_api.sample_catalog())

                bad = [{"file": "ok.jsonl"}, {"file": "../secret.txt"}, {"file": "secret.txt"}, {"file": "missing.jsonl"},
                       {"file": "ok.exe"}, {"file": "a/b.jsonl"}, {"file": "a\\b.jsonl"}, {"file": "x" * 90 + ".jsonl"},
                       "text", {"file": 7}, {}, None]
                self.assertEqual(catalog(json.dumps(bad)), {"ok.jsonl"})
                self.assertEqual(catalog("not json"), set())
                self.assertEqual(catalog('{"file": "ok.jsonl"}'), set())      # an object, not a list
                self.assertEqual(catalog(None), set())                        # no listing at all
            finally:
                upload_api.HERE, upload_api.SAMPLE_FOLDERS = saved
                upload_api._samples.clear()


# --------------------------------------------------------------------------
# tools/build_lambdas.py: the zips that are deployed
# --------------------------------------------------------------------------

class TestBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.TemporaryDirectory()
        with contextlib.redirect_stdout(io.StringIO()):
            assert build_lambdas.main(["--out", cls.out.name]) == 0
        cls.api = zipfile.ZipFile(os.path.join(cls.out.name, "upload-api.zip"))
        cls.trigger = zipfile.ZipFile(os.path.join(cls.out.name, "start-analysis.zip"))

    @classmethod
    def tearDownClass(cls):
        cls.api.close()
        cls.trigger.close()
        cls.out.cleanup()

    def test_what_is_in_each_zip(self):
        self.assertEqual(self.trigger.namelist(), ["handler.py"])
        listed = [e["file"] for e in json.loads(read("aws", "lambda", "upload_api", "samples.json"))]
        self.assertEqual(self.api.namelist(),
                         sorted(["handler.py", "samples.json", "web/app.css", "web/app.js", "web/index.html"]
                                + [f"samples/{name}" for name in listed]))
        for info in self.api.infolist() + self.trigger.infolist():
            self.assertEqual(info.external_attr >> 16, 0o644, info.filename)    # a function's user can read them
            self.assertNotIn("__pycache__", info.filename)
        self.assertLess(sum(i.compress_size for i in self.api.infolist()), 100 * 1024)

    def test_the_samples_in_the_zip_are_the_repositorys_own_bytes(self):
        for info in self.api.infolist():
            if info.filename.startswith("samples/") and info.filename != "samples.json":
                self.assertEqual(self.api.read(info.filename), sample(info.filename.split("/", 1)[1]), info.filename)

    def test_the_same_files_make_the_same_zip(self):
        with tempfile.TemporaryDirectory() as again, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(build_lambdas.main(["--out", again]), 0)
            for name in ("upload-api.zip", "start-analysis.zip"):
                with open(os.path.join(again, name), "rb") as one, open(os.path.join(self.out.name, name), "rb") as two:
                    self.assertEqual(one.read(), two.read(), name)

    def test_the_function_works_from_the_unpacked_zip(self):
        # What Lambda runs: the zip's own layout, with no repository around it.
        with tempfile.TemporaryDirectory() as unpacked:
            self.api.extractall(unpacked)
            spec = importlib.util.spec_from_file_location("lambda_upload_api_unpacked", os.path.join(unpacked, "handler.py"))
            module = importlib.util.module_from_spec(spec)
            cached, sys.dont_write_bytecode = sys.dont_write_bytecode, True
            try:
                spec.loader.exec_module(module)
            finally:
                sys.dont_write_bytecode = cached
            module.print = lambda *args, **kwargs: None
            self.assertTrue(module.SAMPLE_FOLDERS[0].startswith(unpacked))
            request = {"rawPath": "/api/samples", "headers": {"x-access-code": CODE},
                       "requestContext": {"http": {"method": "GET", "path": "/api/samples"}}}
            response = module.handle(request, API_ENV, local.LocalS3())
            listed = json.loads(response["body"])["samples"]
            self.assertEqual({s["file"] for s in listed}, set(upload_api.sample_catalog()))
            request.update(rawPath="/api/samples/log_cleared.xml")
            response = module.handle(request, API_ENV, local.LocalS3())
            self.assertEqual(base64.b64decode(response["body"]), sample("log_cleared.xml"))
            page = module.handle({"rawPath": "/", "requestContext": {"http": {"method": "GET"}}}, API_ENV,
                                 local.LocalS3(base_url="https://b.s3.eu-north-1.amazonaws.com"))
            self.assertIn("Try a sample", page["body"])

    def test_a_listed_sample_that_is_missing_stops_the_build(self):
        saved = build_lambdas.SAMPLES
        build_lambdas.SAMPLES = os.path.join(ROOT, "no-such-folder")
        try:
            with contextlib.redirect_stderr(io.StringIO()) as err, tempfile.TemporaryDirectory() as out:
                self.assertEqual(build_lambdas.main(["--out", out]), 2)
                self.assertEqual(os.listdir(out), [])
            self.assertIn("build_lambdas:", err.getvalue())
        finally:
            build_lambdas.SAMPLES = saved


# --------------------------------------------------------------------------
# tools/access_codes.py: where the codes and their fingerprints come from
# --------------------------------------------------------------------------

def run_codes(*argv):
    """(exit code, stdout, stderr) of one run of the tool."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = access_codes.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def printed_codes(out: str) -> dict:
    """{name: code} for the codes the tool showed."""
    found = (re.fullmatch(r"  ([a-z][a-z0-9]+)\s+([A-Za-z0-9_-]{24})", line) for line in out.splitlines())
    return {m.group(1): m.group(2) for m in found if m}


def printed_setting(out: str) -> dict:
    return json.loads(next(line for line in out.splitlines() if line.startswith("{")))


class TestAccessCodes(unittest.TestCase):
    def test_new_people_get_random_codes_and_the_setting_holds_only_fingerprints(self):
        code, out, _err = run_codes("alice", "bob")
        self.assertEqual(code, 0)
        codes, setting = printed_codes(out), printed_setting(out)
        self.assertEqual(set(codes), {"alice", "bob"})
        self.assertNotEqual(codes["alice"], codes["bob"])
        for name, secret in codes.items():
            self.assertEqual(setting[name], sha256(secret))
            self.assertNotIn(secret, json.dumps(setting))
        # The function accepts exactly those codes, for exactly those people.
        users = upload_api.load_users({"USERS": json.dumps(setting)})
        self.assertEqual(upload_api.who({"x-access-code": codes["bob"]}, users), "bob")
        self.assertIsNone(upload_api.who({"x-access-code": codes["bob"] + "x"}, users))
        self.assertIsNone(upload_api.who({}, users))

    def test_every_run_makes_new_codes(self):
        first = printed_codes(run_codes("alice")[1])["alice"]
        self.assertNotEqual(first, printed_codes(run_codes("alice")[1])["alice"])

    def test_adding_removing_and_replacing_someone_leaves_the_others_alone(self):
        first = printed_setting(run_codes("alice", "bob")[1])
        keep = json.dumps(first)

        code, out, _err = run_codes("carol", "--keep", keep)
        added = printed_setting(out)
        self.assertEqual((code, set(printed_codes(out))), (0, {"carol"}))          # only carol's code is shown
        self.assertEqual({name: added[name] for name in first}, first)             # alice and bob unchanged

        code, out, _err = run_codes("--keep", keep, "--remove", "bob")
        self.assertEqual((code, set(printed_setting(out)), printed_codes(out)), (0, {"alice"}, {}))

        code, out, _err = run_codes("alice", "--keep", keep, "--remove", "alice")
        replaced = printed_setting(out)
        self.assertEqual(code, 0)
        self.assertNotEqual(replaced["alice"], first["alice"])
        self.assertEqual(replaced["bob"], first["bob"])

    def test_mistakes_are_refused_and_no_code_is_shown(self):
        keep = json.dumps(printed_setting(run_codes("alice")[1]))
        for argv in (["Alice"], ["a"], ["alice-b"], ["x" * 21], ["bob", "bob"],
                     ["alice", "--keep", keep],                                    # alice already has one
                     ["--keep", keep, "--remove", "nobody"],
                     ["--keep", keep, "--remove", "alice"],                        # nobody would be left
                     ["bob", "--keep", "not json"], ["bob", "--keep", '{"Alice": "x"}'],
                     ["bob", "--keep", "@no-such-file.json"]):
            code, out, err = run_codes(*argv)
            self.assertEqual(code, 2, argv)
            self.assertEqual(printed_codes(out), {}, argv)
            self.assertTrue(err.startswith("access_codes:"), argv)

    def test_the_environment_file_replaces_the_whole_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "nested", "environment.json")
            code, out, _err = run_codes("alice", "--env-file", path)
            with open(path, encoding="utf-8") as fh:
                environment = json.load(fh)
        self.assertEqual(code, 0)
        self.assertEqual(set(environment), {"Variables"})
        variables = environment["Variables"]
        self.assertEqual(set(variables), {"UPLOADS_BUCKET", "REPORT_BUCKET", "USERS"})   # no ACCESS_CODE
        self.assertEqual(json.loads(variables["USERS"]), printed_setting(out))
        self.assertNotIn(printed_codes(out)["alice"], json.dumps(environment))

    def test_a_code_can_be_given_a_last_day_and_the_function_accepts_it(self):
        code, out, _err = run_codes("reviewer", "--expire", "reviewer=2099-01-01")
        self.assertEqual(code, 0)
        setting = printed_setting(out)
        secret = printed_codes(out)["reviewer"]
        self.assertEqual(setting, {"reviewer": {"sha256": sha256(secret), "expires": "2099-01-01"}})
        self.assertIn("reviewer             last day 2099-01-01", out)
        users = upload_api.load_users({"USERS": json.dumps(setting)})
        self.assertEqual(upload_api.who({"x-access-code": secret}, users), "reviewer")

    def test_the_last_day_of_someone_who_has_a_code_can_be_moved_or_removed_without_a_new_code(self):
        first = printed_setting(run_codes("alice", "bob")[1])
        code, out, _err = run_codes("--keep", json.dumps(first), "--expire", "alice=2099-01-01", "--expire", "bob=2099-02-02")
        moved = printed_setting(out)
        self.assertEqual((code, printed_codes(out)), (0, {}))                          # nobody got a new code
        self.assertEqual(moved, {"alice": {"sha256": first["alice"], "expires": "2099-01-01"},
                                 "bob": {"sha256": first["bob"], "expires": "2099-02-02"}})
        # The tool reads its own output back, keeps the other person's date, and can clear one.
        code, out, _err = run_codes("--keep", json.dumps(moved), "--expire", "alice=none")
        self.assertEqual(printed_setting(out), {"alice": first["alice"], "bob": moved["bob"]})
        code, out, _err = run_codes("carol", "--keep", json.dumps(moved))
        self.assertEqual({k: v for k, v in printed_setting(out).items() if k != "carol"}, moved)

    def test_a_last_day_that_makes_no_sense_is_refused(self):
        keep = json.dumps(printed_setting(run_codes("alice")[1]))
        real = access_codes.today
        access_codes.today = lambda: datetime.date(2026, 10, 6)
        try:
            self.assertEqual(run_codes("--keep", keep, "--expire", "alice=2026-10-06")[0], 0)        # today still counts
            for expire in ("alice=2026-10-05",                                                      # already past: that is --remove
                           "nobody=2099-01-01", "alice=20-10-2026", "alice=2026-13-01", "alice=", "alice", "=2099-01-01"):
                code, out, err = run_codes("--keep", keep, "--expire", expire)
                self.assertEqual((code, printed_codes(out)), (2, {}), expire)
                self.assertTrue(err.startswith("access_codes:"), expire)
            code, _out, err = run_codes("--keep", keep, "--expire", "alice=2099-01-01", "--expire", "alice=2099-02-02")
            self.assertEqual(code, 2)
            self.assertIn("twice", err)
            bad_keep = json.dumps({"alice": {"sha256": "0" * 64, "expires": "tomorrow"}})
            self.assertEqual(run_codes("bob", "--keep", bad_keep)[0], 2)
            self.assertEqual(run_codes("bob", "--keep", json.dumps({"alice": {"sha256": "0" * 64, "extra": 1}}))[0], 2)
        finally:
            access_codes.today = real


if __name__ == "__main__":
    unittest.main(verbosity=2)
