"""
Lambda: the upload page and its small API, behind one function URL.

    GET  /                    the page (web/index.html, app.js, app.css)
    POST /api/uploads         {"filename", "size"} -> a job id and a pre-signed
                              S3 POST for uploads/<job id>/<file name>
    GET  /api/jobs/<job id>   where the job is, and the report once it is done
    GET  /api/samples         the bundled sample logs (samples.json), to try the page without one
    GET  /api/samples/<file>  one of them, byte for byte

The file goes from the browser straight to S3; it never passes through this
function. Its arrival in the bucket is what starts the analysis (see
start_analysis). This function only signs the upload and reads what
s3_wrapper.py writes: reports/<job id>/status.json and the report.

Every /api/ call needs a person's access code (header X-Access-Code). The
function holds only a fingerprint (SHA-256) of each person's code, never the
code, so a leaked setting cannot be used to sign in. That is safe because the
codes are long and random (tools/access_codes.py makes them); a short or
chosen code would not be. A job id is <person>-<128 random bits>, and a person
can only ask about their own jobs.

Environment (aws/UPLOAD-FLOW.md, step 8):
    UPLOADS_BUCKET, REPORT_BUCKET    required
    USERS                            required; JSON {"alice": "<sha256 hex of her code>", ...}
                                     (without it the API answers 503)
    MAX_UPLOAD_BYTES                 default 64 MB; keep it at or below the task's
                                     MAX_INPUT_BYTES
    UPLOAD_EXPIRES_SECONDS           how long a pre-signed upload stays valid (default 300)
    MAX_INLINE_REPORT_BYTES          a larger report is download-only (default 1 MB)

Needs only s3:PutObject on uploads/* in the uploads bucket (that is what a
pre-signed upload is allowed to do) and s3:GetObject on reports/* in the
reports bucket (aws/lambda-upload-api-policy.json). Those two permissions are
not split per person: the separation between people is made here, in code.

The event and response shapes are the function URL ones (payload format 2.0),
which an API Gateway HTTP API also uses.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import traceback
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))

STATIC = {                                          # path -> (file in web/, content type)
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
}
# What evtxkit reads; the same list as s3_wrapper.KNOWN_EXTENSIONS.
ALLOWED_EXTENSIONS = (".evtx", ".xml", ".json", ".jsonl", ".ndjson", ".txt", ".log")
# A person's name goes into every job id and S3 key: letters and digits only,
# so the "-" after it can never be part of it.
USER_NAME = re.compile(r"[a-z][a-z0-9]{1,19}")
FINGERPRINT = re.compile(r"[0-9a-f]{64}")
JOB_ID = re.compile(r"([a-z][a-z0-9]{1,19})-([0-9a-f]{32})")
MAX_CODE_LENGTH = 200
DEFAULT_MAX_UPLOAD_BYTES = 64 * 1024 * 1024
DEFAULT_UPLOAD_EXPIRES_SECONDS = 300
DEFAULT_MAX_INLINE_REPORT_BYTES = 1024 * 1024
MAX_STATUS_BYTES = 64 * 1024
DOWNLOAD_EXPIRES_SECONDS = 300
TOO_LARGE = object()

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000",
}

SAMPLE_NAME = re.compile(r"[A-Za-z0-9._-]{1,80}")
# In the deployed zip the samples sit next to the handler; in the repo they are
# the toolkit's own samples/evtxkit.
SAMPLE_FOLDERS = (os.path.join(HERE, "samples"), os.path.normpath(os.path.join(HERE, "..", "..", "..", "samples", "evtxkit")))

_clients: dict = {}
_origins: dict = {}
_users: dict = {}
_samples: dict = {}


class UsersError(Exception):
    """The USERS setting is missing or wrong; the message never contains a fingerprint."""


def _s3_client():
    if "s3" not in _clients:             # created once per execution environment
        import boto3                     # provided by the Lambda runtime
        from botocore.config import Config
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        # Sign for the bucket's own regional address. A request signed for the
        # global one is redirected while a bucket is new, and a browser does not
        # follow that redirect for a cross-origin upload.
        _clients["s3"] = boto3.client(
            "s3", region_name=region,
            endpoint_url=f"https://s3.{region}.amazonaws.com" if region else None,
            config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"},
                          connect_timeout=5, read_timeout=10))
    return _clients["s3"]


def _int_env(env, name: str, default: int) -> int:
    try:
        return int(env.get(name) or default)
    except ValueError:
        return default


def load_users(env) -> dict:
    """{name: SHA-256 fingerprint of that person's code} from the USERS setting."""
    raw = (env.get("USERS") or "").strip()
    if not raw:
        raise UsersError("USERS is not set")
    if raw not in _users:                # the setting does not change within one execution environment
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise UsersError("USERS is not valid JSON") from exc
        if not isinstance(data, dict) or not data:
            raise UsersError("USERS must be a JSON object with at least one person")
        for name, fingerprint in data.items():
            if not USER_NAME.fullmatch(name):
                raise UsersError(f"{name!r} is not a usable name (a-z and 0-9, starting with a letter, 2-20 characters)")
            if not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint):
                raise UsersError(f"the entry for {name!r} is not a lowercase hex SHA-256")
        if len(set(data.values())) != len(data):
            raise UsersError("two people share a code")
        _users[raw] = dict(data)
    return _users[raw]


def fingerprint(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def who(headers: dict, users: dict) -> str | None:
    """The person whose code the request carries, or None."""
    given = str(headers.get("x-access-code") or "")
    if not given or len(given) > MAX_CODE_LENGTH:
        return None
    digest = fingerprint(given)
    found = None
    for name, stored in users.items():   # no early exit: the time says nothing about whose fingerprint was close
        if hmac.compare_digest(digest, stored):
            found = name
    return found


def sample_catalog() -> dict:
    """{file name: entry} for the sample logs that are really there.

    samples.json describes them; a listed file that is missing, or whose name is
    anything but a plain file name of a kind evtxkit reads, is left out."""
    if "catalog" not in _samples:
        found: dict = {}
        folder = next((d for d in SAMPLE_FOLDERS if os.path.isdir(d)), None)
        try:
            with open(os.path.join(HERE, "samples.json"), encoding="utf-8") as fh:
                listed = json.load(fh)
        except (OSError, ValueError):
            listed = []
        for entry in listed if folder and isinstance(listed, list) else []:
            name = entry.get("file") if isinstance(entry, dict) else None
            if not isinstance(name, str) or not SAMPLE_NAME.fullmatch(name) or not name.lower().endswith(ALLOWED_EXTENSIONS):
                continue
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                found[name] = {"file": name, "title": str(entry.get("title") or name), "about": str(entry.get("about") or ""),
                               "worst": str(entry.get("worst") or ""), "rules": [str(r) for r in entry.get("rules") or []],
                               "bytes": os.path.getsize(path), "path": path}
        _samples["catalog"] = found
    return _samples["catalog"]


def _sample_list() -> dict:
    return _json(200, {"samples": [{k: v for k, v in e.items() if k != "path"} for e in sample_catalog().values()]})


def _sample_file(name: str) -> dict:
    entry = sample_catalog().get(name)         # only names in the catalog: nothing the caller types reaches the file system
    if entry is None:
        return _error(404, "No such sample.")
    with open(entry["path"], "rb") as fh:
        data = fh.read()
    response = _response(200, base64.b64encode(data).decode("ascii"), "application/octet-stream",
                         {"Content-Disposition": f'attachment; filename="{name}"'})
    response["isBase64Encoded"] = True          # byte for byte: a line ending changed would change the evidence
    return response


def _response(status: int, body: str, content_type: str, extra: dict | None = None) -> dict:
    return {"statusCode": status, "isBase64Encoded": False, "body": body,
            "headers": {**SECURITY_HEADERS, "Content-Type": content_type, **(extra or {})}}


def _json(status: int, obj: dict) -> dict:
    return _response(status, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")


def _error(status: int, message: str) -> dict:
    return _json(status, {"error": message})


def _json_body(event: dict) -> dict:
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    data = json.loads(raw or "{}")
    if not isinstance(data, dict):
        raise ValueError("the body is not a JSON object")
    return data


def safe_name(filename: str) -> str | None:
    """The name the upload is stored under, or None if evtxkit cannot read that kind of file.

    The result is what s3_wrapper.local_name() makes of it, so the name in the
    report's title is the name in the key."""
    base = re.split(r"[\\/]", filename)[-1]
    stem, ext = os.path.splitext(base)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return None
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._")[:80] or "upload"
    return stem + ext.lower()


def _upload_origin(env, s3) -> str:
    """Scheme and host the browser sends the file to, for the page's Content-Security-Policy."""
    bucket = env.get("UPLOADS_BUCKET") or ""
    if not bucket:
        return ""
    if bucket not in _origins:           # signing is a local calculation, not a request
        url = urlsplit(s3.generate_presigned_post(Bucket=bucket, Key="uploads/origin/probe", ExpiresIn=1)["url"])
        _origins[bucket] = f"{url.scheme}://{url.netloc}" if url.netloc else ""
    return _origins[bucket]


def _static(path: str, env, s3) -> dict:
    name, content_type = STATIC[path]
    with open(os.path.join(HERE, "web", name), encoding="utf-8") as fh:
        body = fh.read()
    if path != "/":
        return _response(200, body, content_type)
    connect = " ".join(filter(None, ("'self'", _upload_origin(env, s3))))
    csp = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
           f"connect-src {connect}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
    return _response(200, body, content_type, {"Content-Security-Policy": csp})


def _create_upload(event: dict, env, s3, user: str) -> dict:
    try:
        body = _json_body(event)
    except ValueError:
        return _error(400, "The request is not valid JSON.")
    name = safe_name(str(body.get("filename") or ""))
    if name is None:
        return _error(400, "That is not a Windows event log this service can read. "
                           "Upload one of: " + ", ".join(ALLOWED_EXTENSIONS) + ".")
    limit = _int_env(env, "MAX_UPLOAD_BYTES", DEFAULT_MAX_UPLOAD_BYTES)
    size = body.get("size")
    if isinstance(size, int) and not isinstance(size, bool):
        if size < 1:
            return _error(400, "The file is empty.")
        if size > limit:                 # S3 enforces the same limit; this only says so sooner
            return _error(413, f"The file is too large. The limit is {limit // (1024 * 1024)} MB.")
    job_id = f"{user}-{secrets.token_hex(16)}"
    key = f"uploads/{job_id}/{name}"
    expires = _int_env(env, "UPLOAD_EXPIRES_SECONDS", DEFAULT_UPLOAD_EXPIRES_SECONDS)
    # Valid for this one key, this size range and a few minutes; nothing else.
    post = s3.generate_presigned_post(Bucket=env["UPLOADS_BUCKET"], Key=key,
                                      Conditions=[["content-length-range", 1, limit]], ExpiresIn=expires)
    print(json.dumps({"upload_signed": {"user": user, "job_id": job_id, "name": name}}))
    return _json(201, {"job_id": job_id, "upload": {"url": post["url"], "fields": post["fields"]},
                       "max_bytes": limit, "expires_in": expires})


def _get(s3, bucket: str, key: str, limit: int):
    """The object's bytes; None if it is not there (yet); TOO_LARGE if it is over the limit."""
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
    except s3.exceptions.ClientError as exc:
        # This function may not list the bucket, so S3 answers 403 rather than
        # 404 for a key that does not exist. Both mean "not written yet".
        if exc.response["ResponseMetadata"]["HTTPStatusCode"] in (403, 404):
            return None
        raise
    body = response["Body"]
    try:
        if int(response["ContentLength"]) > limit:
            return TOO_LARGE
        return body.read()
    finally:
        body.close()                     # an unread body keeps its connection open


def _job(job_id: str, env, s3, user: str) -> dict:
    match = JOB_ID.fullmatch(job_id)
    # Someone else's job answers exactly like one that does not exist.
    if not match or match.group(1) != user:
        return _error(404, "No such job.")
    bucket = env["REPORT_BUCKET"]
    raw = _get(s3, bucket, f"reports/{job_id}/status.json", MAX_STATUS_BYTES)
    if raw is None:                      # uploaded, or about to be, but the task has not started
        return _json(200, {"job_id": job_id, "state": "queued"})
    try:
        status = json.loads(raw) if raw is not TOO_LARGE else None
    except ValueError:
        status = None
    if not isinstance(status, dict):
        print(f"upload_api: reports/{job_id}/status.json is not a status file")
        return _error(502, "The job's status could not be read.")

    state = status.get("state") if status.get("state") in ("running", "done", "failed") else "running"
    view = {"job_id": job_id, "state": state, "started": status.get("started"), "finished": status.get("finished")}
    if state == "failed":                # s3_wrapper.py only stores reasons that are safe to show
        view["error"] = str(status.get("error") or "The analysis failed.")[:500]
    if state == "done":
        key = str(status.get("report_key") or "")
        if not key.startswith(f"reports/{job_id}/"):
            print(f"upload_api: job {job_id} names a report outside its own folder: {key!r}")
            return _error(502, "The job's status could not be read.")
        report = _get(s3, bucket, key, _int_env(env, "MAX_INLINE_REPORT_BYTES", DEFAULT_MAX_INLINE_REPORT_BYTES))
        if report is None:
            return _error(502, "The report could not be read.")
        ext = os.path.splitext(key)[1]
        view["high_or_critical_findings"] = bool(status.get("high_or_critical_findings"))
        view["report_name"] = f"evtxkit-report-{match.group(2)[:8]}{ext}"
        view["report"] = None if report is TOO_LARGE else report.decode("utf-8", errors="replace")
        view["download_url"] = s3.generate_presigned_url(
            "get_object", ExpiresIn=DOWNLOAD_EXPIRES_SECONDS,
            Params={"Bucket": bucket, "Key": key,
                    "ResponseContentDisposition": f'attachment; filename="{view["report_name"]}"'})
    return _json(200, view)


def handle(event: dict, env, s3) -> dict:
    http = (event.get("requestContext") or {}).get("http") or {}
    method = str(http.get("method") or "GET").upper()
    path = event.get("rawPath") or http.get("path") or "/"

    if path in STATIC:
        return _static(path, env, s3) if method == "GET" else _error(405, "Method not allowed.")
    if not path.startswith("/api/"):
        return _error(404, "Not found.")

    if not env.get("UPLOADS_BUCKET") or not env.get("REPORT_BUCKET"):
        print("upload_api: UPLOADS_BUCKET and REPORT_BUCKET must both be set; refusing the call")
        return _error(503, "The service is not set up yet.")
    try:
        users = load_users(env)
    except UsersError as exc:
        print(f"upload_api: {exc}; refusing the call")
        return _error(503, "The service is not set up yet.")
    headers = {str(name).lower(): value for name, value in (event.get("headers") or {}).items()}
    user = who(headers, users)
    if user is None:
        print(json.dumps({"auth_failed": {"ip": http.get("sourceIp")}}))
        return _error(401, "The access code is missing or wrong.")

    if path == "/api/samples":
        return _sample_list() if method == "GET" else _error(405, "Method not allowed.")
    sample = re.fullmatch(r"/api/samples/([^/]+)", path)
    if sample:
        return _sample_file(sample.group(1)) if method == "GET" else _error(405, "Method not allowed.")
    if path == "/api/uploads":
        return _create_upload(event, env, s3, user) if method == "POST" else _error(405, "Method not allowed.")
    job = re.fullmatch(r"/api/jobs/([^/]+)", path)
    if job:
        return _job(job.group(1), env, s3, user) if method == "GET" else _error(405, "Method not allowed.")
    return _error(404, "Not found.")


def handler(event, context=None):
    try:
        return handle(event or {}, os.environ, _s3_client())
    except Exception:                    # the log gets the traceback, the caller a plain answer
        traceback.print_exc()
        return _error(500, "Something went wrong. Please try again.")
