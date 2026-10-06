"""
Run the whole upload flow on this machine, without AWS.

    python tools/local_upload_flow.py                  # then open the link it prints
    python tools/local_upload_flow.py --port 8080 --access-code demo

The real code runs: the upload page and its API (aws/lambda/upload_api), the
trigger (aws/lambda/start_analysis), s3_wrapper.py and evtxkit. Only AWS is
replaced: S3 by a dict in memory, the bucket notification by a function call,
and the Fargate task by a thread that runs s3_wrapper.py. Uploads live in
memory and are gone when this stops.

This shows that the pieces fit together. It cannot show that the IAM
policies, the bucket settings or the task definition are right; only the real
account can (aws/UPLOAD-FLOW.md). tests/test_upload_flow.py runs on the same
stand-ins.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
import re
import secrets
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, quote_plus, unquote, urlsplit
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import s3_wrapper  # noqa: E402

UPLOADS_BUCKET, REPORT_BUCKET = "local-uploads", "local-reports"
S3_PATH = "/local-s3"                       # where this server plays S3 for the browser
MAX_REQUEST_BYTES = 128 * 1024 * 1024


def load_lambda(name: str):
    """Import aws/lambda/<name>/handler.py. The folder cannot be a package: "lambda" is a keyword."""
    path = os.path.join(ROOT, "aws", "lambda", name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"lambda_{name}", path)
    module = importlib.util.module_from_spec(spec)
    cached, sys.dont_write_bytecode = sys.dont_write_bytecode, True     # no __pycache__ in a folder that gets zipped
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = cached
    return module


# --------------------------------------------------------------------------
# S3
# --------------------------------------------------------------------------

class S3Error(Exception):
    """Shaped like botocore's ClientError: the code and the HTTP status are in .response."""

    def __init__(self, code: str, status: int, message: str = ""):
        super().__init__(f"An error occurred ({code}): {message or code}")
        self.code, self.status, self.message = code, status, message or code
        self.response = {"Error": {"Code": code, "Message": self.message},
                         "ResponseMetadata": {"HTTPStatusCode": status}}


class LocalS3:
    """The S3 calls this project makes, over a dict. One instance plays every bucket."""

    class exceptions:                       # where a boto3 client keeps its exception classes
        ClientError = S3Error

    def __init__(self, base_url: str = S3_PATH, missing_status: int = 404):
        self.objects: dict = {}             # (bucket, key) -> bytes
        self.uploaded: dict = {}            # what browsers posted, kept even after the task deletes it (for the tests)
        self.base_url = base_url
        self.missing_status = missing_status    # S3 says 403 to a caller that may not list the bucket
        self.on_created = None              # called with an S3 event, as a bucket notification would be
        self._posts: dict = {}              # signature -> the pre-signed POST it was issued for
        self._links: dict = {}              # signature -> (bucket, key, expiry, content disposition)
        self._sequence = 0
        self._lock = threading.Lock()

    # ---- what s3_wrapper.py and the API call --------------------------------
    def put_object(self, Bucket, Key, Body, ContentType=None):
        with self._lock:
            self.objects[(Bucket, Key)] = bytes(Body)

    def delete_object(self, Bucket, Key):
        with self._lock:
            self.objects.pop((Bucket, Key), None)       # like S3: deleting what is not there is not an error

    def _data(self, bucket: str, key: str, code: str) -> bytes:
        with self._lock:
            if (bucket, key) not in self.objects:
                denied = self.missing_status == 403
                raise S3Error("AccessDenied" if denied else code, self.missing_status)
            return self.objects[(bucket, key)]

    def head_object(self, Bucket, Key):
        return {"ContentLength": len(self._data(Bucket, Key, "404"))}

    def get_object(self, Bucket, Key):
        data = self._data(Bucket, Key, "NoSuchKey")
        return {"Body": io.BytesIO(data), "ContentLength": len(data)}

    def download_file(self, Bucket, Key, Filename):
        with open(Filename, "wb") as fh:
            fh.write(self._data(Bucket, Key, "404"))

    def generate_presigned_post(self, Bucket, Key, Fields=None, Conditions=None, ExpiresIn=3600):
        expires = time.time() + ExpiresIn
        conditions = list(Conditions or []) + [{"bucket": Bucket}, {"key": Key}]    # boto3 adds these two itself
        policy = {"expiration": datetime.datetime.fromtimestamp(expires, datetime.timezone.utc)
                  .strftime("%Y-%m-%dT%H:%M:%SZ"), "conditions": conditions}
        signature = secrets.token_hex(32)
        with self._lock:
            self._posts[signature] = {"bucket": Bucket, "key": Key, "expires": expires, "conditions": conditions}
        fields = dict(Fields or {}, key=Key, policy=base64.b64encode(json.dumps(policy).encode()).decode())
        fields["x-amz-signature"] = signature
        return {"url": f"{self.base_url}/{Bucket}", "fields": fields}

    def generate_presigned_url(self, ClientMethod, Params=None, ExpiresIn=3600, HttpMethod=None):
        if ClientMethod != "get_object":
            raise NotImplementedError(ClientMethod)
        signature = secrets.token_hex(32)
        with self._lock:
            self._links[signature] = (Params["Bucket"], Params["Key"], time.time() + ExpiresIn,
                                      Params.get("ResponseContentDisposition"))
        return f"{self.base_url}/{Params['Bucket']}/{quote(Params['Key'])}?X-Amz-Signature={signature}"

    # ---- what the browser does with those two ------------------------------
    def post_object(self, bucket: str, fields: dict, data: bytes) -> str:
        """A browser's form POST. Like S3, it checks the policy the upload was signed with."""
        post = self._posts.get(fields.get("x-amz-signature") or "")
        if not post or post["bucket"] != bucket or post["key"] != fields.get("key"):
            raise S3Error("AccessDenied", 403, "Invalid according to Policy")
        if time.time() > post["expires"]:
            raise S3Error("AccessDenied", 403, "Invalid according to Policy: Policy expired.")
        for condition in post["conditions"]:
            if isinstance(condition, list) and condition[0] == "content-length-range":
                if len(data) < condition[1]:
                    raise S3Error("EntityTooSmall", 400, "Your proposed upload is smaller than the minimum allowed size")
                if len(data) > condition[2]:
                    raise S3Error("EntityTooLarge", 400, "Your proposed upload exceeds the maximum allowed size")
        self.put_object(bucket, post["key"], data)
        self.uploaded[(bucket, post["key"])] = data
        self._notify(bucket, post["key"], len(data))
        return post["key"]

    def open_link(self, bucket: str, key: str, signature: str) -> tuple[bytes, str | None]:
        """A browser's GET of a pre-signed URL: (the object, the Content-Disposition asked for)."""
        link = self._links.get(signature)
        if not link or link[:2] != (bucket, key) or time.time() > link[2]:
            raise S3Error("AccessDenied", 403, "Request has expired or its signature does not match")
        return self._data(bucket, key, "NoSuchKey"), link[3]

    def _notify(self, bucket: str, key: str, size: int) -> None:
        if self.on_created is None:
            return
        with self._lock:
            self._sequence += 1
            sequencer = "%016X" % self._sequence
        self.on_created({"Records": [{
            "eventSource": "aws:s3", "eventName": "ObjectCreated:Post",
            "s3": {"bucket": {"name": bucket},          # keys arrive URL-encoded, spaces as "+"
                   "object": {"key": quote_plus(key, safe="/"), "size": size, "sequencer": sequencer}},
        }]})


# --------------------------------------------------------------------------
# ECS
# --------------------------------------------------------------------------

class LocalECS:
    """ecs.run_task, played by s3_wrapper.py in a thread instead of in a container.

    With background=False the "task" has finished by the time run_task returns
    and its output is kept in .transcripts; that is what the tests use."""

    def __init__(self, s3: LocalS3, task_env: dict, background: bool = True, start_delay: float = 0.0):
        self.s3, self.task_env = s3, dict(task_env)
        self.background, self.start_delay = background, start_delay
        self.calls: list[dict] = []
        self.failures: list[dict] = []      # set this to make run_task report that nothing started
        self.transcripts: list[str] = []

    def run_task(self, **request) -> dict:
        self.calls.append(request)
        if self.failures:
            return {"tasks": [], "failures": list(self.failures)}
        env = dict(self.task_env)           # the task definition's environment, then the overrides
        for override in (request.get("overrides") or {}).get("containerOverrides") or []:
            env.update({item["name"]: item["value"] for item in override.get("environment") or []})
        if self.background:
            threading.Thread(target=self._task, args=(env,), daemon=True).start()
        else:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                self._task(env)
            self.transcripts.append(out.getvalue())
        return {"tasks": [{"taskArn": f"arn:aws:ecs:local:000000000000:task/local/{len(self.calls):04d}"}],
                "failures": []}

    def _task(self, env: dict) -> None:
        if self.start_delay:                # Fargate needs the better part of a minute to start a task
            time.sleep(self.start_delay)
        s3_wrapper.main([], env, self.s3)   # what it prints is what CloudWatch would hold


# --------------------------------------------------------------------------
# The pieces, wired the way AWS wires them
# --------------------------------------------------------------------------

class Flow:
    def __init__(self, access_code: str, background: bool = True, start_delay: float = 0.0, log=print):
        self.access_code, self.log = access_code, log
        self.s3 = LocalS3()
        self.ecs = LocalECS(self.s3, {"REPORT_BUCKET": REPORT_BUCKET}, background, start_delay)
        self.upload_api = load_lambda("upload_api")
        self.start_analysis = load_lambda("start_analysis")
        self.upload_api.print = self.start_analysis.print = log     # the functions' CloudWatch logs
        # One person, "local", whose code is the one printed at start-up; like the real
        # function this holds only the code's fingerprint.
        self.api_env = {"UPLOADS_BUCKET": UPLOADS_BUCKET, "REPORT_BUCKET": REPORT_BUCKET,
                        "USERS": json.dumps({"local": hashlib.sha256(access_code.encode("utf-8")).hexdigest()})}
        self.trigger_env = {"ECS_CLUSTER": "local", "TASK_DEFINITION": "evtxkit-task", "SUBNETS": "subnet-local",
                            "SECURITY_GROUPS": "sg-local", "UPLOADS_BUCKET": UPLOADS_BUCKET}
        self.trigger_errors: list[Exception] = []
        self.s3.on_created = self._object_created

    def _object_created(self, event: dict) -> None:
        # S3 invokes the function on its own; the uploader never sees how that went.
        try:
            self.start_analysis.handle(event, self.trigger_env, self.ecs)
        except Exception as exc:
            self.trigger_errors.append(exc)
            self.log(f"start_analysis failed: {type(exc).__name__}: {exc}")


def parse_multipart(content_type: str, body: bytes) -> tuple[dict, bytes | None]:
    """(the text fields before the file, the bytes of the part named "file") of a form upload."""
    boundary = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not boundary or not content_type.lower().startswith("multipart/form-data"):
        raise S3Error("MalformedPOSTRequest", 400, "The body of your POST request is not well-formed multipart/form-data.")
    delimiter = b"\r\n--" + boundary.group(1).encode("latin-1")
    fields: dict = {}
    for part in (b"\r\n" + body).split(delimiter)[1:]:
        if part.startswith(b"--"):          # the closing delimiter
            break
        head, separator, data = part.partition(b"\r\n\r\n")
        name = re.search(rb'name="([^"]*)"', head)
        if not separator or not name:
            continue
        if name.group(1) == b"file":        # S3 ignores every field after the file
            return fields, data
        fields[name.group(1).decode("utf-8")] = data.decode("utf-8", errors="replace")
    return fields, None


class Handler(BaseHTTPRequestHandler):
    flow: Flow = None  # type: ignore[assignment]
    server_version = "evtxkit-upload-flow-local"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):      # keep the console for what the functions and the task print
        pass

    def _send(self, status: int, body: bytes, headers: dict) -> None:
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_REQUEST_BYTES:
            self.close_connection = True
            raise S3Error("EntityTooLarge", 400, "The request is larger than this local server accepts.")
        return self.rfile.read(length) if length else b""

    def _route(self, method: str) -> None:
        url = urlsplit(self.path)
        port = self.server.server_address[1]
        if (self.headers.get("Host") or "").strip().lower() not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            self.close_connection = True
            return self._send(403, b"bad host", {"Content-Type": "text/plain"})
        if url.path == S3_PATH or url.path.startswith(S3_PATH + "/"):
            return self._s3(method, url)
        return self._function_url(method, url)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    def _function_url(self, method: str, url) -> None:
        """Hand the request to the upload_api function the way a Lambda function URL does."""
        try:
            body = self._body()
            # A function URL passes text bodies as they are and base64-encodes the rest.
            is_text = (self.headers.get("Content-Type") or "").lower().startswith(("application/json", "text/"))
            event = {
                "version": "2.0", "routeKey": "$default", "rawPath": url.path, "rawQueryString": url.query,
                "headers": {name.lower(): value for name, value in self.headers.items()},
                "requestContext": {"http": {"method": method, "path": url.path, "sourceIp": self.client_address[0]}},
                "body": (body.decode("utf-8", errors="replace") if is_text
                         else base64.b64encode(body).decode("ascii")) if body else None,
                "isBase64Encoded": bool(body) and not is_text,
            }
            response = self.flow.upload_api.handle(event, self.flow.api_env, self.flow.s3)
        except Exception:
            traceback.print_exc()
            return self._send(500, b'{"error": "Something went wrong. Please try again."}',
                              {"Content-Type": "application/json; charset=utf-8"})
        payload = response.get("body") or ""
        payload = base64.b64decode(payload) if response.get("isBase64Encoded") else payload.encode("utf-8")
        self._send(response["statusCode"], payload, dict(response.get("headers") or {}))

    def _s3(self, method: str, url) -> None:
        """POST /local-s3/<bucket> is a form upload; GET /local-s3/<bucket>/<key>?... is a pre-signed download."""
        parts = url.path[len(S3_PATH):].strip("/").split("/", 1)
        bucket = unquote(parts[0])
        try:
            if method == "POST" and len(parts) == 1 and bucket:
                fields, data = parse_multipart(self.headers.get("Content-Type") or "", self._body())
                if data is None:
                    raise S3Error("InvalidArgument", 400, "POST requires exactly one file upload per request.")
                self.flow.s3.post_object(bucket, fields, data)
                return self._send(204, b"", {})
            if method == "GET" and len(parts) == 2:
                signature = (parse_qs(url.query).get("X-Amz-Signature") or [""])[0]
                data, disposition = self.flow.s3.open_link(bucket, unquote(parts[1]), signature)
                headers = {"Content-Type": "application/octet-stream"}
                if disposition:
                    headers["Content-Disposition"] = disposition
                return self._send(200, data, headers)
            raise S3Error("MethodNotAllowed", 405, "The specified method is not allowed against this resource.")
        except S3Error as exc:
            xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>%s</Code><Message>%s</Message></Error>'
                   % (escape(exc.code), escape(exc.message)))
            self._send(exc.status, xml.encode("utf-8"), {"Content-Type": "application/xml"})


def make_server(port: int = 0, access_code: str | None = None, background: bool = True,
                start_delay: float = 0.0, log=print) -> tuple[ThreadingHTTPServer, Flow]:
    """Loopback only: this is a development stand-in, not something to put on a network."""
    flow = Flow(access_code or secrets.token_urlsafe(9), background, start_delay, log)
    handler = type("BoundHandler", (Handler,), {"flow": flow})
    return ThreadingHTTPServer(("127.0.0.1", port), handler), flow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the evtxkit upload flow locally, without AWS.")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--access-code", help="default: a new random one each run")
    parser.add_argument("--start-delay", type=float, default=3.0, metavar="SECONDS",
                        help="pretend the task takes this long to start (default 3; Fargate takes about a minute)")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):     # a report can hold characters this console cannot show,
        if hasattr(stream, "reconfigure"):      # and a log is only useful if lines appear as they are written
            stream.reconfigure(errors="replace", line_buffering=True)

    httpd, flow = make_server(args.port, args.access_code, start_delay=args.start_delay)
    port = httpd.server_address[1]
    print("Upload flow, running locally. Nothing here talks to AWS.")
    print(f"Open:  http://127.0.0.1:{port}/#code={quote(flow.access_code, safe='')}")
    print("Ctrl+C stops it.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
