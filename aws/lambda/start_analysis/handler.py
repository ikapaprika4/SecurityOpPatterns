"""
Lambda: start an evtxkit analysis when a file lands in the uploads bucket.

Trigger: s3:ObjectCreated:* on the uploads bucket, prefix uploads/.

For every uploads/<job id>/<file name> object it starts one Fargate task from
the evtxkit task definition with two environment overrides, INPUT_BUCKET and
INPUT_KEY. Everything else (download, analysis, report, status.json) is
s3_wrapper.py's job inside the container; this function only says "go".

If ECS does not start the task the invocation fails, so Lambda retries it
(twice, for an S3 event) and the reason is in this function's log.

Environment, all set on the function (aws/UPLOAD-FLOW.md, step 7):
    ECS_CLUSTER, TASK_DEFINITION, SUBNETS, SECURITY_GROUPS    required
    UPLOADS_BUCKET      required; events from any other bucket are ignored
    CONTAINER_NAME      default evtxkit
    ASSIGN_PUBLIC_IP    default ENABLED (there is no NAT gateway, so the task
                        needs a public address to reach ECR and S3)

Needs only ecs:RunTask on that task definition and iam:PassRole for the
task's two roles (aws/lambda-start-analysis-policy.json).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from urllib.parse import unquote_plus

# uploads/<job id>/<file name>. The job id is limited to what s3_wrapper.py
# keeps unchanged, so a report always lands under the id its upload was given.
UPLOAD_KEY = re.compile(r"^uploads/([A-Za-z0-9](?:[A-Za-z0-9._-]{0,78}[A-Za-z0-9])?)/([^/]+)$")
MAX_KEY_LENGTH = 512
REQUIRED = ("ECS_CLUSTER", "TASK_DEFINITION", "SUBNETS", "SECURITY_GROUPS", "UPLOADS_BUCKET")

_clients: dict = {}


class ConfigError(Exception):
    """The function is missing a setting; retrying will not fix that."""


def _ecs_client():
    if "ecs" not in _clients:            # created once per execution environment
        import boto3                     # provided by the Lambda runtime
        from botocore.config import Config
        # Fail well inside the function's own timeout, with ECS's error, not Lambda's.
        _clients["ecs"] = boto3.client("ecs", config=Config(
            connect_timeout=5, read_timeout=15, retries={"total_max_attempts": 2, "mode": "standard"}))
    return _clients["ecs"]


def _config(env) -> dict:
    missing = [name for name in REQUIRED if not (env.get(name) or "").strip()]
    if missing:
        raise ConfigError("missing environment variable(s): " + ", ".join(missing))

    def listed(name: str) -> list[str]:
        return [value.strip() for value in env[name].split(",") if value.strip()]

    return {
        "cluster": env["ECS_CLUSTER"].strip(),
        "task_definition": env["TASK_DEFINITION"].strip(),
        "subnets": listed("SUBNETS"),
        "security_groups": listed("SECURITY_GROUPS"),
        "uploads_bucket": env["UPLOADS_BUCKET"].strip(),
        "container": (env.get("CONTAINER_NAME") or "evtxkit").strip(),
        "assign_public_ip": (env.get("ASSIGN_PUBLIC_IP") or "ENABLED").strip().upper(),
    }


def uploads_in(event: dict, uploads_bucket: str) -> tuple[list[dict], list[dict]]:
    """(uploads to analyse, records ignored and why) for one S3 event."""
    uploads, ignored = [], []
    for record in event.get("Records") or []:       # S3's own s3:TestEvent has no Records
        s3 = record.get("s3") or {}
        bucket = (s3.get("bucket") or {}).get("name") or ""
        obj = s3.get("object") or {}
        key = unquote_plus(obj.get("key") or "")    # S3 URL-encodes keys in events, spaces as "+"
        reason = None
        if not str(record.get("eventName") or "").startswith("ObjectCreated"):
            reason = "not an ObjectCreated event"
        elif bucket != uploads_bucket:
            reason = "not the uploads bucket"
        elif len(key) > MAX_KEY_LENGTH or not UPLOAD_KEY.match(key):
            reason = "not uploads/<job id>/<file name>"
        if reason:
            ignored.append({"bucket": bucket, "key": key, "reason": reason})
            continue
        uploads.append({"bucket": bucket, "key": key, "job_id": UPLOAD_KEY.match(key).group(1),
                        "sequencer": str(obj.get("sequencer") or obj.get("eTag") or "")})
    return uploads, ignored


def client_token(upload: dict) -> str:
    """The same for a repeated delivery of one event, different for a new upload to the same key."""
    identity = "\n".join((upload["bucket"], upload["key"], upload["sequencer"]))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def start_task(upload: dict, cfg: dict, ecs) -> str:
    """Start the analysis task for one upload and return its ARN."""
    response = ecs.run_task(
        cluster=cfg["cluster"],
        taskDefinition=cfg["task_definition"],      # the family name: its latest active revision
        launchType="FARGATE",
        count=1,
        clientToken=client_token(upload),           # S3 may deliver an event more than once
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": cfg["subnets"],
            "securityGroups": cfg["security_groups"],
            "assignPublicIp": cfg["assign_public_ip"],
        }},
        overrides={"containerOverrides": [{
            "name": cfg["container"],
            "environment": [{"name": "INPUT_BUCKET", "value": upload["bucket"]},
                            {"name": "INPUT_KEY", "value": upload["key"]}],
        }]},
    )
    tasks = response.get("tasks") or []
    if response.get("failures") or not tasks:       # run_task reports these without raising
        raise RuntimeError("ECS did not start a task for %s: %s"
                           % (upload["key"], json.dumps(response.get("failures") or [])))
    return tasks[0]["taskArn"]


def handle(event: dict, env, ecs) -> dict:
    cfg = _config(env)
    uploads, ignored = uploads_in(event or {}, cfg["uploads_bucket"])
    for record in ignored:
        print(json.dumps({"ignored": record}))
    started, errors = [], []
    for upload in uploads:
        try:
            arn = start_task(upload, cfg, ecs)
        except Exception as exc:                    # try the other records, then fail the invocation
            print(json.dumps({"failed": {"job_id": upload["job_id"], "key": upload["key"],
                                         "error": f"{type(exc).__name__}: {exc}"}}))
            errors.append(exc)
            continue
        started.append({"job_id": upload["job_id"], "key": upload["key"], "task_arn": arn})
        print(json.dumps({"started": started[-1]}))
    if errors:
        raise errors[0]                             # a failed invocation is what makes Lambda retry
    return {"started": started, "ignored": ignored}


def handler(event, context=None):
    return handle(event, os.environ, _ecs_client())
