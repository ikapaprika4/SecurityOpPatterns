"""
Container entry point for the evtxkit image.

The environment decides which of two things it does:

  Analysis job -- INPUT_BUCKET and INPUT_KEY are set (the upload flow)
      Download s3://INPUT_BUCKET/INPUT_KEY, run `evtxkit analyze` on it and
      upload to REPORT_BUCKET:
          reports/<job id>/report.md      the report, the artifact a customer gets
          reports/<job id>/status.json    running | done | failed, and why
      The job id is JOB_ID if given, else taken from the upload's key
      (uploads/<job id>/<file name>), so a report always traces back to its
      upload. Command-line arguments are ignored in this mode.

  Pass-through -- otherwise
      Run `evtxkit <arguments>` unchanged and exit with its exit code. If
      REPORT_BUCKET is set the output is also uploaded
      (reports/report-<time>.txt), as before. If it is not set nothing is
      uploaded and nothing fails, so the same image still runs in CI, in
      Kubernetes and on a laptop.

The complete transcript (stdout and stderr) always goes to the container log
(CloudWatch on Fargate); S3 only ever receives the clean report.

Environment:
    INPUT_BUCKET, INPUT_KEY     the uploaded evidence (selects the analysis job)
    REPORT_BUCKET               where reports go (required for an analysis job)
    JOB_ID                      optional; overrides the id derived from INPUT_KEY
    REPORT_FORMAT               markdown (default) | json | html | console
    MAX_INPUT_BYTES             largest upload accepted (default 64 MB; analysis needs
                                roughly 6x the file size in memory, so raise the
                                task's memory with it)
    ANALYSIS_TIMEOUT_SECONDS    give up after this long (default 900)

Needs only s3:GetObject on the uploads bucket and s3:PutObject on the reports
bucket (aws/s3-read-uploads-policy.json, aws/s3-write-policy.json).
"""

from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))

FORMATS = {                                   # REPORT_FORMAT -> (file name, content type)
    "markdown": ("report.md", "text/markdown; charset=utf-8"),
    "json": ("report.json", "application/json"),
    "html": ("report.html", "text/html; charset=utf-8"),
    "console": ("report.txt", "text/plain; charset=utf-8"),
}
# The upload's extension is kept only when it is one evtxkit knows. .evtx, .xml
# and the JSON ones pick the reader; for the rest evtxkit goes by the content.
KNOWN_EXTENSIONS = (".evtx", ".xml", ".json", ".jsonl", ".ndjson", ".txt", ".log")
DEFAULT_MAX_INPUT_BYTES = 64 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 900
EXIT_OK, EXIT_FAILED = 0, 1


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def job_id_from_key(key: str) -> str:
    """uploads/<job id>/<file name> -> <job id>; any other key -> its file
    name without the extension. Only [A-Za-z0-9._-] survives."""
    parts = [p for p in key.split("/") if p]
    if len(parts) >= 3 and parts[0] == "uploads":
        candidate = parts[1]
    else:
        candidate = os.path.splitext(parts[-1])[0] if parts else ""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", candidate).strip("-.")[:80] or "job"


def local_name(key: str) -> str:
    """A safe local file name for the upload: the key's base name reduced to
    [A-Za-z0-9._-]. It is shown in the report's title, never used as a path."""
    base = key.replace("\\", "/").rsplit("/", 1)[-1]
    stem, ext = os.path.splitext(base)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._")[:80] or "upload"
    return stem + (ext.lower() if ext.lower() in KNOWN_EXTENSIONS else "")


def run_evtxkit(args: list[str], cwd: str, timeout: float | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    env["PYTHONPATH"] = HERE + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return subprocess.run([sys.executable, "-m", "evtxkit", *args], cwd=cwd, env=env, timeout=timeout,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def _s3_client():
    import boto3                     # only the AWS paths need it
    return boto3.client("s3")


def _int_env(env: dict, name: str, default: int) -> int:
    try:
        return int(env.get(name) or default)
    except ValueError:
        return default


# --------------------------------------------------------------------------
# Pass-through
# --------------------------------------------------------------------------

def pass_through(argv: list[str], env: dict, s3=None) -> int:
    result = run_evtxkit(argv, cwd=os.getcwd())
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    bucket = env.get("REPORT_BUCKET")
    if bucket:
        key = "reports/report-%s.txt" % datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
        (s3 or _s3_client()).put_object(Bucket=bucket, Key=key, Body=result.stdout.encode("utf-8"),
                                        ContentType="text/plain; charset=utf-8")
        print(f"Uploaded to s3://{bucket}/{key}")
    return result.returncode


# --------------------------------------------------------------------------
# Analysis job
# --------------------------------------------------------------------------

class JobError(Exception):
    """The job cannot produce a report; the message is safe to show the uploader."""


def analysis_job(env: dict, s3=None) -> int:
    in_bucket, in_key = env["INPUT_BUCKET"], env["INPUT_KEY"]
    out_bucket = env.get("REPORT_BUCKET")
    if not out_bucket:
        print("s3_wrapper: REPORT_BUCKET is not set; an analysis job has nowhere to put its report",
              file=sys.stderr)
        return EXIT_FAILED
    fmt = (env.get("REPORT_FORMAT") or "markdown").lower()
    if fmt not in FORMATS:
        print(f"s3_wrapper: unknown REPORT_FORMAT {fmt!r} ({' | '.join(FORMATS)})", file=sys.stderr)
        return EXIT_FAILED
    job_id = re.sub(r"[^A-Za-z0-9._-]+", "-", env.get("JOB_ID") or "").strip("-.")[:80] or job_id_from_key(in_key)
    report_name, content_type = FORMATS[fmt]
    report_key = f"reports/{job_id}/{report_name}"
    status_key = f"reports/{job_id}/status.json"
    s3 = s3 or _s3_client()
    status = {"job_id": job_id, "state": "running", "input": {"bucket": in_bucket, "key": in_key},
              "format": fmt, "report_key": None, "error": None, "started": _now(), "finished": None}

    def put_status() -> None:
        s3.put_object(Bucket=out_bucket, Key=status_key, ContentType="application/json",
                      Body=json.dumps(status, indent=2).encode("utf-8"))

    print(f"s3_wrapper: job {job_id}: s3://{in_bucket}/{in_key} -> s3://{out_bucket}/{report_key}")
    put_status()
    try:
        report, code = _analyse(s3, in_bucket, in_key, fmt, status, env)
        s3.put_object(Bucket=out_bucket, Key=report_key, Body=report.encode("utf-8"), ContentType=content_type)
    except Exception as exc:
        # Whatever went wrong, status.json has to say so: a job left at
        # "running" keeps its uploader waiting for a report that never comes.
        expected = isinstance(exc, JobError)
        if not expected:
            traceback.print_exc()        # the log gets the details, the uploader a plain answer
        status.update(state="failed", finished=_now(),
                      error=str(exc) if expected else "The analysis could not be completed.")
        put_status()
        print(f"s3_wrapper: job {job_id} failed: {exc}", file=sys.stderr)
        return EXIT_FAILED
    status.update(state="done", report_key=report_key, finished=_now(), analysis_exit_code=code,
                  high_or_critical_findings=code == 1)
    put_status()
    print(f"Uploaded to s3://{out_bucket}/{report_key}")
    return EXIT_OK                        # findings are a result, not a failure of the job


def _analyse(s3, bucket: str, key: str, fmt: str, status: dict, env: dict) -> tuple[str, int]:
    limit = _int_env(env, "MAX_INPUT_BYTES", DEFAULT_MAX_INPUT_BYTES)
    try:
        size = int(s3.head_object(Bucket=bucket, Key=key)["ContentLength"])
    except Exception as exc:              # botocore's ClientError, without importing botocore here
        print(f"s3_wrapper: head_object failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise JobError("The uploaded file could not be found.") from exc
    status["input"]["bytes"] = size
    if size == 0:
        raise JobError("The uploaded file is empty.")
    if size > limit:
        raise JobError(f"The uploaded file is too large ({size:,} bytes; the limit is {limit:,}).")

    name = local_name(key)
    with tempfile.TemporaryDirectory(prefix="evtxkit-job-") as work:
        try:
            s3.download_file(bucket, key, os.path.join(work, name))
        except Exception as exc:
            print(f"s3_wrapper: download failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            raise JobError("The uploaded file could not be downloaded.") from exc
        timeout = _int_env(env, "ANALYSIS_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        try:
            # Relative path, run inside the work folder: the report's title then
            # shows the upload's name, not a temporary path.
            result = run_evtxkit(["analyze", name, "-f", fmt], cwd=work, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise JobError(f"The analysis did not finish within {timeout} seconds.") from exc
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode not in (0, 1):   # 0 = nothing high/critical, 1 = high/critical findings
        reason = next((ln for ln in result.stderr.splitlines() if ln.startswith("evtxkit:")), "")
        reason = reason[len("evtxkit:"):].strip()
        raise JobError("The file could not be analysed as a Windows event log"
                       + (f": {reason[:300]}" if reason else "."))
    return result.stdout, result.returncode


def main(argv: list[str] | None = None, env: dict | None = None, s3=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if env is None else env
    if env.get("INPUT_BUCKET") and env.get("INPUT_KEY"):
        return analysis_job(env, s3)
    return pass_through(argv, env, s3)


if __name__ == "__main__":
    raise SystemExit(main())
