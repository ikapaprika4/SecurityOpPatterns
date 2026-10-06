"""
Package the two Lambda functions as zip files.

    python tools/build_lambdas.py            writes build/start-analysis.zip and build/upload-api.zip
    python tools/build_lambdas.py --out DIR  writes them to DIR instead

start-analysis.zip is its handler. upload-api.zip is its handler, the page
(web/) and the sample logs the page offers: samples.json lists them, and the
files themselves are copied from samples/evtxkit, so there is one copy of each
in the repository. A sample that samples.json lists but that is not there makes
this fail, rather than ship a page with a dead button.

The zips are the same every time for the same files (fixed dates, sorted
entries), so a changed zip means changed code.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAMBDAS = os.path.join(ROOT, "aws", "lambda")
SAMPLES = os.path.join(ROOT, "samples", "evtxkit")
FIXED_DATE = (2026, 1, 1, 0, 0, 0)


def read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def start_analysis_files() -> dict:
    return {"handler.py": read(os.path.join(LAMBDAS, "start_analysis", "handler.py"))}


def upload_api_files() -> dict:
    folder = os.path.join(LAMBDAS, "upload_api")
    files = {"handler.py": read(os.path.join(folder, "handler.py")),
             "samples.json": read(os.path.join(folder, "samples.json"))}
    for name in sorted(os.listdir(os.path.join(folder, "web"))):
        files[f"web/{name}"] = read(os.path.join(folder, "web", name))
    for entry in json.loads(files["samples.json"]):
        path = os.path.join(SAMPLES, entry["file"])
        if not os.path.isfile(path):
            raise FileNotFoundError(f"samples.json lists {entry['file']}, which is not in {SAMPLES}")
        files[f"samples/{entry['file']}"] = read(path)
    return files


def write_zip(path: str, files: dict) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, FIXED_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16        # readable by the function's user
            zf.writestr(info, files[name])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package the two Lambda functions.")
    parser.add_argument("--out", default=os.path.join(ROOT, "build"), help="folder for the zip files (default: build)")
    args = parser.parse_args(argv)
    try:
        built = {"start-analysis.zip": start_analysis_files(), "upload-api.zip": upload_api_files()}
    except (OSError, ValueError, KeyError) as exc:
        print(f"build_lambdas: {exc}", file=sys.stderr)
        return 2
    for name, files in built.items():
        target = os.path.join(args.out, name)
        write_zip(target, files)
        print(f"{target}  ({os.path.getsize(target):,} bytes, {len(files)} files)")
        for entry in sorted(files):
            print(f"    {entry}  {len(files[entry]):,}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
