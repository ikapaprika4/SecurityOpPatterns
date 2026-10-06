"""
Make the access codes for the upload page, one per person.

    python tools/access_codes.py alice bob
        a new random code for alice and for bob, and the USERS setting that
        holds their fingerprints

    python tools/access_codes.py carol --keep @current-users.json
        carol is added, alice and bob keep their codes (--keep takes the
        current USERS setting as JSON, or @file)

    python tools/access_codes.py --keep @current-users.json --remove bob
        bob is taken out; nobody else is affected

    python tools/access_codes.py alice --keep @current-users.json --remove alice
        alice gets a new code and the old one stops working

    ... --env-file build/upload-api-environment.json
        also writes the function's complete environment as a file for
        `aws lambda update-function-configuration --environment file://...`

A code is shown once, here, and is not kept anywhere: the setting holds only
its SHA-256 fingerprint, which cannot be turned back into the code. Run this
in your own terminal and give each person their code yourself, so a code never
has to be typed into a chat or an email thread. The codes are random and long
on purpose: a plain SHA-256 is only safe for codes nobody could guess.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import sys

NAME = re.compile(r"[a-z][a-z0-9]{1,19}")
FINGERPRINT = re.compile(r"[0-9a-f]{64}")
# Lambda keeps all of a function's environment variables within 4 KB.
WARN_ABOVE = 3000


def fingerprint(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def parse_keep(text: str) -> dict:
    """The current USERS setting, given as JSON or as @file."""
    if text.startswith("@"):
        with open(text[1:], encoding="utf-8") as fh:
            text = fh.read()
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError("--keep is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("--keep must be a JSON object like {\"alice\": \"<fingerprint>\"}")
    for name, value in data.items():
        if not NAME.fullmatch(name):
            raise ValueError(f"--keep has {name!r}, which is not a usable name")
        if not isinstance(value, str) or not FINGERPRINT.fullmatch(value):
            raise ValueError(f"--keep: the entry for {name!r} is not a lowercase hex SHA-256")
    return dict(data)


def make(names: list[str], keep: dict, remove: list[str]) -> tuple[dict, dict]:
    """(codes for the new people, the whole USERS setting)."""
    users = dict(keep)
    for name in set(remove):
        if name not in users:
            raise ValueError(f"{name!r} is not in --keep, so there is nothing to remove")
        del users[name]
    codes: dict = {}
    for name in names:
        if not NAME.fullmatch(name):
            raise ValueError(f"{name!r} is not a usable name: use a-z and 0-9, start with a letter, 2 to 20 characters")
        if name in users or name in codes:
            raise ValueError(f"{name!r} already has a code; use --remove {name} to give a new one")
        codes[name] = secrets.token_urlsafe(18)
        users[name] = fingerprint(codes[name])
    if not users:
        raise ValueError("that would leave nobody who can sign in")
    return codes, users


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Make access codes for the upload page, one per person.")
    parser.add_argument("names", nargs="*", help="people to make a code for (a-z and 0-9)")
    parser.add_argument("--keep", default="{}", metavar="JSON_OR_@FILE", help="the current USERS setting")
    parser.add_argument("--remove", nargs="+", default=[], metavar="NAME", help="people to take out")
    parser.add_argument("--env-file", metavar="PATH", help="also write the function's complete environment here")
    parser.add_argument("--uploads-bucket", default="evtxkit-uploads-772325758655")
    parser.add_argument("--reports-bucket", default="evtxkit-reports-772325758655")
    args = parser.parse_args(argv)
    if not args.names and not args.remove:
        parser.error("give at least one name, or --remove")
    try:
        codes, users = make(args.names, parse_keep(args.keep), args.remove)
    except (ValueError, OSError) as exc:
        print(f"access_codes: {exc}", file=sys.stderr)
        return 2

    setting = json.dumps(users, separators=(",", ":"), sort_keys=True)
    if codes:
        print("Codes. Shown once and kept nowhere: give each person theirs.")
        for name, code in codes.items():
            print(f"  {name:<20} {code}")
        print()
    if args.remove:
        print("Taken out: " + ", ".join(sorted(set(args.remove))))
        print()
    print(f"USERS setting ({len(users)} {'person' if len(users) == 1 else 'people'}; fingerprints only):")
    print(setting)
    if len(setting) > WARN_ABOVE:
        print(f"\nwarning: this is {len(setting)} characters and a Lambda function's whole environment is limited to "
              "4 KB. Past about 30 people, keep the fingerprints somewhere else (SSM Parameter Store).", file=sys.stderr)
    if args.env_file:
        environment = {"Variables": {"UPLOADS_BUCKET": args.uploads_bucket,
                                     "REPORT_BUCKET": args.reports_bucket, "USERS": setting}}
        folder = os.path.dirname(os.path.abspath(args.env_file))
        os.makedirs(folder, exist_ok=True)
        with open(args.env_file, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(environment, fh, indent=2)
            fh.write("\n")
        print(f"\nwrote {args.env_file}: the function's complete environment (it replaces every variable it has)")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(errors="replace")
    raise SystemExit(main())
