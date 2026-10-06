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

    python tools/access_codes.py reviewer --expire reviewer=2026-10-20
        reviewer's code works through 20 October 2026 (UTC) and then stops by
        itself

    python tools/access_codes.py --keep @current-users.json --expire reviewer=2026-11-03
    python tools/access_codes.py --keep @current-users.json --expire reviewer=none
        move or remove the expiry of someone who already has a code; the code
        itself does not change

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
import datetime
import hashlib
import json
import os
import re
import secrets
import sys

NAME = re.compile(r"[a-z][a-z0-9]{1,19}")
FINGERPRINT = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
# Lambda keeps all of a function's environment variables within 4 KB.
WARN_ABOVE = 3000


def fingerprint(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def today() -> datetime.date:
    return datetime.datetime.now(datetime.timezone.utc).date()


def parse_date(text: str, what: str) -> str:
    """text as a YYYY-MM-DD date, or ValueError saying what was wrong with `what`."""
    try:
        if not DATE.fullmatch(text):
            raise ValueError
        return datetime.date.fromisoformat(text).isoformat()
    except ValueError:
        raise ValueError(f"{what}: {text!r} is not a date like 2026-10-20") from None


def parse_keep(text: str) -> dict:
    """The current USERS setting (JSON or @file) as {name: (fingerprint, last day or None)}."""
    if text.startswith("@"):
        with open(text[1:], encoding="utf-8") as fh:
            text = fh.read()
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ValueError("--keep is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("--keep must be a JSON object like {\"alice\": \"<fingerprint>\"}")
    users: dict = {}
    for name, entry in data.items():
        if not NAME.fullmatch(name):
            raise ValueError(f"--keep has {name!r}, which is not a usable name")
        expires = None
        if isinstance(entry, dict):
            if "sha256" not in entry or set(entry) - {"sha256", "expires"}:
                raise ValueError(f"--keep: the entry for {name!r} may only have sha256 and expires")
            if entry.get("expires") is not None:
                expires = parse_date(str(entry["expires"]), f"--keep, the expiry of {name!r}")
            entry = entry["sha256"]
        if not isinstance(entry, str) or not FINGERPRINT.fullmatch(entry):
            raise ValueError(f"--keep: the entry for {name!r} is not a lowercase hex SHA-256")
        users[name] = (entry, expires)
    return users


def parse_expire(items: list[str]) -> dict:
    """['reviewer=2026-10-20', 'bob=none'] -> {'reviewer': '2026-10-20', 'bob': None}."""
    wanted: dict = {}
    for item in items:
        name, _, value = item.partition("=")
        if not NAME.fullmatch(name) or not value:
            raise ValueError(f"--expire wants NAME=YYYY-MM-DD (or NAME=none), not {item!r}")
        if name in wanted:
            raise ValueError(f"--expire names {name!r} twice")
        wanted[name] = None if value.lower() == "none" else parse_date(value, "--expire")
    return wanted


def make(names: list[str], keep: dict, remove: list[str], expire: dict | None = None) -> tuple[dict, dict]:
    """(codes for the new people, the whole USERS setting as {name: (fingerprint, last day or None)})."""
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
        users[name] = (fingerprint(codes[name]), None)
    for name, last_day in (expire or {}).items():
        if name not in users:
            raise ValueError(f"--expire: {name!r} is not one of the people in the setting")
        if last_day is not None and datetime.date.fromisoformat(last_day) < today():
            raise ValueError(f"--expire: {last_day} is already past, which would lock {name} out at once "
                             "(use --remove for that)")
        users[name] = (users[name][0], last_day)
    if not users:
        raise ValueError("that would leave nobody who can sign in")
    return codes, users


def setting_of(users: dict) -> str:
    """The USERS setting: a plain fingerprint for a person with no expiry, an object for one with."""
    entries = {name: fp if last_day is None else {"sha256": fp, "expires": last_day}
               for name, (fp, last_day) in users.items()}
    return json.dumps(entries, separators=(",", ":"), sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Make access codes for the upload page, one per person.")
    parser.add_argument("names", nargs="*", help="people to make a code for (a-z and 0-9)")
    parser.add_argument("--keep", default="{}", metavar="JSON_OR_@FILE", help="the current USERS setting")
    parser.add_argument("--remove", nargs="+", default=[], metavar="NAME", help="people to take out")
    parser.add_argument("--expire", action="append", default=[], metavar="NAME=DATE",
                        help="the last day (UTC, YYYY-MM-DD) a person's code works, or NAME=none; repeatable")
    parser.add_argument("--env-file", metavar="PATH", help="also write the function's complete environment here")
    parser.add_argument("--uploads-bucket", default="evtxkit-uploads-772325758655")
    parser.add_argument("--reports-bucket", default="evtxkit-reports-772325758655")
    args = parser.parse_args(argv)
    if not args.names and not args.remove and not args.expire:
        parser.error("give at least one name, or --remove, or --expire")
    try:
        codes, users = make(args.names, parse_keep(args.keep), args.remove, parse_expire(args.expire))
    except (ValueError, OSError) as exc:
        print(f"access_codes: {exc}", file=sys.stderr)
        return 2

    setting = setting_of(users)
    if codes:
        print("Codes. Shown once and kept nowhere: give each person theirs.")
        for name, code in codes.items():
            print(f"  {name:<20} {code}")
        print()
    if args.remove:
        print("Taken out: " + ", ".join(sorted(set(args.remove))))
        print()
    expiring = {name: last_day for name, (_fp, last_day) in users.items() if last_day}
    if expiring:
        print("Codes that stop by themselves (the whole last day counts, UTC):")
        for name, last_day in sorted(expiring.items()):
            print(f"  {name:<20} last day {last_day}")
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
