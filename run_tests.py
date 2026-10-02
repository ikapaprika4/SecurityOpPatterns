"""
Run every test suite in the workbench and print one summary.

    python run_tests.py            all suites
    python run_tests.py trafkit    just the named suite(s)

Each suite runs in its own interpreter, so one suite's imports or module
state can never mask a failure in another.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.join(ROOT, "tests")

# unittest prints "Ran N tests" + "OK"/"FAILED (...)"; the phishkit/nsmkit
# runners print "N passed, M failed, T total".
_UNITTEST_RAN = re.compile(r"^Ran (\d+) tests?", re.M)
_UNITTEST_FAIL = re.compile(r"^FAILED \((?:failures=(\d+))?(?:, )?(?:errors=(\d+))?", re.M)
_UNITTEST_SKIP = re.compile(r"^(?:OK|FAILED) \(.*?skipped=(\d+)", re.M)
_CUSTOM = re.compile(r"(\d+) passed, (\d+) failed, (\d+) total")


def run_suite(path: str) -> tuple[int, int, int, float, str]:
    """(passed, failed, skipped, seconds, output) for one suite."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    t0 = time.perf_counter()
    proc = subprocess.run([sys.executable, path], cwd=ROOT, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", env=env)
    elapsed = time.perf_counter() - t0
    out = proc.stdout + proc.stderr

    m = _CUSTOM.search(out)
    if m:
        passed, failed = int(m.group(1)), int(m.group(2))
        return passed, failed, 0, elapsed, out
    ran = _UNITTEST_RAN.search(out)
    if ran:
        total = int(ran.group(1))
        fm = _UNITTEST_FAIL.search(out)
        failed = sum(int(g or 0) for g in fm.groups()) if fm else 0
        sm = _UNITTEST_SKIP.search(out)
        skipped = int(sm.group(1)) if sm else 0      # e.g. the Windows-only wevtutil test, on Linux
        return total - failed - skipped, failed, skipped, elapsed, out
    # The suite could not even start (import error, missing dependency, ...).
    return 0, max(1, proc.returncode), 0, elapsed, out


def main(argv: list[str]) -> int:
    wanted = set(argv)
    suites = sorted(f for f in os.listdir(TESTS) if re.fullmatch(r"test_\w+\.py", f))
    if wanted:
        unknown = wanted - {s[5:-3] for s in suites}
        if unknown:                 # a typo must not pass as "0 failed"
            print(f"no such test suite: {', '.join(sorted(unknown))} "
                  f"(have: {', '.join(s[5:-3] for s in suites)})", file=sys.stderr)
            return 2
        suites = [s for s in suites if s[5:-3] in wanted]
    total_pass = total_fail = total_skip = 0
    for name in suites:
        passed, failed, skipped, elapsed, out = run_suite(os.path.join(TESTS, name))
        total_pass += passed
        total_fail += failed
        total_skip += skipped
        status = "ok  " if failed == 0 else "FAIL"
        print(f"  {status} {name[5:-3]:<12} {passed:>4} passed  {failed:>3} failed  ({elapsed:5.1f}s)"
              + (f"  {skipped} skipped" if skipped else ""))
        if failed:
            tail = [ln for ln in out.splitlines()
                    if re.search(r"FAIL|ERROR|Error|Traceback|assert", ln)][:12]
            for ln in tail:
                print(f"         {ln[:160]}")
    print(f"\n  {total_pass} passed, {total_fail} failed" + (f", {total_skip} skipped" if total_skip else ""))
    return 1 if total_fail or not total_pass else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
