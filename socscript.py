"""
socscript -- one entry point for the whole SOC toolkit (the container's ENTRYPOINT).

    socscript <tool> [arguments...]

    triage      any mix of evidence -> one case per email / host / capture,
                a report per case, and an exit code a pipeline can act on
    evtxkit     Windows event logs (Security, Sysmon, PowerShell)
    phish       emails (.eml, .msg, .mbox)
    nsm         network logs (firewall, IDS, VPN, WAF, DNS)
    trafkit     packet captures (.pcap, .pcapng)
    workbench   the web UI
    selftest    run the test suite shipped next to the code
    version

`socscript <tool> --help` shows that tool's own options.

Anything that is not a tool name is passed to evtxkit unchanged, so commands
written for the earlier evtxkit-only image keep working (`socscript rules`).
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

TOOLS = {
    "triage": "socworkbench.batch",
    "evtxkit": "evtxkit.cli",
    "phish": "phishkit.cli", "phishkit": "phishkit.cli",
    "nsm": "nsmkit.cli", "nsmkit": "nsmkit.cli",
    "trafkit": "trafkit.cli",
    "workbench": "socworkbench.__main__",
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0
    tool, rest = argv[0], argv[1:]
    if tool in ("version", "--version"):
        from socworkbench import __version__
        print(f"socscript (SOC Workbench {__version__}), Python {sys.version.split()[0]}")
        return 0
    if tool == "selftest":
        runner = os.path.join(ROOT, "run_tests.py")
        if not os.path.exists(runner):
            print("socscript: the test suite is not installed next to the code", file=sys.stderr)
            return 2
        return subprocess.call([sys.executable, runner, *rest], cwd=ROOT)
    if tool in TOOLS:
        return int(importlib.import_module(TOOLS[tool]).main(rest) or 0)
    # Not a tool name: the evtxkit-only image's command line (`rules`, `analyze x.jsonl`, ...).
    return int(importlib.import_module("evtxkit.cli").main(argv) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
