"""
Golden reference for tools/compare_pcap_backends.py: dump every field the
scapy backend of trafkit (the original implementation, kept opt-in in
trafkit/pcapread.py) produces for each packet, as JSON.

    pip install scapy
    python tools/dump_scapy_fields.py golden.json capture1.pcap [...]
    python tools/compare_pcap_backends.py golden.json capture1.pcap [...]

    --orig DIR   read with an untouched original trafkit instead (DIR is the
                 folder that contains the original `trafkit` package)
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def norm(v):
    if isinstance(v, (bytes, bytearray)):
        return {"__bytes__": bytes(v).hex()}
    if isinstance(v, (list, tuple)):
        return [norm(x) for x in v]
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return {"__repr__": repr(v), "__type__": type(v).__name__}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", help="golden JSON to write")
    ap.add_argument("captures", nargs="+")
    ap.add_argument("--orig", help="folder containing an original trafkit package")
    args = ap.parse_args()

    if args.orig:
        sys.path.insert(0, os.path.abspath(args.orig))
        from trafkit.pcapread import read_pcap
        read = read_pcap
    else:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from trafkit.pcapread import read_pcap

        def read(path):
            return read_pcap(path, backend="scapy")

    out = {}
    for path in args.captures:
        out[os.path.basename(path)] = [{
            "frame_number": r.frame_number, "ts": r.ts, "length": r.length,
            "src_mac": r.src_mac, "dst_mac": r.dst_mac, "src_ip": r.src_ip, "dst_ip": r.dst_ip,
            "proto": r.proto, "src_port": r.src_port, "dst_port": r.dst_port,
            "summary": r.summary,
            "fields": {k: norm(v) for k, v in r.fields.items()},
        } for r in read(path)]
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print(f"dumped {sum(len(v) for v in out.values())} packets from {len(out)} captures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
