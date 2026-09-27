"""
Differential check: the native packet reader (soccore.pcap) against a golden
JSON dump of what the original scapy-backed trafkit reader produced for the
same captures.

    python tools/compare_pcap_backends.py golden.json capture1.pcap [...]

Produce the golden file with scapy installed (see tools/dump_scapy_fields.py).
Rules: every non-None field scapy produced must be present with the same
value in the native output, except for a short, documented list of fields
whose native value is intentionally closer to Wireshark. Fields only the
native reader produces are reported but not treated as failures.
"""

from __future__ import annotations

import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soccore.pcap import read_packets  # noqa: E402

# Native value intentionally differs (documented in docs/CHANGES.md).
INTENTIONAL = {
    "http.request.full_uri",   # native: http://host/path (Wireshark); scapy build: path only
}


def _is_ipv4(v) -> bool:
    parts = str(v).split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _skip(key: str, scapy_val, native: dict) -> bool:
    """Differences where the scapy-backed reader was wrong or incomplete."""
    # scapy-trafkit stored the *first* answer of any type in dns.a and only ever
    # captured one answer; native follows Wireshark (dns.a = first A record) and
    # keeps every answer. Compare only where scapy's first answer was an A record.
    if key == "dns.a":
        return not _is_ipv4(scapy_val)
    if key == "dns.resp_all":
        return native.get("dns.resp_all", [])[:len(scapy_val)] == scapy_val or not all(
            _is_ipv4(v) for v in scapy_val)
    # A genuine RFC 4120 message: scapy-trafkit's strict parse failed and its
    # string-scan fallback merged the service name into the client name.
    if key in ("kerberos.strings", "kerberos.CNameString", "kerberos.hostname") \
            and "kerberos.pvno" in native:
        return True
    # scapy counts Ethernet padding (bytes past the IP total length) as
    # transport payload; native bounds payloads by ip.len.
    if key == "data.len" and "ip.len" in native:
        link = 14 + 4 * ("vlan.id" in native)
        if native.get("frame.cap_len", 0) > link + native["ip.len"]:
            return True
    return False


def main(golden_path: str, captures: list[str]) -> int:
    golden = json.load(open(golden_path, encoding="utf-8"))
    mismatches = 0
    extras: Counter[str] = Counter()
    compared = 0
    for cap in captures:
        name = os.path.basename(cap)
        want = golden.get(name)
        if want is None:
            print(f"  (no golden data for {name})")
            continue
        got = read_packets(cap)
        if len(got) != len(want):
            print(f"  {name}: packet count native={len(got)} scapy={len(want)}")
            mismatches += 1
        for g, w in zip(got, want):
            compared += 1
            where = f"{name}#{w['frame_number']}"
            for attr in ("src_mac", "dst_mac", "src_ip", "dst_ip", "proto", "src_port",
                         "dst_port", "length"):
                if w[attr] is None and getattr(g, attr) is not None and (
                        "ipv6.src" in g.fields or "sll.src.eth" in g.fields):
                    continue      # IPv6 / SLL: the scapy build never dissected these
                if getattr(g, attr) != w[attr]:
                    print(f"  {where}: {attr} native={getattr(g, attr)!r} scapy={w[attr]!r}")
                    mismatches += 1
            if abs(g.ts - w["ts"]) > 1e-5:
                print(f"  {where}: ts native={g.ts!r} scapy={w['ts']!r}")
                mismatches += 1
            for key, wv in w["fields"].items():
                if wv is None or key in INTENTIONAL or _skip(key, wv, g.fields):
                    continue
                gv = g.fields.get(key, "<absent>")
                if isinstance(wv, float) or isinstance(gv, float):
                    same = isinstance(gv, (int, float)) and abs(gv - wv) < 1e-5
                else:
                    same = gv == wv
                if not same:
                    print(f"  {where}: {key} native={gv!r} scapy={wv!r}")
                    mismatches += 1
            for key in g.fields:
                if key not in w["fields"] or w["fields"][key] is None:
                    extras[key] += 1
    print(f"\ncompared {compared} packets across {len(captures)} captures: "
          f"{mismatches} mismatch(es)")
    if extras:
        print("native-only fields (additive): "
              + ", ".join(f"{k}({n})" for k, n in sorted(extras.items())))
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2:]))
