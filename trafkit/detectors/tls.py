"""
TLS handshake analysis (Wireshark: Traffic Analysis, task 7). Decrypting the
session itself needs an SSLKEYLOGFILE captured at the time -- nothing after
the fact can substitute for that -- so what trafkit can do from the capture
alone is: list every ClientHello/ServerHello with its SNI (the `tls`
subcommand), and flag a full TLS handshake riding on a port nobody expects
one on, which is a common way to hide a C2 channel in plain sight.
"""

from __future__ import annotations

from ..models import Finding, PacketRecord
from .base import AnalysisContext, Detector, register

# Ports where TLS is the norm: HTTPS/alt, mail submission and retrieval, LDAPS,
# FTPS, global catalog, DNS-over-TLS, SIP-TLS, Apple/Google push, MQTT-TLS.
_EXPECTED_TLS_PORTS = {443, 8443, 9443, 465, 587, 636, 993, 995, 989, 990, 3269,
                       853, 5061, 5223, 5228, 8883}


def tls_handshakes(packets: list[PacketRecord]) -> list[dict]:
    out = []
    for p in packets:
        f = p.fields
        if f.get("tls.handshake.type") is None:
            continue
        out.append({
            "frame": p.frame_number,
            "type": "ClientHello" if f["tls.handshake.type"] == 1 else (
                     "ServerHello" if f["tls.handshake.type"] == 2 else
                     f"handshake({f['tls.handshake.type']})"),
            "src": p.src_ip, "dst": p.dst_ip, "port": p.dst_port,
            "sni": f.get("tls.handshake.extensions_server_name"),
        })
    return out


@register
class TLSUnusualPortDetector(Detector):
    id = "TLS-PORT-01"
    title = "TLS handshake on an unexpected port"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        seen: dict[tuple, list[PacketRecord]] = {}
        for p in packets:
            f = p.fields
            if f.get("tls.handshake.type") != 1:  # ClientHello only
                continue
            port = p.dst_port
            if port in _EXPECTED_TLS_PORTS:
                continue
            seen.setdefault((p.src_ip, p.dst_ip, port), []).append(p)

        findings = []
        for (src, dst, port), pkts in seen.items():
            findings.append(self._finding(
                severity="medium", confidence="medium",
                description=(f"{src} completed a TLS ClientHello to {dst}:{port} -- a port not "
                             f"normally associated with TLS. Legitimate services do run TLS on "
                             f"nonstandard ports, but it's also a common way to blend a C2 "
                             f"channel into what looks like ordinary encrypted traffic on a scan."),
                frames=[p.frame_number for p in pkts[:10]],
                evidence={"src": src, "dst": dst, "port": port,
                          "sni": pkts[0].fields.get("tls.handshake.extensions_server_name")},
                recommendation="Check whether this port/service is documented for this host. If "
                                "an SSLKEYLOGFILE was captured for this session, decrypt and "
                                "inspect the application data.",
                mitre="T1571 Non-Standard Port",
            ))
        return findings
