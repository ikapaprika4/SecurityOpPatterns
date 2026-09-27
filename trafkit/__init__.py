"""
trafkit -- packet-native traffic analysis toolkit.

Companion to nsmkit (log-driven network security monitoring) and phishkit
(email/phishing analysis): where nsmkit reads firewall/IDS/VPN log lines,
trafkit reads the packets themselves, reimplementing the Wireshark and
NetworkMiner analyst workflow (display filters, Statistics overview, host
identification, scan/ARP/tunnelling/credential detection) as a scriptable,
testable library instead of a GUI you click through by hand.

    import trafkit
    result = trafkit.analyze("capture.pcapng")
    for finding in result.findings:
        print(finding.severity, finding.title)
"""

from __future__ import annotations

from .config import Config
from .detectors import REGISTRY, AnalysisContext, run_detectors  # noqa: F401 (registers detectors)
from .hosts import build_conversations, build_hosts
from .models import AnalysisResult, Artifact, Conversation, Credential, Finding, Host, PacketRecord
from .pcapread import read_pcap

__version__ = "1.0.0"

__all__ = [
    "analyze", "read_pcap", "Config", "AnalysisResult", "Artifact", "Conversation",
    "Credential", "Finding", "Host", "PacketRecord",
]


def analyze(path: str, cfg: Config | None = None) -> AnalysisResult:
    cfg = cfg or Config()
    status: dict = {}
    packets = read_pcap(path, status=status)
    hosts = build_hosts(packets)
    conversations = build_conversations(packets)
    ctx = AnalysisContext(hosts=hosts, conversations=conversations)
    findings = run_detectors(packets, ctx, cfg)
    return AnalysisResult(path=path, packets=packets, hosts=hosts,
                           conversations=conversations, findings=findings,
                           warnings=read_warnings(status, len(packets)))


def read_warnings(status: dict, n_packets: int) -> list[str]:
    """What an analyst must know about how completely the capture was read."""
    if status.get("problem"):
        return [f"the capture is damaged ({status['problem']}); only the first "
                f"{n_packets:,} frame(s) were analysed"]
    if n_packets == 0:
        return ["the capture contains no packets"]
    return []
