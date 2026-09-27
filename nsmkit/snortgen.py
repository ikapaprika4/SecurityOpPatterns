"""
Turn findings into Snort 2/3 rules and Suricata-compatible signatures.

The output is deliberately conservative: IOC-pinned rules (block this IP, alert
on this domain) rather than behavioural ones, because behavioural logic belongs
in the detectors above -- Snort's rule language cannot express "10 ports in 300
seconds" without `threshold`, and even then only crudely.

SID policy (from the Snort material):
    <100          reserved
    100-999,999   shipped rules
    >=1,000,000   locally authored -- what this generator emits
"""

from __future__ import annotations

from typing import Any, Iterable

_HEADER = """# ------------------------------------------------------------------
# Auto-generated local rules from nsmkit findings.
# Review before deploying. Place in /etc/snort/rules/local.rules and ensure
#   include $RULE_PATH/local.rules
# is uncommented in snort.conf (Snort 2) or the rules path in snort.lua (Snort 3).
# Test with:  snort -c /etc/snort/snort.conf -T
# ------------------------------------------------------------------
"""


def _esc(s: str) -> str:
    return str(s).replace('"', '').replace(";", "").replace("|", "")


def findings_to_snort(findings: Iterable[dict[str, Any]], start_sid: int = 1000001) -> str:
    lines = [_HEADER]
    sid = start_sid
    seen: set[str] = set()

    for f in findings:
        rule_id = f.get("rule_id", "")
        metrics = f.get("metrics") or {}
        sev = f.get("severity", "medium")
        prio = {"critical": 1, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 3)
        msg_base = _esc(f.get("title", rule_id))[:110]

        # --- external attacker IP: block inbound ---
        src = f.get("src_ip")
        if src and rule_id.startswith(("NSM-SCAN", "NSM-CRED", "NSM-WEB")):
            key = f"src:{src}"
            if key not in seen:
                seen.add(key)
                lines.append(
                    f'alert ip {src} any -> $HOME_NET any '
                    f'(msg:"LOCAL {msg_base}"; '
                    f'metadata:policy security-ips drop, source nsmkit, finding {rule_id}; '
                    f'classtype:attempted-recon; sid:{sid}; rev:1;)')
                sid += 1

        # --- C2 / exfil destination: alert on egress ---
        dst = f.get("dst_ip")
        port = metrics.get("port")
        if dst and rule_id.startswith(("NSM-C2", "NSM-EXFIL")):
            key = f"dst:{dst}:{port}"
            if key not in seen:
                seen.add(key)
                pspec = str(port) if isinstance(port, int) else "any"
                lines.append(
                    f'alert ip $HOME_NET any -> {dst} {pspec} '
                    f'(msg:"LOCAL C2/Exfil destination contacted - {msg_base}"; '
                    f'metadata:source nsmkit, finding {rule_id}; '
                    f'classtype:trojan-activity; priority:{prio}; sid:{sid}; rev:1;)')
                sid += 1

        # --- DNS tunnelling domain ---
        domain = metrics.get("domain")
        if domain and rule_id == "NSM-EXFIL-001":
            key = f"dns:{domain}"
            if key not in seen:
                seen.add(key)
                labels = _esc(domain).split(".")
                content = "".join(f"|{len(l):02x}|{l}" for l in labels)
                lines.append(
                    f'alert udp $HOME_NET any -> any 53 '
                    f'(msg:"LOCAL DNS tunnelling domain {_esc(domain)}"; '
                    f'content:"{content}"; nocase; '
                    f'metadata:source nsmkit, finding {rule_id}; '
                    f'classtype:trojan-activity; priority:1; sid:{sid}; rev:1;)')
                sid += 1
                # Length-based companion: catch the same tunnel on a new domain.
                lines.append(
                    f'alert udp $HOME_NET any -> any 53 '
                    f'(msg:"LOCAL Oversized DNS query name - possible tunnelling"; '
                    f'dsize:>150; threshold:type threshold, track by_src, count 20, seconds 60; '
                    f'classtype:policy-violation; priority:2; sid:{sid}; rev:1;)')
                sid += 1

        # --- exposed high-risk service ---
        if rule_id == "NSM-PERIM-001" and metrics.get("port"):
            key = f"perim:{f.get('dst_ip')}:{metrics['port']}"
            if key not in seen:
                seen.add(key)
                lines.append(
                    f'alert tcp $EXTERNAL_NET any -> {f.get("dst_ip")} {metrics["port"]} '
                    f'(msg:"LOCAL Inbound to exposed {_esc(metrics.get("service", "service"))}"; '
                    f'flags:S; threshold:type limit, track by_src, count 1, seconds 300; '
                    f'classtype:attempted-admin; priority:1; sid:{sid}; rev:1;)')
                sid += 1

        # --- ARP / MITM cannot be expressed in Snort rules; emit a comment ---
        if rule_id.startswith("NSM-MITM"):
            lines.append(f'# {rule_id}: {msg_base}\n'
                         f'#   Snort cannot match ARP reliably. Use the arpspoof preprocessor '
                         f'(Snort 2) or arp_spoof inspector (Snort 3), configured with the '
                         f'authoritative host/MAC list, e.g.\n'
                         f'#   preprocessor arpspoof\n'
                         f'#   preprocessor arpspoof_detect_host: <gateway_ip> <gateway_mac>')

    # --- always-useful generic companions ---
    lines += [
        "",
        "# --- generic behavioural companions (tune thresholds per environment) ---",
        f'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Horizontal scan - many hosts one port"; '
        f'flags:S; threshold:type threshold, track by_src, count 20, seconds 60; '
        f'classtype:attempted-recon; sid:{sid}; rev:1;)',
        f'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"LOCAL Vertical scan - many ports one host"; '
        f'flags:S; detection_filter:track by_src, count 15, seconds 60; '
        f'classtype:attempted-recon; sid:{sid + 1}; rev:1;)',
        f'alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL Oversized ICMP payload - possible tunnel"; '
        f'itype:8; dsize:>100; classtype:policy-violation; sid:{sid + 2}; rev:1;)',
        f'alert tcp $HOME_NET any -> $EXTERNAL_NET 4444 (msg:"LOCAL Egress to default Metasploit port"; '
        f'flags:S; classtype:trojan-activity; priority:1; sid:{sid + 3}; rev:1;)',
        f'alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"LOCAL FTP STOR upload to external host"; '
        f'content:"STOR"; nocase; depth:4; classtype:policy-violation; sid:{sid + 4}; rev:1;)',
    ]
    return "\n".join(lines) + "\n"
