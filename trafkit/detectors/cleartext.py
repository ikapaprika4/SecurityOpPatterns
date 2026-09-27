"""
Cleartext protocol analysis (Wireshark: Traffic Analysis, task 6) -- FTP
brute force / password spray signals, plus a general cleartext-credential
harvester (FTP, HTTP Basic/form auth) feeding the `creds` CLI command and
the NetworkMiner-style Credentials extraction in extract.py.
"""

from __future__ import annotations

import base64
from collections import defaultdict

from ..models import Credential, Finding, PacketRecord
from ._window import slide
from .base import AnalysisContext, Detector, register


@register
class FTPBruteForceDetector(Detector):
    id = "FTP-BRUTE-01"
    title = "FTP brute-force / password spray"

    def run(self, packets: list[PacketRecord], ctx: AnalysisContext) -> list[Finding]:
        findings = []
        findings += self._bruteforce(packets)
        findings += self._spray(packets)
        return findings

    def _bruteforce(self, packets: list[PacketRecord]) -> list[Finding]:
        by_pair: dict[tuple, list[PacketRecord]] = defaultdict(list)
        for p in packets:
            if p.fields.get("ftp.response.code") == 530:
                by_pair[(p.dst_ip, p.src_ip)].append(p)  # (client, server) i.e. server is p.src

        findings = []
        for (client, server), pkts in by_pair.items():
            pkts.sort(key=lambda x: x.ts)
            window = _slide(pkts, self.cfg.bruteforce_window_seconds)
            if window is None or len(window) < self.cfg.bruteforce_min_failures:
                continue
            findings.append(self._finding(
                severity="high", confidence="high",
                description=(f"{len(window)} failed FTP logins (530) from {client} against "
                             f"{server} within {self.cfg.bruteforce_window_seconds}s -- brute-force "
                             f"pattern, not a user mistyping a password a couple of times."),
                frames=[p.frame_number for p in window[:25]],
                evidence={"client": client, "server": server, "failure_count": len(window)},
                recommendation="Check whether any attempt in this window succeeded (230) -- if so, "
                                "escalate as a confirmed compromise, not just an attempt.",
                mitre="T1110.001 Brute Force: Password Guessing",
            ))
        return findings

    def _spray(self, packets: list[PacketRecord]) -> list[Finding]:
        # Pair each PASS with the USER immediately preceding it on the same
        # (client, server) stream, then group by (server, password).
        by_pair: dict[tuple, list[PacketRecord]] = defaultdict(list)
        for p in packets:
            if p.fields.get("ftp.request.command") in ("USER", "PASS"):
                by_pair[(p.src_ip, p.dst_ip)].append(p)

        by_server_password: dict[tuple, set] = defaultdict(set)
        frames_by_key: dict[tuple, list] = defaultdict(list)
        for (client, server), pkts in by_pair.items():
            pkts.sort(key=lambda x: x.ts)
            last_user = None
            for p in pkts:
                cmd, arg = p.fields.get("ftp.request.command"), p.fields.get("ftp.request.arg")
                if cmd == "USER":
                    last_user = arg
                elif cmd == "PASS" and last_user:
                    key = (server, arg)
                    by_server_password[key].add(last_user)
                    frames_by_key[key].append(p.frame_number)
                    last_user = None

        findings = []
        for (server, password), users in by_server_password.items():
            if len(users) < self.cfg.spray_min_targets:
                continue
            findings.append(self._finding(
                rule_id="FTP-BRUTE-02", title="FTP password spray",
                severity="high", confidence="medium",
                description=(f"The same password was tried against {len(users)} different "
                             f"usernames on {server} -- a password-spray pattern (one password, "
                             f"many accounts) rather than a brute force (many passwords, one "
                             f"account)."),
                frames=frames_by_key[(server, password)][:25],
                evidence={"server": server, "usernames_tried": sorted(users)[:50]},
                recommendation="Password spraying is designed to dodge per-account lockout "
                                "thresholds -- check every listed username for a subsequent "
                                "successful login (230), not just for repeated failures.",
                mitre="T1110.003 Brute Force: Password Spraying",
            ))
        return findings


def extract_credentials(packets: list[PacketRecord]) -> list[Credential]:
    """NetworkMiner-style credential harvest: FTP USER/PASS pairs and HTTP
    Basic-Auth / form-style credentials seen in the clear."""
    creds: list[Credential] = []

    by_ftp_pair: dict[tuple, list[PacketRecord]] = defaultdict(list)
    for p in packets:
        if p.fields.get("ftp.request.command") in ("USER", "PASS"):
            by_ftp_pair[(p.src_ip, p.dst_ip)].append(p)
    for (client, server), pkts in by_ftp_pair.items():
        pkts.sort(key=lambda x: x.ts)
        pending_user, pending_frame = None, None
        for p in pkts:
            cmd, arg = p.fields.get("ftp.request.command"), p.fields.get("ftp.request.arg")
            if cmd == "USER":
                pending_user, pending_frame = arg, p.frame_number
            elif cmd == "PASS":
                creds.append(Credential(protocol="ftp", frame=p.frame_number, src=client, dst=server,
                                         username=pending_user, secret=arg, secret_type="cleartext"))
                pending_user = None

    for p in packets:
        auth = p.fields.get("http.authorization")
        if auth and auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth.split(None, 1)[1]).decode("utf-8", "replace")
                user, _, secret = decoded.partition(":")
                creds.append(Credential(protocol="http-basic", frame=p.frame_number,
                                         src=p.src_ip, dst=p.dst_ip,
                                         username=user, secret=secret, secret_type="cleartext"))
            except Exception:
                pass
        body = p.fields.get("http.file_data")
        if body and ("password=" in body or "passwd=" in body or "pwd=" in body):
            user = _form_field(body, ("username", "user", "email", "login"))
            secret = _form_field(body, ("password", "passwd", "pwd"))
            if secret:
                creds.append(Credential(protocol="http-form", frame=p.frame_number,
                                         src=p.src_ip, dst=p.dst_ip,
                                         username=user, secret=secret, secret_type="cleartext"))
    return creds


def _form_field(body: str, names: tuple) -> str | None:
    for part in body.split("&"):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        if k.strip().lower() in names:
            return v.strip()
    return None


def _slide(pkts: list[PacketRecord], window_seconds: int):
    return slide(pkts, window_seconds)
