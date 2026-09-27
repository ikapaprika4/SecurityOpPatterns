"""
NetworkMiner-style artifact extraction: credentials, transferred-file
metadata, keyword hits, and the resolved-address table -- the "low hanging
fruit" pass meant to run before anyone opens a single packet by hand.

Note on file extraction: trafkit works packet-by-packet (see pcapread.py)
rather than doing full TCP stream reassembly, so `extract_files` recovers
file *metadata* (name, size, content type, which packet announced it) the
same way a firewall/proxy log would -- not the reassembled bytes NetworkMiner
would save to disk. That's a deliberate scope line, not an oversight: real
byte-for-byte carving needs a stream reassembler, which is a project on its
own. `phish attachments --extract` in the sibling toolkit does full
reconstruction because MIME attachments arrive as one contiguous blob;
here they don't.
"""

from __future__ import annotations

from collections import defaultdict

from .detectors.cleartext import extract_credentials  # re-exported
from .hosts import resolved_addresses  # re-exported
from .models import Artifact, Credential, PacketRecord

__all__ = ["extract_credentials", "resolved_addresses", "extract_files",
           "search_keywords"]


def extract_files(packets: list[PacketRecord]) -> list[Artifact]:
    out = []
    for p in packets:
        f = p.fields
        if not f.get("http.response"):
            continue
        cd = f.get("http.content_disposition", "")
        ct = f.get("http.content_type", "")
        filename = None
        if "filename=" in cd:
            filename = cd.split("filename=", 1)[1].strip().strip('"')
        elif ct and ct not in ("text/html", "text/plain") and "/" in ct:
            filename = f"(unnamed).{ct.split('/')[-1]}"
        if not filename:
            continue
        out.append(Artifact(kind="file", frame=p.frame_number, detail={
            "filename": filename, "content_type": ct,
            "src": p.dst_ip, "dst": p.src_ip,  # server -> client
        }))
    return out


def search_keywords(packets: list[PacketRecord], keywords: list[str]) -> list[Artifact]:
    """Case-insensitive substring search across every text-ish field trafkit
    extracted -- the room's "Keywords" tab. Reload-after-adding-keywords in
    NetworkMiner is just re-running this with a new list here."""
    if not keywords:
        return []
    needles = [k.lower() for k in keywords]
    fields_to_search = (
        "http.request.uri", "http.host", "http.user_agent", "http.file_data",
        "ftp.request.arg", "ftp.response.arg", "dns.qry.name",
        "kerberos.realm", "kerberos.CNameString", "nbns.name",
        "dhcp.option.hostname",
    )
    out = []
    for p in packets:
        for field_name in fields_to_search:
            value = p.fields.get(field_name)
            if not value:
                continue
            low = str(value).lower()
            for needle, original in zip(needles, keywords):
                if needle in low:
                    out.append(Artifact(kind="keyword", frame=p.frame_number, detail={
                        "keyword": original, "field": field_name,
                        "context": str(value)[:200],
                        "src": p.src_ip, "dst": p.dst_ip,
                    }))
    return out
