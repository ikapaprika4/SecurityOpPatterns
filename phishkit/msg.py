"""
Outlook .msg reading with the standard library only.

A .msg file is an OLE2 Compound File (a small FAT filesystem in one file)
whose streams are MAPI properties named `__substg1.0_<PROPID><TYPE>`. For
triage only a handful matter, and the most important one makes the rest
easy: PR_TRANSPORT_MESSAGE_HEADERS (0x007D) is the complete original
Internet header block -- Received chain, Authentication-Results, everything
the .eml path analyses. So a .msg is rebuilt into an RFC 5322 message
(original headers + text/HTML bodies + attachments) and handed to the
regular parser; no rule needs to know the input was Outlook's format.

Handles: CFB v3 (512-byte sectors) and v4 (4096), the mini stream, DIFAT
chains, Unicode (001F) and ANSI (001E) string properties, binary HTML bodies
(1013/0102), and attachment storages (`__attach_version1.0_#XXXXXXXX`,
long/short filename, data, MIME tag). Embedded .msg attachments are kept as
opaque attachments (their own triage is one more drag-and-drop away).
"""

from __future__ import annotations

import struct
from email.message import EmailMessage
from email.policy import SMTP
from typing import Optional

_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_FREESECT, _ENDOFCHAIN = 0xFFFFFFFF, 0xFFFFFFFE
_NOSTREAM = 0xFFFFFFFF


class MsgError(ValueError):
    pass


class CompoundFile:
    """Minimal read-only OLE2 / CFB reader (MS-CFB)."""

    def __init__(self, data: bytes):
        if data[:8] != _MAGIC:
            raise MsgError("not an OLE2 compound file")
        self.data = data
        (minor, major, bom, sec_shift, mini_shift) = struct.unpack_from("<HHHHH", data, 24)
        self.sector_size = 1 << sec_shift
        self.mini_size = 1 << mini_shift
        (self.n_fat, self.dir_start, _tx, self.mini_cutoff, self.minifat_start,
         self.n_minifat, self.difat_start, self.n_difat) = struct.unpack_from("<IIIIIIII", data, 44)
        self.fat = self._read_fat()
        self.dir_entries = self._read_directory()
        root = self.dir_entries[0] if self.dir_entries else None
        if root is None:
            raise MsgError("compound file has no root entry")
        self.ministream = self._chain_bytes(root["start"], root["size"]) if root["size"] else b""
        self.minifat = self._read_minifat()

    # -- sectors --------------------------------------------------------
    def _sector(self, n: int) -> bytes:
        off = (n + 1) * self.sector_size
        return self.data[off:off + self.sector_size]

    def _read_fat(self) -> list[int]:
        difat = list(struct.unpack_from("<109I", self.data, 76))
        nxt, guard = self.difat_start, 0
        per = self.sector_size // 4 - 1
        while nxt not in (_FREESECT, _ENDOFCHAIN) and guard < 10000:
            sec = self._sector(nxt)
            vals = struct.unpack_from(f"<{per + 1}I", sec, 0)
            difat.extend(vals[:per])
            nxt = vals[per]
            guard += 1
        fat: list[int] = []
        for s in difat[:self.n_fat]:
            if s in (_FREESECT, _ENDOFCHAIN):
                continue
            sec = self._sector(s)
            fat.extend(struct.unpack_from(f"<{len(sec) // 4}I", sec, 0))
        return fat

    def _chain(self, start: int, table: list[int]) -> list[int]:
        out, s, seen = [], start, set()
        while s not in (_FREESECT, _ENDOFCHAIN) and s < len(table) and s not in seen:
            seen.add(s)
            out.append(s)
            s = table[s]
        return out

    def _chain_bytes(self, start: int, size: int) -> bytes:
        return b"".join(self._sector(s) for s in self._chain(start, self.fat))[:size]

    def _read_minifat(self) -> list[int]:
        if not self.n_minifat or self.minifat_start in (_FREESECT, _ENDOFCHAIN):
            return []
        raw = b"".join(self._sector(s) for s in self._chain(self.minifat_start, self.fat))
        return list(struct.unpack_from(f"<{len(raw) // 4}I", raw, 0))

    def _read_directory(self) -> list[dict]:
        raw = b"".join(self._sector(s) for s in self._chain(self.dir_start, self.fat))
        entries = []
        for off in range(0, len(raw) - 127, 128):
            name_len = struct.unpack_from("<H", raw, off + 64)[0]
            name = raw[off:off + max(0, name_len - 2)].decode("utf-16-le", "replace")
            etype = raw[off + 66]
            left, right, child = struct.unpack_from("<III", raw, off + 68)
            start, size = struct.unpack_from("<IQ", raw, off + 116)
            if self.sector_size == 512:
                size &= 0xFFFFFFFF
            entries.append({"name": name, "type": etype, "left": left, "right": right,
                            "child": child, "start": start, "size": size})
        return entries

    # -- tree -----------------------------------------------------------
    def children(self, index: int) -> dict[str, int]:
        """name -> entry index for the direct children of a storage."""
        out: dict[str, int] = {}
        root = self.dir_entries[index]["child"]
        stack, guard = [root], 0
        while stack and guard < 100000:
            i = stack.pop()
            guard += 1
            if i == _NOSTREAM or i >= len(self.dir_entries):
                continue
            e = self.dir_entries[i]
            out[e["name"]] = i
            stack.extend((e["left"], e["right"]))
        return out

    def read(self, index: int) -> bytes:
        e = self.dir_entries[index]
        if e["size"] < self.mini_cutoff and index != 0:
            chain = self._chain(e["start"], self.minifat)
            blob = b"".join(self.ministream[s * self.mini_size:(s + 1) * self.mini_size]
                            for s in chain)
            return blob[:e["size"]]
        return self._chain_bytes(e["start"], e["size"])


# --------------------------------------------------------------------------
# MAPI properties
# --------------------------------------------------------------------------

def _props(cf: CompoundFile, storage: int) -> dict[str, bytes]:
    """'007D' -> raw bytes, preferring the Unicode (001F) variant."""
    out: dict[str, bytes] = {}
    for name, idx in cf.children(storage).items():
        if not name.startswith("__substg1.0_") or len(name) < 20:
            continue
        prop, ptype = name[12:16].upper(), name[16:20].upper()
        raw = cf.read(idx)
        if ptype == "001F":
            out[prop] = raw.decode("utf-16-le", "replace").rstrip("\x00").encode("utf-8")
            out[prop + ":u"] = b"1"
        elif ptype == "001E" and prop + ":u" not in out:
            out[prop] = raw.rstrip(b"\x00")
        elif ptype == "0102":
            out[prop + ":bin"] = raw
    return out


def _text(props: dict[str, bytes], prop: str) -> str:
    v = props.get(prop)
    if v is None:
        return ""
    try:
        return v.decode("utf-8")
    except UnicodeDecodeError:
        return v.decode("cp1252", "replace")


def looks_like_msg(data: bytes) -> bool:
    return data[:8] == _MAGIC


def msg_to_eml(data: bytes) -> tuple[bytes, list[str]]:
    """Rebuild an Outlook .msg as RFC 5322 bytes. Returns (eml, notes)."""
    cf = CompoundFile(data)
    notes: list[str] = []
    props = _props(cf, 0)
    headers = _text(props, "007D")          # PR_TRANSPORT_MESSAGE_HEADERS
    subject = _text(props, "0037")
    body_text = _text(props, "1000")
    html_bin = props.get("1013:bin")
    body_html = ""
    if html_bin:
        body_html = html_bin.decode("utf-8", "replace") if html_bin[:3] != b"\xff\xfe" else \
            html_bin.decode("utf-16", "replace")
    elif props.get("1013"):
        body_html = _text(props, "1013")

    msg = EmailMessage(policy=SMTP)
    if headers.strip():
        # Keep the original header block verbatim: it is the evidence.
        from email.parser import HeaderParser
        parsed = HeaderParser().parsestr(headers.strip() + "\r\n\r\n")
        skip = {"content-type", "content-transfer-encoding", "mime-version"}
        for key, value in parsed.items():
            if key.lower() not in skip:
                try:
                    msg[key] = value
                except (ValueError, TypeError):
                    notes.append(f"header {key!r} could not be carried over")
    else:
        notes.append("the .msg has no transport headers (it was probably created or saved "
                     "inside Outlook, not received), so the delivery path and SPF/DKIM/DMARC "
                     "results are unavailable")
        sender_name = _text(props, "0C1A")
        sender_addr = _text(props, "5D01") or _text(props, "0C1F") or _text(props, "0065")
        if sender_addr:
            msg["From"] = f'"{sender_name}" <{sender_addr}>' if sender_name else sender_addr
        if _text(props, "0E04"):
            msg["To"] = _text(props, "0E04")
        if _text(props, "0E03"):
            msg["Cc"] = _text(props, "0E03")
    if subject and "Subject" not in msg:
        msg["Subject"] = subject

    if body_text or not body_html:
        msg.set_content(body_text or "")
        if body_html:
            msg.add_alternative(body_html, subtype="html")
    else:
        msg.set_content(body_html, subtype="html")

    for name, idx in cf.children(0).items():
        if not name.startswith("__attach_version1.0_"):
            continue
        ap = _props(cf, idx)
        filename = (_text(ap, "3707") or _text(ap, "3704") or _text(ap, "3001")
                    or "attachment.bin")
        blob = ap.get("3701:bin")
        if blob is None:
            kids = cf.children(idx)
            if "__substg1.0_3701000D" in kids:
                notes.append(f"attachment {filename!r} is an embedded Outlook item; "
                             "analyse it separately")
                blob = b""
            else:
                blob = b""
        mime = _text(ap, "370E") or "application/octet-stream"
        maintype, _, subtype = mime.partition("/")
        try:
            msg.add_attachment(blob, maintype=maintype or "application",
                               subtype=subtype or "octet-stream", filename=filename)
        except (TypeError, ValueError):
            msg.add_attachment(blob, maintype="application", subtype="octet-stream",
                               filename=filename)
    return msg.as_bytes(), notes


def read_msg(path: str) -> tuple[bytes, list[str]]:
    with open(path, "rb") as fh:
        return msg_to_eml(fh.read())


def build_msg(headers: str, subject: str, body: str, html: Optional[str] = None,
              attachments: Optional[list[tuple[str, bytes]]] = None) -> bytes:
    """Write a small but valid .msg (CFB v3) -- used by tests and the sample
    generator, so .msg support is exercised without shipping Outlook files."""
    streams: dict[str, bytes] = {
        "__substg1.0_007D001F": headers.encode("utf-16-le"),
        "__substg1.0_0037001F": subject.encode("utf-16-le"),
        "__substg1.0_1000001F": body.encode("utf-16-le"),
    }
    if html is not None:
        streams["__substg1.0_10130102"] = html.encode("utf-8")
    storages: dict[str, dict[str, bytes]] = {}
    for i, (fname, data) in enumerate(attachments or []):
        storages[f"__attach_version1.0_#{i:08X}"] = {
            "__substg1.0_3707001F": fname.encode("utf-16-le"),
            "__substg1.0_37010102": data,
        }
    return _write_cfb(streams, storages)


def _write_cfb(streams: dict[str, bytes], storages: dict[str, dict[str, bytes]]) -> bytes:
    """Tiny CFB v3 writer following the spec's layout: streams under the
    4096-byte cutoff live in the mini stream (as in real .msg files, where
    nearly every property does), larger ones in regular sectors."""
    SEC, MINI, CUTOFF = 512, 64, 4096
    entries = [{"name": "Root Entry", "type": 5, "data": b"", "kids": []}]

    def add(name, etype, data=b""):
        entries.append({"name": name, "type": etype, "data": data, "kids": []})
        return len(entries) - 1

    for name, data in streams.items():
        entries[0]["kids"].append(add(name, 2, data))
    for sname, kids in storages.items():
        sidx = add(sname, 1)
        entries[0]["kids"].append(sidx)
        for name, data in kids.items():
            entries[sidx]["kids"].append(add(name, 2, data))

    sectors: list[bytes] = []
    fat: list[int] = []

    def alloc(blob: bytes) -> int:
        if not blob:
            return _ENDOFCHAIN
        start = len(sectors)
        for off in range(0, len(blob), SEC):
            sectors.append(blob[off:off + SEC].ljust(SEC, b"\x00"))
            fat.append(len(sectors))
        fat[-1] = _ENDOFCHAIN
        return start

    ministream = bytearray()
    minifat: list[int] = []

    def alloc_mini(blob: bytes) -> int:
        if not blob:
            return _ENDOFCHAIN
        start = len(ministream) // MINI
        count = (len(blob) + MINI - 1) // MINI
        ministream.extend(blob.ljust(count * MINI, b"\x00"))
        minifat.extend(range(start + 1, start + count + 1))
        minifat[-1] = _ENDOFCHAIN
        return start

    for e in entries[1:]:
        if e["type"] == 2:
            e["start"] = alloc_mini(e["data"]) if len(e["data"]) < CUTOFF else alloc(e["data"])
    root = entries[0]
    root["data"] = bytes(ministream)
    root["start"] = alloc(root["data"])
    minifat_blob = b"".join(struct.pack("<I", v) for v in minifat)
    n_minifat = (len(minifat_blob) + SEC - 1) // SEC
    minifat_start = alloc(minifat_blob.ljust(n_minifat * SEC, b"\xff")) if minifat else _ENDOFCHAIN

    # Siblings ordered the way CFB compares names (length, then upper-case),
    # linked as a right-leaning chain -- readers must not rely on balance.
    for e in entries:
        kids = sorted(e["kids"], key=lambda i: (len(entries[i]["name"]), entries[i]["name"].upper()))
        e["child"] = kids[0] if kids else _NOSTREAM
        for a, b in zip(kids, kids[1:] + [None]):
            entries[a]["right"] = b if b is not None else _NOSTREAM
            entries[a]["left"] = _NOSTREAM
    dir_blob = b""
    for e in entries:
        name16 = e["name"].encode("utf-16-le") + b"\x00\x00"
        rec = name16.ljust(64, b"\x00") + struct.pack("<HBB", len(name16), e["type"], 1)
        rec += struct.pack("<III", e.get("left", _NOSTREAM), e.get("right", _NOSTREAM), e["child"])
        rec += b"\x00" * 36                               # CLSID, state bits, timestamps
        start = e.get("start", _ENDOFCHAIN) if e["type"] in (2, 5) else 0
        rec += struct.pack("<IQ", start, len(e["data"]))
        dir_blob += rec
    dir_blob = dir_blob.ljust(((len(dir_blob) + SEC - 1) // SEC) * SEC, b"\x00")
    dir_start = alloc(dir_blob)
    n_fat = 1                                          # FAT sectors describe themselves too
    while (len(sectors) + n_fat) * 4 > n_fat * SEC:
        n_fat += 1
    fat_start = len(sectors)
    fat.extend([0xFFFFFFFD] * n_fat)                   # FATSECT markers
    fat_blob = b"".join(struct.pack("<I", v) for v in fat).ljust(n_fat * SEC, b"\xff")
    for off in range(0, len(fat_blob), SEC):
        sectors.append(fat_blob[off:off + SEC])
    header = bytearray(512)
    header[0:8] = _MAGIC
    struct.pack_into("<HHHHH", header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIII", header, 44, n_fat, dir_start, 0, CUTOFF,
                     minifat_start, n_minifat, _ENDOFCHAIN, 0)
    difat = [fat_start + i for i in range(n_fat)] + [_FREESECT] * (109 - n_fat)
    struct.pack_into("<109I", header, 76, *difat)
    return bytes(header) + b"".join(sectors)
