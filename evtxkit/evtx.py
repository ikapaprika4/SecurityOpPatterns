"""
Native reader for Windows .evtx files (standard library only).

An .evtx file is a 4 KiB header followed by 64 KiB chunks. Each chunk holds
event records; a record is a "binary XML" stream: a template (the event's XML
skeleton, stored once per chunk and shared by every event of that kind) plus
the substitution values for this event. Rendering a record means walking the
template and dropping the values in.

`iter_events()` yields each event as an ElementTree <Event> element shaped
like the XML `wevtutil qe /f:xml` prints -- the same element names, the same
attribute names and, for every value type, the same text -- so the rest of
evtxkit reads a file identically on Windows (wevtutil) and everywhere else
(this module). tests/test_evtxkit.py checks the two against each other on a
live log when run on Windows.

Everything is defensive: a record that cannot be decoded is skipped and
counted, never allowed to abort the file, and the optional `status` dict
says how many were read and how many were skipped.
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta
from typing import Iterator, Optional
from xml.etree import ElementTree as ET

__all__ = ["EvtxError", "iter_events", "is_evtx"]

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = b"\x2a\x2a\x00\x00"
FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512

# Binary XML tokens (the 0x40 bit means "more follows": attributes on an
# element, another attribute, another piece of the same value).
T_EOF, T_OPEN, T_CLOSE_START, T_CLOSE_EMPTY, T_END = 0x00, 0x01, 0x02, 0x03, 0x04
T_VALUE, T_ATTRIBUTE, T_CDATA, T_CHARREF, T_ENTITYREF = 0x05, 0x06, 0x07, 0x08, 0x09
T_PI_TARGET, T_PI_DATA, T_TEMPLATE, T_SUBST, T_OPT_SUBST, T_FRAGMENT = 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F

# Value types.
V_NULL, V_WSTRING, V_ASTRING = 0x00, 0x01, 0x02
V_BOOL, V_BINARY, V_GUID, V_SIZET, V_FILETIME, V_SYSTEMTIME, V_SID = 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13
V_HEX32, V_HEX64, V_BINXML = 0x14, 0x15, 0x21
V_ARRAY = 0x80

_INTS = {0x03: "<b", 0x04: "<B", 0x05: "<h", 0x06: "<H", 0x07: "<i", 0x08: "<I", 0x09: "<q", 0x0A: "<Q"}
_FIXED = {0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8, 0x0A: 8, 0x0B: 4, 0x0C: 8,
          V_BOOL: 4, V_GUID: 16, V_FILETIME: 8, V_SYSTEMTIME: 16, V_HEX32: 4, V_HEX64: 8}
_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}
_EPOCH_1601 = datetime(1601, 1, 1)

_u16 = struct.Struct("<H").unpack_from
_u32 = struct.Struct("<I").unpack_from
_u64 = struct.Struct("<Q").unpack_from


class EvtxError(ValueError):
    """The file is not an .evtx log, or a structure in it is malformed."""


def is_evtx(head: bytes) -> bool:
    return head[:8] == FILE_MAGIC


# --------------------------------------------------------------------------
# Value rendering -- the text wevtutil prints for each type
# --------------------------------------------------------------------------

def _filetime(q: int) -> str:
    secs, ticks = divmod(q, 10_000_000)
    try:
        dt = _EPOCH_1601 + timedelta(seconds=secs)
    except OverflowError:
        return str(q)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{ticks:07d}Z"


def _systemtime(b: bytes) -> str:
    y, mo, _dow, d, h, mi, s, ms = struct.unpack("<8H", b)
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}Z"


def _guid(b: bytes) -> str:
    d1, d2, d3 = struct.unpack("<IHH", b[:8])
    return "{%08x-%04x-%04x-%s-%s}" % (d1, d2, d3, b[8:10].hex(), b[10:16].hex())


def _sid(b: bytes) -> str:
    if len(b) < 8:
        return ""
    count = b[1]
    authority = int.from_bytes(b[2:8], "big")
    subs = struct.unpack_from(f"<{count}I", b, 8) if len(b) >= 8 + 4 * count else ()
    return "S-%d-%d%s" % (b[0], authority, "".join(f"-{s}" for s in subs))


def _text(s: str) -> str:
    """Line ends as an XML parser delivers them (XML 1.0, 2.11: CRLF and a
    lone CR both become LF) -- which is what every XML-based path, wevtutil
    and Event Viewer exports included, hands the detectors."""
    return s.replace("\r\n", "\n").replace("\r", "\n") if "\r" in s else s


def _scalar(vtype: int, b: bytes) -> str:
    """One non-array value as text."""
    if vtype == V_WSTRING:
        return _text(b.decode("utf-16-le", "replace").rstrip("\x00"))
    if vtype == V_ASTRING:
        return _text(b.decode("cp1252", "replace").rstrip("\x00"))
    fmt = _INTS.get(vtype)
    if fmt:
        size = struct.calcsize(fmt)
        return str(struct.unpack(fmt, b[:size])[0]) if len(b) >= size else ""
    if vtype == 0x0B:
        return repr(struct.unpack("<f", b[:4])[0]) if len(b) >= 4 else ""
    if vtype == 0x0C:
        return repr(struct.unpack("<d", b[:8])[0]) if len(b) >= 8 else ""
    if vtype == V_BOOL:
        return "true" if any(b) else "false"
    if vtype == V_BINARY:
        return b.hex().upper()
    if vtype == V_GUID:
        return _guid(b) if len(b) >= 16 else ""
    if vtype in (V_SIZET, V_HEX32, V_HEX64):
        return "0x%x" % int.from_bytes(b, "little")
    if vtype == V_FILETIME:
        return _filetime(_u64(b)[0]) if len(b) >= 8 else ""
    if vtype == V_SYSTEMTIME:
        return _systemtime(b[:16]) if len(b) >= 16 else ""
    if vtype == V_SID:
        return _sid(b)
    return b.hex().upper()


# --------------------------------------------------------------------------
# One chunk
# --------------------------------------------------------------------------

# A parsed template is a tree of plain tuples, built once per chunk:
#   ("E", name, [(attr_name, [piece, ...]), ...], [child-or-piece, ...])
#   ("T", "literal text")
#   ("S", substitution_index, optional)

class _Chunk:
    def __init__(self, data: bytes):
        self.d = data
        self.names: dict[int, tuple[str, int]] = {}        # offset -> (name, size of the name record)
        self.templates: dict[int, tuple[list, int]] = {}   # offset -> (nodes, size of the definition)

    # ---- names -----------------------------------------------------------
    def _name(self, offset: int, p: int) -> tuple[str, int]:
        """The name stored at `offset`. A name is written in place the first
        time it is used (offset == p); later uses only point back at it."""
        hit = self.names.get(offset)
        if hit is None:
            nchars = _u16(self.d, offset + 6)[0]
            raw = self.d[offset + 8: offset + 8 + 2 * nchars]
            hit = (raw.decode("utf-16-le", "replace"), 8 + 2 * nchars + 2)
            self.names[offset] = hit
        return hit[0], (p + hit[1] if offset == p else p)

    # ---- template parsing --------------------------------------------------
    def _pieces(self, p: int) -> tuple[list, int]:
        """The run of value tokens at p: literal text, character and entity
        references, substitutions. Stops at the first token of another kind."""
        d, out = self.d, []
        while True:
            base = d[p] & 0x0F
            if base == T_VALUE:
                vtype = d[p + 1]
                if vtype == V_WSTRING:
                    n = _u16(d, p + 2)[0]
                    out.append(("T", _text(d[p + 4: p + 4 + 2 * n].decode("utf-16-le", "replace"))))
                    p += 4 + 2 * n
                else:
                    size = _FIXED.get(vtype)
                    if size is None:
                        raise EvtxError(f"literal of type 0x{vtype:02x} at {p}")
                    out.append(("T", _scalar(vtype, d[p + 2: p + 2 + size])))
                    p += 2 + size
            elif base in (T_SUBST, T_OPT_SUBST):
                out.append(("S", _u16(d, p + 1)[0], base == T_OPT_SUBST))
                p += 4
            elif base == T_CHARREF:
                out.append(("T", chr(_u16(d, p + 1)[0])))
                p += 3
            elif base == T_ENTITYREF:
                name, p = self._name(_u32(d, p + 1)[0], p + 5)
                out.append(("T", _ENTITIES.get(name, f"&{name};")))
            elif base == T_CDATA:
                n = _u16(d, p + 1)[0]
                out.append(("T", _text(d[p + 3: p + 3 + 2 * n].decode("utf-16-le", "replace"))))
                p += 3 + 2 * n
            else:
                return out, p

    def _element(self, p: int) -> tuple[tuple, int]:
        d = self.d
        has_attributes = bool(d[p] & 0x40)
        name, p = self._name(_u32(d, p + 7)[0], p + 11)     # token, dependency id, size, name offset
        attrs = []
        if has_attributes:
            p += 4                                           # size of the attribute list
            while d[p] & 0x0F == T_ATTRIBUTE:
                more = d[p] & 0x40
                aname, p = self._name(_u32(d, p + 1)[0], p + 5)
                pieces, p = self._pieces(p)
                attrs.append((aname, pieces))
                if not more:
                    break
        tok = d[p]
        if tok == T_CLOSE_EMPTY:
            return ("E", name, attrs, []), p + 1
        if tok != T_CLOSE_START:
            raise EvtxError(f"element <{name}> is not closed (token 0x{tok:02x} at {p})")
        p += 1
        content: list = []
        while True:
            tok = d[p]
            base = tok & 0x0F
            if tok == T_END:
                return ("E", name, attrs, content), p + 1
            if base == T_OPEN:
                child, p = self._element(p)
                content.append(child)
            elif base in (T_VALUE, T_SUBST, T_OPT_SUBST, T_CHARREF, T_ENTITYREF, T_CDATA):
                pieces, p = self._pieces(p)
                content.extend(pieces)
            elif base == T_PI_TARGET:
                _n, p = self._name(_u32(d, p + 1)[0], p + 5)
            elif base == T_PI_DATA:
                p += 3 + 2 * _u16(d, p + 1)[0]
            else:
                raise EvtxError(f"unexpected token 0x{tok:02x} inside <{name}> at {p}")

    def _nodes(self, p: int) -> tuple[list, int]:
        """Top-level nodes of a fragment, up to its end-of-stream token."""
        d, nodes = self.d, []
        while p < len(d):
            tok = d[p]
            if tok == T_EOF:
                return nodes, p + 1
            if tok == T_FRAGMENT:
                p += 4
            elif tok & 0x0F == T_OPEN:
                node, p = self._element(p)
                nodes.append(node)
            else:
                raise EvtxError(f"unexpected token 0x{tok:02x} at {p}")
        return nodes, p

    # ---- rendering -------------------------------------------------------
    def _template_instance(self, p: int) -> tuple[list[ET.Element], int]:
        """A template instance at p (token 0x0C): its definition -- stored
        here the first time the chunk uses it -- then this event's values."""
        d = self.d
        offset = _u32(d, p + 6)[0]
        p += 10
        cached = self.templates.get(offset)
        if cached is None:
            size = _u32(d, offset + 20)[0]                   # next offset, GUID, size, then the body
            nodes, _ = self._nodes(offset + 24)
            cached = self.templates[offset] = (nodes, 24 + size)
        if offset == p:
            p += cached[1]
        count = _u32(d, p)[0]
        p += 4
        if count > 4096:
            raise EvtxError(f"implausible substitution count {count} at {p}")
        table = p
        p += 4 * count
        subs = []
        for i in range(count):
            size = _u16(d, table + 4 * i)[0]
            subs.append((d[table + 4 * i + 2], p, size))
            p += size
        out: list[ET.Element] = []
        for node in cached[0]:
            out.extend(self._build(node, subs))
        return out, p

    def _fragment(self, p: int, end: int) -> list[ET.Element]:
        """Render the binary XML between p and end (a record, or a value of
        type BinXml -- that is how <EventData> is nested into <Event>)."""
        d, out = self.d, []
        while p < end:
            tok = d[p]
            if tok == T_FRAGMENT:
                p += 4
            elif tok == T_TEMPLATE:
                elements, p = self._template_instance(p)
                out.extend(elements)
            elif tok & 0x0F == T_OPEN:
                node, p = self._element(p)
                out.extend(self._build(node, []))
            else:
                break                                        # end of stream, or padding
        return out

    def _value(self, piece: tuple, subs: list):
        """A piece as text, a list of texts (an array), a list of elements
        (nested binary XML) or None (an optional value that is absent)."""
        if piece[0] == "T":
            return piece[1]
        _kind, index, optional = piece
        if index >= len(subs):
            return None if optional else ""
        vtype, offset, size = subs[index]
        if vtype == V_NULL:
            return None if optional else ""
        raw = self.d[offset: offset + size]
        if vtype == V_BINXML:
            return self._fragment(offset, offset + size)
        if vtype & V_ARRAY:
            base = vtype & 0x7F
            if base == V_WSTRING:
                items = _text(raw.decode("utf-16-le", "replace")).split("\x00")
                if items and items[-1] == "":
                    items.pop()                              # the terminator of the last string
                return items
            width = _FIXED.get(base)
            if width:
                return [_scalar(base, raw[i: i + width]) for i in range(0, len(raw) - width + 1, width)]
            return [_scalar(base, raw)]
        return _scalar(vtype, raw)

    def _build(self, node: tuple, subs: list) -> list[ET.Element]:
        _kind, name, attrs, content = node
        el = ET.Element(name)
        for aname, pieces in attrs:
            values = [self._value(piece, subs) for piece in pieces]
            if all(v is None for v in values):
                continue                                     # optional attribute, no value
            el.set(aname, "".join(", ".join(v) if isinstance(v, list) else (v or "")
                                  for v in values if not _is_elements(v)))
        only = None                                          # the value, when it is the whole content
        if len(content) == 1 and content[0][0] == "S":
            only = self._value(content[0], subs)
            if only is None:
                return []                                    # optional element, no value
            if isinstance(only, list) and not _is_elements(only):
                # An array substitution repeats its element once per item.
                copies = []
                for item in only or [""]:
                    copy = ET.Element(name, dict(el.attrib))
                    copy.text = item
                    copies.append(copy)
                return copies
        last = None
        for item in content:
            if item[0] == "E":
                for child in self._build(item, subs):
                    el.append(child)
                    last = child
                continue
            value = only if only is not None else self._value(item, subs)
            if value is None:
                continue
            if _is_elements(value):
                for child in value:
                    el.append(child)
                    last = child
                continue
            text = ", ".join(value) if isinstance(value, list) else value
            if last is None:
                el.text = (el.text or "") + text
            else:
                last.tail = (last.tail or "") + text
        return [el]

    # ---- records ------------------------------------------------------------
    def events(self, status: dict) -> Iterator[ET.Element]:
        d = self.d
        p = CHUNK_HEADER_SIZE
        # The chunk header says where its records end; whatever lies beyond
        # is left over from earlier use of the chunk and must not be read.
        end = _u32(d, 0x30)[0]
        if not CHUNK_HEADER_SIZE <= end <= len(d):
            end = len(d)
        while p + 28 <= end and d[p: p + 4] == RECORD_MAGIC:
            size = _u32(d, p + 4)[0]
            if size < 28 or p + size > end:
                break
            try:
                elements = self._fragment(p + 24, p + size - 4)
                if not elements:
                    raise EvtxError("empty record")
            except (EvtxError, IndexError, struct.error, RecursionError, ValueError):
                status["skipped"] += 1
            else:
                status["records"] += 1
                yield elements[0]
            p += size


def _is_elements(value) -> bool:
    return isinstance(value, list) and bool(value) and isinstance(value[0], ET.Element)


# --------------------------------------------------------------------------
# File
# --------------------------------------------------------------------------

def iter_events(path: str, status: Optional[dict] = None) -> Iterator[ET.Element]:
    """Yield every event in the .evtx file at `path` as an <Event> element.

    Raises EvtxError if the file is not an .evtx log. `status` (optional) is
    filled with `records` and `skipped` -- records that could not be decoded.
    """
    status = status if status is not None else {}
    status.update(records=0, skipped=0, chunks=0)
    with open(path, "rb") as fh:
        header = fh.read(FILE_HEADER_SIZE)
        if not is_evtx(header):
            raise EvtxError(f"{path}: not an .evtx file")
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if len(chunk) < CHUNK_HEADER_SIZE:
                return
            if chunk[:8] != CHUNK_MAGIC:
                continue                                     # an unused (zeroed) chunk
            status["chunks"] += 1
            yield from _Chunk(chunk).events(status)
