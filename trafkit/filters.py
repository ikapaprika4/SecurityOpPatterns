"""
Wireshark-style display filter engine.

Implements the subset of display filter syntax an analyst actually uses day to
day (Wireshark: Packet Operations, task 2-4):

    field references     ip.addr, tcp.flags.syn, http.request.method
    comparisons           == != > < >= <=          (and eq/ne/gt/lt/ge/le)
    logic                 and / or / not            (and &&/||/!)
    membership            tcp.port in {80 443 8080}
    substring              http.server contains "Apache"
    regex                 http.host matches "\\.(php|html)$"
    functions              upper(x), lower(x), string(x)
    bare presence          `tcp`, `http.request`, `arp`

so the same query an analyst would type into Wireshark's filter bar also
works against a PacketRecord.fields dict here -- `parse_filter(expr)` builds
a small AST once, `evaluate(ast, fields)` runs it per packet.
"""

from __future__ import annotations

import re as _re
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union

# --------------------------------------------------------------------------
# Tokenizer
# --------------------------------------------------------------------------

_TOKEN_RE = _re.compile(r"""
    \s*(?:
        (?P<STRING>"(?:[^"\\]|\\.)*")
      | (?P<HEX>0[xX][0-9a-fA-F]+)
      | (?P<IPV4>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)
      | (?P<NUMBER>\d+(?:\.\d+)?)
      | (?P<LBRACE>\{)
      | (?P<RBRACE>\})
      | (?P<COMMA>,)
      | (?P<LPAREN>\()
      | (?P<RPAREN>\))
      | (?P<OP><=|>=|==|!=|<|>)
      | (?P<LOGIC>&&|\|\||!(?!=))
      | (?P<IDENT>[A-Za-z_][A-Za-z0-9_.\-]*)
    )
""", _re.VERBOSE)

_KEYWORD_OPS = {
    "eq": "==", "ne": "!=", "gt": ">", "lt": "<", "ge": ">=", "le": "<=",
}
_LOGICAL_WORDS = {"and", "or", "not", "in", "contains", "matches",
                  "&&", "||", "!"}


class FilterSyntaxError(ValueError):
    pass


@dataclass
class _Tok:
    kind: str
    value: str


def _tokenize(expr: str) -> list[_Tok]:
    toks: list[_Tok] = []
    pos = 0
    n = len(expr)
    while pos < n:
        if expr[pos].isspace():
            pos += 1
            continue
        m = _TOKEN_RE.match(expr, pos)
        if not m or m.end() == pos:
            raise FilterSyntaxError(f"Cannot tokenize filter at position {pos}: {expr[pos:pos+20]!r}")
        kind = m.lastgroup
        val = m.group(kind)
        pos = m.end()
        toks.append(_Tok(kind, val))
    return toks


# --------------------------------------------------------------------------
# AST
# --------------------------------------------------------------------------

class Node:
    def eval(self, fields: dict[str, Any]) -> Any:
        raise NotImplementedError


@dataclass
class Literal(Node):
    value: Any

    def eval(self, fields):
        return self.value


# Wireshark's own "direction-blind" fields: `ip.addr == X` matches X as
# either the source or the destination, same for tcp.port/udp.port/eth.addr.
# pcapread.py stores src/dst separately (that's what direction-aware
# detectors need), so these are resolved as an OR across both underlying
# fields at filter-evaluation time instead of being duplicated into the
# packet dict at extraction time.
_FIELD_ALIASES = {
    "ip.addr": ("ip.src", "ip.dst"),
    "eth.addr": ("eth.src", "eth.dst"),
    "tcp.port": ("tcp.srcport", "tcp.dstport"),
    "udp.port": ("udp.srcport", "udp.dstport"),
}


def _left_values(node: Node, fields: dict[str, Any]) -> list[Any]:
    """Every candidate value `node` could take against this packet -- one
    value normally, two for a direction-blind alias, none if absent."""
    if isinstance(node, FieldRef) and node.name in _FIELD_ALIASES:
        return [fields[k] for k in _FIELD_ALIASES[node.name] if k in fields]
    v = node.eval(fields)
    return [] if v is None else [v]


@dataclass
class FieldRef(Node):
    name: str

    def eval(self, fields):
        return fields.get(self.name)


@dataclass
class Presence(Node):
    name: str

    def eval(self, fields):
        if self.name in _FIELD_ALIASES:
            return any(k in fields for k in _FIELD_ALIASES[self.name])
        if self.name in fields:
            return True
        p = self.name + "."
        return any(k.startswith(p) for k in fields)


@dataclass
class FuncCall(Node):
    fname: str
    arg: Node

    def eval(self, fields):
        v = self.arg.eval(fields)
        s = "" if v is None else str(v)
        if self.fname == "upper":
            return s.upper()
        if self.fname == "lower":
            return s.lower()
        if self.fname == "string":
            return s
        raise FilterSyntaxError(f"Unknown function {self.fname}()")


@dataclass
class Compare(Node):
    op: str
    left: Node
    right: Node

    def eval(self, fields):
        rv = self.right.eval(fields)
        values = _left_values(self.left, fields)
        if not values:
            return False
        return any(self._one(lv, rv) for lv in values)

    def _one(self, lv, rv) -> bool:
        # `ip.addr == 10.10.10.0/24` -- subnet membership, not string equality.
        if self.op in ("==", "!=") and isinstance(rv, str) and "/" in rv:
            member = _ip_in_subnet(lv, rv)
            if member is not None:
                return member if self.op == "==" else not member
        # Numeric compare if both sides look numeric, else string compare.
        ln, rn = _coerce_num(lv), _coerce_num(rv)
        a, b = (ln, rn) if ln is not None and rn is not None else (lv, rv)
        try:
            if self.op == "==":
                return a == b
            if self.op == "!=":
                return a != b
            if self.op == ">":
                return a > b
            if self.op == "<":
                return a < b
            if self.op == ">=":
                return a >= b
            if self.op == "<=":
                return a <= b
        except TypeError:
            return False
        raise FilterSyntaxError(f"Unknown operator {self.op}")


@dataclass
class Contains(Node):
    left: Node
    right: Node
    negate: bool = False

    def eval(self, fields):
        rv = self.right.eval(fields)
        values = _left_values(self.left, fields)
        if not values:
            return False ^ self.negate
        result = any(str(rv) in str(lv) for lv in values)
        return result ^ self.negate


@dataclass
class Matches(Node):
    left: Node
    pattern: str

    def eval(self, fields):
        values = _left_values(self.left, fields)
        if not values:
            return False
        try:
            return any(bool(_re.search(self.pattern, str(lv), _re.IGNORECASE)) for lv in values)
        except _re.error as e:
            raise FilterSyntaxError(f"Bad regex in filter: {e}")


@dataclass
class InSet(Node):
    left: Node
    values: list[Node]

    def eval(self, fields):
        left_values = _left_values(self.left, fields)
        if not left_values:
            return False
        for lv in left_values:
            lv_num = _coerce_num(lv)
            for v in self.values:
                rv = v.eval(fields)
                rn = _coerce_num(rv)
                if lv_num is not None and rn is not None:
                    if lv_num == rn:
                        return True
                elif str(lv) == str(rv):
                    return True
        return False


@dataclass
class And(Node):
    left: Node
    right: Node

    def eval(self, fields):
        return bool(self.left.eval(fields)) and bool(self.right.eval(fields))


@dataclass
class Or(Node):
    left: Node
    right: Node

    def eval(self, fields):
        return bool(self.left.eval(fields)) or bool(self.right.eval(fields))


@dataclass
class Not(Node):
    inner: Node

    def eval(self, fields):
        return not bool(self.inner.eval(fields))


def _ip_in_subnet(addr: Any, cidr: str) -> Optional[bool]:
    try:
        import ipaddress
        return ipaddress.ip_address(str(addr)) in ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return None


def _coerce_num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        try:
            if s.lower().startswith("0x"):
                return float(int(s, 16))
            return float(s)
        except ValueError:
            return None
    return None


# --------------------------------------------------------------------------
# Recursive-descent parser
#   expr    := or_expr
#   or_expr := and_expr (("or"|"||") and_expr)*
#   and_expr:= not_expr (("and"|"&&") not_expr)*
#   not_expr:= ("not"|"!") not_expr | primary
#   primary := "(" expr ")" | comparison | presence
#   comparison := value (OP|"in"|"contains"|"matches") value_or_set
#   value   := literal | funccall | fieldref
# --------------------------------------------------------------------------

class _Parser:
    def __init__(self, toks: list[_Tok]):
        self.toks = toks
        self.i = 0

    def _peek(self) -> Optional[_Tok]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self) -> _Tok:
        t = self._peek()
        if t is None:
            raise FilterSyntaxError("Unexpected end of filter expression")
        self.i += 1
        return t

    def _expect_ident(self, word: str) -> bool:
        t = self._peek()
        return t is not None and t.kind == "IDENT" and t.value.lower() == word

    def parse(self) -> Node:
        node = self._or_expr()
        if self._peek() is not None:
            raise FilterSyntaxError(f"Unexpected token {self._peek().value!r}")
        return node

    def _or_expr(self) -> Node:
        node = self._and_expr()
        while self._peek() and (self._expect_ident("or") or self._peek().value == "||"):
            self._next()
            node = Or(node, self._and_expr())
        return node

    def _and_expr(self) -> Node:
        node = self._not_expr()
        while self._peek() and (self._expect_ident("and") or self._peek().value == "&&"):
            self._next()
            node = And(node, self._not_expr())
        return node

    def _not_expr(self) -> Node:
        if self._peek() and (self._expect_ident("not") or self._peek().value == "!"):
            self._next()
            return Not(self._not_expr())
        return self._primary()

    def _primary(self) -> Node:
        t = self._peek()
        if t is None:
            raise FilterSyntaxError("Unexpected end of filter expression")
        if t.kind == "LPAREN":
            self._next()
            node = self._or_expr()
            if not self._peek() or self._peek().kind != "RPAREN":
                raise FilterSyntaxError("Missing closing parenthesis")
            self._next()
            return node
        return self._comparison()

    def _comparison(self) -> Node:
        left = self._value()
        t = self._peek()
        if t is None:
            return self._as_presence(left)

        if t.kind == "OP":
            self._next()
            right = self._value()
            return Compare(t.value, left, right)

        if t.kind == "IDENT" and t.value.lower() in _KEYWORD_OPS:
            self._next()
            right = self._value()
            return Compare(_KEYWORD_OPS[t.value.lower()], left, right)

        if t.kind == "IDENT" and t.value.lower() == "contains":
            self._next()
            right = self._value()
            return Contains(left, right)

        if t.kind == "IDENT" and t.value.lower() == "matches":
            self._next()
            right = self._value()
            pattern = right.value if isinstance(right, Literal) else None
            if pattern is None:
                raise FilterSyntaxError("matches requires a string pattern")
            return Matches(left, pattern)

        if t.kind == "IDENT" and t.value.lower() == "in":
            self._next()
            return InSet(left, self._set_literal())

        return self._as_presence(left)

    def _as_presence(self, left: Node) -> Node:
        if isinstance(left, FieldRef):
            return Presence(left.name)
        return left

    def _set_literal(self) -> list[Node]:
        t = self._next()
        if t.kind != "LBRACE":
            raise FilterSyntaxError("Expected '{' to start a set literal")
        values: list[Node] = []
        while True:
            t = self._peek()
            if t is None:
                raise FilterSyntaxError("Unterminated set literal")
            if t.kind == "RBRACE":
                self._next()
                break
            values.append(self._value())
            if self._peek() and self._peek().kind == "COMMA":
                self._next()
        return values

    def _value(self) -> Node:
        t = self._next()
        if t.kind == "STRING":
            return Literal(t.value[1:-1].replace('\\"', '"'))
        if t.kind == "IPV4":
            return Literal(t.value)
        if t.kind == "HEX":
            return Literal(int(t.value, 16))
        if t.kind == "NUMBER":
            return Literal(float(t.value) if "." in t.value else int(t.value))
        if t.kind == "IDENT":
            low = t.value.lower()
            if low in ("upper", "lower", "string") and self._peek() and self._peek().kind == "LPAREN":
                self._next()  # (
                arg = self._value()
                if not self._peek() or self._peek().kind != "RPAREN":
                    raise FilterSyntaxError(f"Missing ')' after {low}(...)")
                self._next()
                return FuncCall(low, arg)
            return FieldRef(t.value)
        raise FilterSyntaxError(f"Unexpected token {t.value!r}")


def parse_filter(expr: str) -> Node:
    expr = expr.strip()
    if not expr:
        raise FilterSyntaxError("Empty filter expression")
    toks = _tokenize(expr)
    return _Parser(toks).parse()


def evaluate(node: Node, fields: dict[str, Any]) -> bool:
    try:
        return bool(node.eval(fields))
    except FilterSyntaxError:
        raise
    except Exception:
        # A field that doesn't apply to this packet type (e.g. http.host on a
        # UDP/DNS packet) should just fail the filter, not crash the run --
        # exactly how Wireshark's own display filters degrade.
        return False


def apply_filter(expr: str, packets: list) -> list:
    """Filter a list of PacketRecord by a display-filter expression string."""
    node = parse_filter(expr)
    return [p for p in packets if evaluate(node, p.fields)]
