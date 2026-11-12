#!/usr/bin/env python3
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Reference checker for VKR-L3 v0.2 (docs/specs/0003-plan.md).

Four operations, matching the vector operations of the same name:

    expr_eval(env, source)                       section 3
    plan_verify(plan, catalog, policy, ...)      sections 4 and 5
    plan_flows(plan, catalog, ...)               section 5, labels and flow list
    plan_run(plan, catalog, inputs, script, ...) section 6

Standard library only. This file is written for reading next to the specification,
not for speed. Rule ids in comments (W-REF, L-CALL, P3, H3, E8 ...) are the ids in
the specification.
"""
from __future__ import annotations

import json

I64_MAX = 2**63 - 1
I64_MIN = -(2**63)
DEC_SCALE = 10**6          # six fractional digits
DEC_LIMIT = 10**24         # 18 integer digits, scaled
EFFECTS = ["compute", "read", "write", "delete", "execute", "egress"]
T, U = "trusted", "untrusted"
MAX_DEPTH, MAX_TOKENS, MAX_EXPR_BYTES, MAX_STRING_BYTES = 16, 256, 1024, 4096


class Problem(Exception):
    """One verifier problem: a code, and optionally a step and a parameter."""

    def __init__(self, code, step=None, param=None):
        super().__init__(code)
        self.code, self.step, self.param = code, step, param


# --------------------------------------------------------------------------- classes, labels


def covers(a: str, b: str) -> bool:
    """5.1: class a covers a itself and every a.* below it."""
    return a == b or b.startswith(a + ".")


def norm(classes) -> frozenset:
    """Normal form: no member covered by another member."""
    cs = set(classes)
    return frozenset(c for c in cs if not any(d != c and covers(d, c) for d in cs))


def is_secret(c: str) -> bool:
    return covers("secrets", c)


def label(classes=(), integ=T):
    return (norm(classes), integ)


BOT = label()


def join(*labels):
    cs, integ = set(), T
    for c, i in labels:
        cs |= c
        integ = U if U in (integ, i) else T
    return (norm(cs), integ)


def leq(a, b) -> bool:
    return all(any(covers(d, c) for d in b[0]) for c in a[0]) and (a[1] == T or b[1] == U)


def has_secret(lbl) -> bool:
    return any(is_secret(c) for c in lbl[0])


def label_json(lbl):
    return {"classes": sorted(lbl[0]), "integrity": lbl[1]}


def label_from_json(obj):
    return label(obj.get("classes", []), obj.get("integrity", U))


# --------------------------------------------------------------------------- types (section 2)

SCALARS = ("bool", "int", "decimal", "string", "enum")


def type_from_schema(s):
    """2.3. Raises Problem('T-SCHEMA') for anything outside the subset."""
    if not isinstance(s, dict):
        raise Problem("T-SCHEMA")
    keys = set(s)
    if "enum" in s:
        if keys != {"enum"} or not s["enum"] or not all(isinstance(x, str) for x in s["enum"]):
            raise Problem("T-SCHEMA")
        return ("enum", frozenset(s["enum"]))
    t = s.get("type")
    if t == "boolean" and keys == {"type"}:
        return ("bool",)
    if t == "integer" and keys <= {"type", "minimum", "maximum"}:
        return ("int",)
    if t == "string" and s.get("format") == "decimal" and keys == {"type", "format"}:
        return ("decimal",)
    if t == "string" and keys <= {"type", "maxLength"}:
        return ("string",)
    if t == "array" and keys == {"type", "items", "maxItems"}:
        n = s["maxItems"]
        if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 1024:
            raise Problem("T-SCHEMA")
        return ("list", type_from_schema(s["items"]), n)
    if t == "object" and keys <= {"type", "properties", "required", "additionalProperties"}:
        if s.get("additionalProperties") is not False:
            raise Problem("T-SCHEMA")
        props, req = s.get("properties", {}), s.get("required", [])
        if not set(req) <= set(props):
            raise Problem("T-SCHEMA")
        return ("record", {k: (type_from_schema(v), k in req) for k, v in props.items()})
    if t == "blob" and keys == {"type", "media"} and isinstance(s["media"], str):
        return ("blob", s["media"])
    raise Problem("T-SCHEMA")


def type_str(t) -> str:
    k = t[0]
    if k == "enum":
        return "enum{" + ", ".join(json.dumps(x) for x in sorted(t[1])) + "}"
    if k == "list":
        return f"list<{type_str(t[1])}>[{t[2]}]"
    if k == "record":
        return "record{" + ", ".join(
            f"{n}{'' if req else '?'}: {type_str(ft)}" for n, (ft, req) in sorted(t[1].items())) + "}"
    if k == "blob":
        return f"blob<{t[1]}>"
    return k


def subtype(a, b) -> bool:
    """2.4, S1 to S6."""
    if a == b:
        return True
    if a[0] == "enum" and b[0] == "string":
        return True
    if a[0] == "enum" and b[0] == "enum":
        return a[1] <= b[1]
    if a[0] == "list" and b[0] == "list":
        return subtype(a[1], b[1]) and a[2] <= b[2]
    if a[0] == "record" and b[0] == "record":
        for name, (bt, breq) in b[1].items():
            if name not in a[1]:
                if breq:
                    return False
                continue
            at, areq = a[1][name]
            if (breq and not areq) or not subtype(at, bt):
                return False
        return True
    if a[0] == "blob" and b[0] == "blob":
        return b[1] == "*" or a[1] == b[1]
    return False


def stringy(t) -> bool:
    return t[0] in ("string", "enum")


def compatible(a, b) -> bool:
    """Operands of ==, != and in: the same scalar type; enum and string mix."""
    return a[0] in SCALARS and b[0] in SCALARS and (a == b or (stringy(a) and stringy(b)))


def parse_decimal(s):
    """2.2. Returns the value scaled by 10^6, or None."""
    if not isinstance(s, str):
        return None
    body = s[1:] if s.startswith("-") else s
    whole, _, frac = body.partition(".")
    if "." in body and not (1 <= len(frac) <= 6 and frac.isascii() and frac.isdigit()):
        return None
    if not (whole.isascii() and whole.isdigit()) or len(whole) > 18 or (len(whole) > 1 and whole[0] == "0"):
        return None
    n = int(whole) * DEC_SCALE + int((frac + "000000")[:6] if frac else 0)
    return -n if s.startswith("-") else n


def render_decimal(n: int) -> str:
    """Canonical form: no trailing fractional zeros, no negative zero."""
    sign, n = ("-", -n) if n < 0 else ("", n)
    whole, frac = divmod(n, DEC_SCALE)
    text = str(whole) + ("." + f"{frac:06d}".rstrip("0") if frac else "")
    return sign + text


class Dec:
    """A decimal value inside the evaluator."""

    __slots__ = ("n",)

    def __init__(self, n):
        self.n = n

    def __eq__(self, other):
        return isinstance(other, Dec) and self.n == other.n

    def __hash__(self):
        return hash(("dec", self.n))


def conforms(v, schema) -> bool:
    """Run-time check of a JSON value against a schema of 2.3 (E5, E7)."""
    try:
        t = type_from_schema(schema)
    except Problem:
        return False
    k = t[0]
    if k == "bool":
        return isinstance(v, bool)
    if k == "int":
        return (isinstance(v, int) and not isinstance(v, bool) and I64_MIN <= v <= I64_MAX
                and schema.get("minimum", v) <= v <= schema.get("maximum", v))
    if k == "decimal":
        return parse_decimal(v) is not None
    if k == "string":
        return isinstance(v, str) and len(v) <= schema.get("maxLength", len(v))
    if k == "enum":
        return isinstance(v, str) and v in t[1]
    if k == "list":
        return isinstance(v, list) and len(v) <= t[2] and all(conforms(x, schema["items"]) for x in v)
    if k == "record":
        if not isinstance(v, dict) or not set(v) <= set(t[1]):
            return False
        return all((name in v and conforms(v[name], schema["properties"][name])) or (name not in v and not req)
                   for name, (_, req) in t[1].items())
    if k == "blob":
        return (isinstance(v, dict) and set(v) == {"digest", "media", "size"}
                and isinstance(v["digest"], str) and v["digest"].startswith("sha256:")
                and isinstance(v["size"], int) and (t[1] == "*" or v["media"] == t[1]))
    return False


def internal(v, t):
    """JSON value to evaluator value: decimals become Dec."""
    if t[0] == "decimal":
        return Dec(parse_decimal(v))
    if t[0] == "list":
        return [internal(x, t[1]) for x in v]
    if t[0] == "record":
        return {k: internal(x, t[1][k][0]) for k, x in v.items()}
    return v


def external(v):
    if isinstance(v, Dec):
        return render_decimal(v.n)
    if isinstance(v, list):
        return [external(x) for x in v]
    if isinstance(v, dict):
        return {k: external(x) for k, x in v.items()}
    return v


# --------------------------------------------------------------------------- expressions (section 3)

OPS = ["||", "&&", "==", "!=", "<=", ">=", "<", ">", "+", "-", "*", "/", "%", "!", "?", ":", ".", ",",
       "(", ")", "[", "]"]


def tokenize(src: str):
    if len(src.encode("utf-8")) > MAX_EXPR_BYTES:
        raise Problem("W-PARSE")
    out, i = [], 0
    while i < len(src):
        ch = src[i]
        if ch in " \t\n":
            i += 1
        elif ch.isascii() and ch.isdigit():
            j = i
            while j < len(src) and src[j].isascii() and src[j].isdigit():
                j += 1
            if int(src[i:j]) > I64_MAX:
                raise Problem("W-PARSE")
            out.append(("int", int(src[i:j])))
            i = j
        elif ch.isascii() and (ch.isalpha() or ch == "_"):
            j = i
            while j < len(src) and src[j].isascii() and (src[j].isalnum() or src[j] == "_"):
                j += 1
            out.append(("ident", src[i:j]))
            i = j
        elif ch == '"':
            j, buf = i + 1, []
            while True:
                if j >= len(src):
                    raise Problem("W-PARSE")
                c = src[j]
                if c == '"':
                    break
                if c == "\\":
                    e = src[j + 1:j + 2]
                    if e in ('"', "\\"):
                        buf.append(e)
                        j += 2
                    elif e == "n":
                        buf.append("\n")
                        j += 2
                    elif e == "t":
                        buf.append("\t")
                        j += 2
                    elif e == "u":
                        hx = src[j + 2:j + 6]
                        if len(hx) != 4 or any(h not in "0123456789abcdefABCDEF" for h in hx):
                            raise Problem("W-PARSE")
                        buf.append(chr(int(hx, 16)))
                        j += 6
                    else:
                        raise Problem("W-PARSE")
                elif c == "\n":
                    raise Problem("W-PARSE")
                else:
                    buf.append(c)
                    j += 1
            out.append(("str", "".join(buf)))
            i = j + 1
        else:
            for op in OPS:
                if src.startswith(op, i):
                    out.append(("op", op))
                    i += len(op)
                    break
            else:
                raise Problem("W-PARSE")
    if not out or len(out) > MAX_TOKENS:
        raise Problem("W-PARSE")
    return out


class Parser:
    """Recursive descent over the grammar of 3.1. `depth` counts open brackets, argument
    lists and ternary branches; chains of one precedence level are loops, not recursion."""

    def __init__(self, tokens):
        self.t, self.i, self.depth = tokens, 0, 0

    def peek(self, kind=None, value=None):
        if self.i >= len(self.t):
            return False
        k, v = self.t[self.i]
        return (kind is None or k == kind) and (value is None or v == value)

    def op(self, *values):
        if self.i < len(self.t) and self.t[self.i][0] == "op" and self.t[self.i][1] in values:
            self.i += 1
            return self.t[self.i - 1][1]
        return None

    def need(self, value):
        if not self.op(value):
            raise Problem("W-PARSE")

    def nested(self, fn):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise Problem("W-PARSE")
        try:
            return fn()
        finally:
            self.depth -= 1

    def expr(self):
        c = self.chain(0)
        if self.op("?"):
            a = self.nested(self.expr)
            self.need(":")
            b = self.nested(self.expr)
            return ("tern", c, a, b)
        return c

    LEVELS = [("||",), ("&&",), None, ("+", "-"), ("*", "/", "%")]

    def chain(self, level):
        if level == 2:
            a = self.chain(3)
            if self.peek("ident", "in"):
                self.i += 1
                return ("cmp", "in", a, self.chain(3))
            o = self.op("==", "!=", "<=", ">=", "<", ">")
            if o:
                b = self.chain(3)
                if self.peek("ident", "in") or (self.peek("op") and self.t[self.i][1] in
                                                 ("==", "!=", "<=", ">=", "<", ">")):
                    raise Problem("W-PARSE")       # comparisons do not chain
                return ("cmp", o, a, b)
            return a
        if level == 5:
            return self.unary()
        first, rest = self.chain(level + 1), []
        while True:
            o = self.op(*self.LEVELS[level])
            if not o:
                break
            rest.append((o, self.chain(level + 1)))
        return ("chain", first, rest) if rest else first

    def unary(self):
        ops = []
        while True:
            o = self.op("!", "-")
            if not o:
                break
            ops.append(o)
        e = self.postfix()
        return ("unary", ops, e) if ops else e

    def args(self, close):
        out = []
        if self.op(close):
            return out
        while True:
            out.append(self.expr())
            if self.op(close):
                return out
            self.need(",")

    def postfix(self):
        base, suffixes = self.primary(), []
        while True:
            if self.op("."):
                if not self.peek("ident"):
                    raise Problem("W-PARSE")
                name = self.t[self.i][1]
                self.i += 1
                if self.op("("):
                    suffixes.append(("method", name, self.nested(lambda: self.args(")"))))
                else:
                    suffixes.append(("field", name))
            elif self.op("["):
                def index():
                    e = self.expr()
                    self.need("]")
                    return e
                suffixes.append(("index", self.nested(index)))
            else:
                break
        return ("post", base, suffixes) if suffixes else base

    def primary(self):
        if self.i >= len(self.t):
            raise Problem("W-PARSE")
        k, v = self.t[self.i]
        self.i += 1
        if k == "int":
            return ("int", v)
        if k == "str":
            return ("str", v)
        if k == "ident":
            if v in ("true", "false"):
                return ("bool", v == "true")
            if v == "in":
                raise Problem("W-PARSE")
            if self.op("("):
                return ("call", v, self.nested(lambda: self.args(")")))
            return ("name", v)
        if (k, v) == ("op", "("):
            def inner():
                e = self.expr()
                self.need(")")
                return e
            return self.nested(inner)
        if (k, v) == ("op", "["):
            return ("list", self.nested(lambda: self.args("]")))
        raise Problem("W-PARSE")


def parse(src: str):
    p = Parser(tokenize(src))
    ast = p.expr()
    if p.i != len(p.t):
        raise Problem("W-PARSE")
    return ast


BOOL, INT, DEC, STR = ("bool",), ("int",), ("decimal",), ("string",)


class Typer:
    """3.3 and 3.4. `env` maps a name to (type, kind); kind is 'input' or a step kind.
    Collects `refs`: (name, first field or None, inside done())."""

    def __init__(self, env):
        self.env, self.refs = env, set()

    def fail(self):
        raise Problem("T-EXPR")

    def check(self, e, in_done=False):
        k = e[0]
        if k == "bool":
            return BOOL
        if k == "int":
            return INT
        if k == "str":
            return STR
        if k == "name":
            return self.name(e[1], None, in_done)
        if k == "list":
            ts = [self.check(x) for x in e[1]]
            if not ts or ts[0][0] not in SCALARS or any(t != ts[0] for t in ts):
                self.fail()
            return ("list", ts[0], len(ts))
        if k == "unary":
            t = self.check(e[2])
            for o in reversed(e[1]):
                if (o == "!" and t != BOOL) or (o == "-" and t not in (INT, DEC)):
                    self.fail()
            return t
        if k == "tern":
            if self.check(e[1]) != BOOL:
                self.fail()
            a, b = self.check(e[2]), self.check(e[3])
            if subtype(a, b):
                return b
            if subtype(b, a):
                return a
            self.fail()
        if k == "cmp":
            a, b = self.check(e[2]), self.check(e[3])
            if e[1] == "in":
                if b[0] != "list" or not compatible(a, b[1]):
                    self.fail()
            elif e[1] in ("==", "!="):
                if not compatible(a, b):
                    self.fail()
            elif not ((a == b and a in (INT, DEC)) or (stringy(a) and stringy(b))):
                self.fail()
            return BOOL
        if k == "chain":
            t = self.check(e[1])
            for o, x in e[2]:
                u = self.check(x)
                if o in ("||", "&&"):
                    ok = t == BOOL and u == BOOL
                elif o == "+":
                    ok = (t == u and t in (INT, DEC)) or (stringy(t) and stringy(u))
                    t = STR if stringy(t) else t
                elif o == "-":
                    ok = t == u and t in (INT, DEC)
                else:
                    ok = t == INT and u == INT
                if not ok:
                    self.fail()
            return t
        if k == "call":
            return self.call(e[1], e[2])
        if k == "post":
            return self.post(e, in_done)
        self.fail()

    def name(self, n, first_field, in_done):
        if n not in self.env:
            raise Problem("W-REF")
        t, kind = self.env[n]
        if kind == "view":
            raise Problem("W-REF")
        self.refs.add((n, first_field, in_done))
        return t

    def post(self, e, in_done=False, for_has=False):
        base, suffixes = e[1], e[2]
        first = suffixes[0][1] if suffixes[0][0] == "field" else None
        t = self.name(base[1], first, in_done) if base[0] == "name" else self.check(base)
        optional_last = False
        for s in suffixes:
            optional_last = False
            if s[0] == "field":
                if t[0] == "record" and s[1] in t[1]:
                    t, req = t[1][s[1]]
                    optional_last = not req
                elif t[0] == "blob" and s[1] in ("size", "media"):
                    t = INT if s[1] == "size" else STR
                else:
                    self.fail()
            elif s[0] == "index":
                if t[0] != "list" or self.check(s[1]) != INT:
                    self.fail()
                t = t[1]
            else:
                if s[1] not in ("startsWith", "endsWith", "contains") or not stringy(t) or len(s[2]) != 1 \
                        or not stringy(self.check(s[2][0])):
                    self.fail()
                t = BOOL
        if for_has and not optional_last:
            self.fail()
        return t

    def call(self, f, args):
        if f == "done":
            if len(args) != 1 or args[0][0] != "name":
                self.fail()
            n = args[0][1]
            if n not in self.env:
                raise Problem("W-REF")
            if self.env[n][1] == "input":
                self.fail()
            self.refs.add((n, None, True))
            return BOOL
        if f == "has":
            if len(args) != 1 or args[0][0] != "post":
                self.fail()
            self.post(args[0], for_has=True)
            return BOOL
        if f == "dec":
            if len(args) != 1 or args[0][0] != "str" or parse_decimal(args[0][1]) is None:
                self.fail()
            return DEC
        if f == "size":
            if len(args) != 1:
                self.fail()
            t = self.check(args[0])
            if not (stringy(t) or t[0] == "list"):
                self.fail()
            return INT
        if f == "sum":
            if len(args) != 1:
                self.fail()
            t = self.check(args[0])
            if t[0] != "list" or t[1] not in (INT, DEC):
                self.fail()
            return t[1]
        self.fail()


class Undefined(Exception):
    pass


def _int(n):
    if not I64_MIN <= n <= I64_MAX:
        raise Undefined()
    return n


def _dec(n):
    if abs(n) >= DEC_LIMIT:
        raise Undefined()
    return Dec(n)


def _key(v):
    return v.n if isinstance(v, Dec) else v


def evaluate(e, values, completed):
    """3.5. `values` holds evaluator values of inputs and completed steps; `completed`
    is the set of completed step ids. Raises Undefined (V1, V2)."""
    k = e[0]
    if k in ("bool", "int", "str"):
        return e[1]
    if k == "name":
        if e[1] not in values:
            raise Undefined()
        return values[e[1]]
    if k == "list":
        return [evaluate(x, values, completed) for x in e[1]]
    if k == "unary":
        v = evaluate(e[2], values, completed)
        for o in reversed(e[1]):
            if o == "!":
                v = not v
            else:
                v = _dec(-v.n) if isinstance(v, Dec) else _int(-v)
        return v
    if k == "tern":                                              # V4
        c = evaluate(e[1], values, completed)
        return evaluate(e[2] if c else e[3], values, completed)
    if k == "cmp":
        a, b = evaluate(e[2], values, completed), evaluate(e[3], values, completed)
        o = e[1]
        if o == "in":
            return any(_key(a) == _key(x) for x in b)
        a, b = _key(a), _key(b)
        return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[o]
    if k == "chain":
        v = evaluate(e[1], values, completed)
        for o, x in e[2]:
            if o == "&&":                                         # V3
                if v is False:
                    return False
                v = evaluate(x, values, completed)
                continue
            if o == "||":
                if v is True:
                    return True
                v = evaluate(x, values, completed)
                continue
            w = evaluate(x, values, completed)
            if isinstance(v, str):
                v = v + w
                if len(v.encode("utf-8")) > MAX_STRING_BYTES:
                    raise Undefined()
            elif isinstance(v, Dec):
                v = _dec(v.n + w.n if o == "+" else v.n - w.n)
            elif o == "+":
                v = _int(v + w)
            elif o == "-":
                v = _int(v - w)
            elif o == "*":
                v = _int(v * w)
            else:                                                 # V6
                if w == 0:
                    raise Undefined()
                q = abs(v) // abs(w)
                q = _int(q if (v >= 0) == (w >= 0) else -q)   # i64::MIN / -1 and % -1 are undefined
                v = q if o == "/" else _int(v - q * w)
        return v
    if k == "call":
        f, args = e[1], e[2]
        if f == "done":                                           # V5
            return args[0][1] in completed
        if f == "has":                                            # V5
            post = args[0]
            holder = evaluate(("post", post[1], post[2][:-1]) if len(post[2]) > 1 else post[1], values, completed)
            return post[2][-1][1] in holder
        if f == "dec":
            return Dec(parse_decimal(args[0][1]))
        v = evaluate(args[0], values, completed)
        if f == "size":
            return len(v)
        if all(isinstance(x, Dec) for x in v) and v:
            return _dec(sum(x.n for x in v))
        return _int(sum(v)) if v else 0
    if k == "post":
        v = evaluate(e[1], values, completed)
        for s in e[2]:
            if s[0] == "field":
                if s[1] not in v:
                    raise Undefined()
                v = v[s[1]]
            elif s[0] == "index":
                i = evaluate(s[1], values, completed)
                if not 0 <= i < len(v):
                    raise Undefined()
                v = v[i]
            else:
                a = evaluate(s[2][0], values, completed)
                v = {"startsWith": v.startswith(a), "endsWith": v.endswith(a), "contains": a in v}[s[1]]
        return v
    raise AssertionError(k)


def _sum_zero(t):
    return Dec(0) if t == DEC else 0


def expr_eval(env: dict, source: str) -> dict:
    """Operation `expr-eval`. env: name -> {"type": schema, "value": json} for an input or a
    completed step, or {"type": schema, "step": true, "completed": false} for a step that
    did not complete. A completed step may say "step": true so that done() accepts it."""
    try:
        ast = parse(source)
        tenv = {n: (type_from_schema(d["type"]), "call" if d.get("step") else "input") for n, d in env.items()}
        typer = Typer(tenv)
        t = typer.check(ast)
    except Problem as p:
        return {"error": p.code}
    values = {n: internal(d["value"], tenv[n][0]) for n, d in env.items() if "value" in d}
    completed = {n for n, d in env.items() if d.get("step") and d.get("completed", "value" in d)}
    try:
        v = evaluate(ast, values, completed)
    except Undefined:
        return {"type": type_str(t), "undefined": True}
    if v == 0 and t == DEC and not isinstance(v, Dec):
        v = Dec(0)
    return {"type": type_str(t), "value": external(v)}


# --------------------------------------------------------------------------- the plan document

NAME_OK = set("abcdefghijklmnopqrstuvwxyz0123456789_")
KINDS = {
    "call": ({"capability", "args"}, {"approval", "retry", "timeout_s", "when", "on_refuse"}),
    "map": ({"capability", "args", "over", "bound"}, {"approval", "parallel", "retry", "timeout_s", "when", "on_refuse"}),
    "expr": ({"expr"}, {"on_refuse"}),
    "ask": ({"prompt"}, {"options", "show", "timeout_s", "when", "on_refuse"}),
    "declassify": ({"value", "drop", "endorse"}, {"timeout_s", "when", "on_refuse"}),
    "view": ({"component", "bind"}, {"when"}),
}


def is_name(s) -> bool:
    return isinstance(s, str) and 1 <= len(s) <= 32 and s[0].isalpha() and s[0].islower() and set(s) <= NAME_OK


def is_int(v, lo, hi) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def lit_ok(v) -> bool:
    if isinstance(v, bool) or isinstance(v, str):
        return True
    if isinstance(v, int):
        return I64_MIN <= v <= I64_MAX
    if isinstance(v, list):
        return all(lit_ok(x) for x in v)
    if isinstance(v, dict):
        return all(lit_ok(x) for x in v.values())
    return False                                   # null, fractional numbers


def lit_fits(v, t) -> bool:
    """A literal is checked against the type it is used at (T-ARGS)."""
    k = t[0]
    if k == "bool":
        return isinstance(v, bool)
    if k == "int":
        return isinstance(v, int) and not isinstance(v, bool)
    if k == "decimal":
        return parse_decimal(v) is not None
    if k == "string":
        return isinstance(v, str)
    if k == "enum":
        return isinstance(v, str) and v in t[1]
    if k == "list":
        return isinstance(v, list) and len(v) <= t[2] and all(lit_fits(x, t[1]) for x in v)
    if k == "record":
        return (isinstance(v, dict) and set(v) <= set(t[1])
                and all(n in v or not req for n, (_, req) in t[1].items())
                and all(lit_fits(x, t[1][n][0]) for n, x in v.items()))
    return False


def arg_form(a) -> str | None:
    """1.4: 'lit', 'ref' or 'item', or None if malformed."""
    if not isinstance(a, dict):
        return None
    keys = set(a)
    path_ok = "field" not in a or (isinstance(a["field"], str) and a["field"]
                                   and all(p and p.replace("_", "a").isalnum() and p.isascii()
                                           for p in a["field"].split(".")))
    if keys == {"lit"}:
        return "lit" if lit_ok(a["lit"]) and len(json.dumps(a["lit"], separators=(",", ":"))) <= 4096 else None
    if keys in ({"ref"}, {"ref", "field"}) and is_name(a["ref"]) and path_ok:
        return "ref"
    if keys in ({"item"}, {"item", "field"}) and a["item"] is True and path_ok:
        return "item"
    return None


def well_formed(plan, caps, prompts, views):
    """4.1. Returns a list of Problems."""
    out = []
    if not isinstance(plan, dict) or not set(plan) <= {"v", "goal", "inputs", "budget", "steps", "result"} \
            or "steps" not in plan or len(json.dumps(plan, separators=(",", ":")).encode()) > 65536:
        return [Problem("W-JSON")]
    if plan.get("v") != "0.2":
        return [Problem("W-VERSION")]
    steps, inputs = plan["steps"], plan.get("inputs", {})
    if not isinstance(steps, list) or not 1 <= len(steps) <= 32 or not all(isinstance(s, dict) for s in steps) \
            or not isinstance(inputs, dict) or len(inputs) > 16 \
            or ("goal" in plan and not (isinstance(plan["goal"], str) and len(plan["goal"]) <= 256)):
        return [Problem("W-JSON")]
    b = plan.get("budget", {})
    if not isinstance(b, dict) or not set(b) <= {"max", "tokens", "wall_s"} \
            or ("tokens" in b and not is_int(b["tokens"], 0, I64_MAX)) \
            or ("wall_s" in b and not is_int(b["wall_s"], 0, I64_MAX)) \
            or ("max" in b and not (isinstance(b["max"], dict) and set(b["max"]) == {"amount", "currency"}
                                    and parse_decimal(b["max"]["amount"]) is not None
                                    and not str(b["max"]["amount"]).startswith("-"))):
        return [Problem("W-JSON")]
    for name, spec in inputs.items():
        if not is_name(name) or not isinstance(spec, dict) or set(spec) != {"type", "label"} \
                or not isinstance(spec["label"], dict) or set(spec["label"]) != {"classes", "integrity"} \
                or spec["label"]["integrity"] not in (T, U):
            out.append(Problem("W-ID" if not is_name(name) else "W-JSON"))
    seen = set(inputs)
    asks = 0
    for s in steps:
        sid = s.get("id")
        if not is_name(sid) or sid in seen:
            out.append(Problem("W-ID", sid if isinstance(sid, str) else None))
            continue
        kind = s.get("kind")
        if kind not in KINDS:
            out.append(Problem("W-KIND", sid))
            seen.add(sid)
            continue
        need, may = KINDS[kind]
        keys = set(s) - {"id", "kind"}
        bad = not need <= keys or not keys <= need | may
        bad |= "on_refuse" in s and s["on_refuse"] not in ("stop", "continue")
        bad |= "retry" in s and not is_int(s["retry"], 0, 3)
        bad |= "timeout_s" in s and not is_int(s["timeout_s"], 1, 3600)
        bad |= "approval" in s and not isinstance(s["approval"], bool)
        bad |= "parallel" in s and not isinstance(s["parallel"], bool)
        bad |= "bound" in s and not is_int(s["bound"], 1, 32)
        bad |= "when" in s and not is_name(s["when"])
        for group in ("args", "show", "bind"):
            if group in s:
                g = s[group]
                bad |= not isinstance(g, dict) or len(g) > 16 or any(arg_form(a) is None for a in g.values())
        for single in ("over", "options", "value"):
            if single in s:
                bad |= arg_form(s[single]) != "ref"
        if kind == "declassify":
            bad |= not isinstance(s.get("endorse"), bool) or not isinstance(s.get("drop"), list) \
                or not all(isinstance(c, str) for c in s.get("drop", []))
        if kind == "expr":
            bad |= not isinstance(s.get("expr"), str)
        if bad:
            out.append(Problem("W-FIELD", sid))
            seen.add(sid)
            continue
        earlier = seen - {x["id"] for x in steps if x.get("kind") == "view" and isinstance(x.get("id"), str)}
        refs = [a["ref"] for g in ("args", "show", "bind") for a in s.get(g, {}).values() if "ref" in a]
        refs += [s[k]["ref"] for k in ("over", "options", "value") if k in s]
        refs += [s["when"]] if "when" in s else []
        if any(r not in earlier for r in refs):
            out.append(Problem("W-REF", sid))
        items = [a for g in ("args", "show", "bind") for a in s.get(g, {}).values() if "item" in a]
        if items and (kind != "map" or any("item" in a for g in ("show", "bind") for a in s.get(g, {}).values())):
            out.append(Problem("W-ITEM", sid))
        if kind in ("call", "map") and s["capability"] not in caps:
            out.append(Problem("W-CAP", sid))
        if kind == "ask" and s["prompt"] not in prompts:
            out.append(Problem("W-PROMPT", sid))
        if kind == "view" and s["component"] not in views:
            out.append(Problem("W-PROMPT", sid))
        if kind == "expr":
            try:
                ast = parse(s["expr"])
                names = set()

                def walk(e):
                    if isinstance(e, tuple):
                        if e[0] == "name":
                            names.add(e[1])
                        for x in e[1:]:
                            walk(x)
                    elif isinstance(e, list):
                        for x in e:
                            walk(x)
                walk(ast)
                if any(n not in earlier for n in names):
                    out.append(Problem("W-REF", sid))
            except Problem as p:
                out.append(Problem(p.code, sid))
        asks += kind in ("ask", "declassify")
        seen.add(sid)
    if "result" in plan and (arg_form(plan["result"]) != "ref" or plan["result"]["ref"] not in seen
                             or any(s.get("id") == plan["result"]["ref"] and s.get("kind") == "view" for s in steps)):
        out.append(Problem("W-REF"))
    if asks > 4:
        out.append(Problem("W-COUNT"))
    return out


# --------------------------------------------------------------------------- typing (4.2)


def follow(t, path, allow_optional=False):
    """Type at a field path. T-PATH if it does not exist or crosses an optional field."""
    for p in path:
        if t[0] == "record" and p in t[1] and (t[1][p][1] or allow_optional):
            t = t[1][p][0]
        elif t[0] == "blob" and p in ("size", "media"):
            t = INT if p == "size" else STR
        else:
            raise Problem("T-PATH")
    return t


def path_of(a):
    return a["field"].split(".") if "field" in a else []


class Analysis:
    """Everything the later stages need: types, labels, control labels, flows."""

    def __init__(self, plan, catalog, prompts=None, views=None):
        self.plan = plan
        self.caps = {c["id"]: c for c in catalog}
        self.prompts, self.views = prompts or {}, views or {}
        self.steps = plan.get("steps", []) if isinstance(plan, dict) else []
        self.types, self.kinds = {}, {}
        self.problems = []
        self.expr_ast, self.expr_refs = {}, {}
        self.item_type = {}

    # ----- types

    def arg_type(self, a, sid):
        if "ref" in a:
            return follow(self.types[a["ref"]], path_of(a))
        return follow(self.item_type[sid], path_of(a))

    def check_args(self, sid, args, target: dict, missing_code="T-ARGS"):
        """`target`: name -> (type, required)."""
        for name, a in args.items():
            if name not in target:
                raise Problem(missing_code, sid, name)
            t = target[name][0]
            if "lit" in a:
                if not lit_fits(a["lit"], t):
                    raise Problem(missing_code, sid, name)
            elif not subtype(self.arg_type(a, sid), t):
                raise Problem(missing_code, sid, name)
        for name, (_, req) in target.items():
            if req and name not in args:
                raise Problem(missing_code, sid, name)

    def typing(self):
        plan = self.plan
        for name, spec in plan.get("inputs", {}).items():
            try:
                self.types[name] = type_from_schema(spec["type"])
            except Problem:
                self.problems.append(Problem("T-SCHEMA", None, name))
                self.types[name] = STR
            self.kinds[name] = "input"
        for s in self.steps:
            sid, kind = s["id"], s["kind"]
            self.kinds[sid] = kind
            try:
                self.types[sid] = self.type_step(s)
            except Problem as p:
                self.problems.append(Problem(p.code, sid, p.param))
                self.types[sid] = ("record", {})
            if "when" in s:
                w = s["when"]
                if self.kinds.get(w) != "expr" or self.types.get(w) != BOOL:
                    self.problems.append(Problem("T-WHEN", sid))
        if "result" in plan:
            try:
                follow(self.types[plan["result"]["ref"]], path_of(plan["result"]))
            except Problem:
                self.problems.append(Problem("T-RESULT"))
        self.budget()

    def type_step(self, s):
        sid, kind = s["id"], s["kind"]
        if kind == "expr":
            ast = parse(s["expr"])
            typer = Typer({n: (t, self.kinds[n]) for n, t in self.types.items()})
            t = typer.check(ast)
            self.expr_ast[sid], self.expr_refs[sid] = ast, typer.refs
            return t
        if kind in ("call", "map"):
            cap = self.caps[s["capability"]]
            try:
                tin = type_from_schema(cap.get("input_schema"))
                tout = type_from_schema(cap.get("output_schema"))
                if tin[0] != "record":
                    raise Problem("T-SCHEMA")
            except Problem:
                raise Problem("T-SCHEMA")
            effects = set(cap["effects"])
            if cap.get("consequential") and s.get("approval") is not True:
                raise Problem("T-APPROVAL")
            if s.get("parallel") and not effects <= {"compute", "read"}:
                raise Problem("T-PAR")
            if s.get("retry", 0) > 0 and not (effects <= {"compute", "read"} or cap.get("idempotent")):
                raise Problem("T-RETRY")
            if kind == "map":
                over = follow(self.types[s["over"]["ref"]], path_of(s["over"]))
                if over[0] != "list":
                    raise Problem("T-OVER")
                self.item_type[sid] = over[1]
            self.check_args(sid, s["args"], tin[1])
            return ("list", tout, s["bound"]) if kind == "map" else tout
        if kind == "ask":
            for name, a in s.get("show", {}).items():
                scalar = (isinstance(a["lit"], (bool, int, str)) if "lit" in a
                          else self.arg_type(a, sid)[0] in SCALARS)
                if not scalar:
                    raise Problem("T-ASK", None, name)
            if "options" in s:
                opts = follow(self.types[s["options"]["ref"]], path_of(s["options"]))
                if opts[0] != "list":
                    raise Problem("T-ASK")
                return ("record", {"index": (INT, True), "value": (opts[1], True)})
            return STR
        if kind == "declassify":
            t = follow(self.types[s["value"]["ref"]], path_of(s["value"]))
            if not (t[0] in SCALARS or (t[0] == "record" and all(ft[0] in SCALARS for ft, _ in t[1].values()))):
                raise Problem("T-DECL")
            return t
        if kind == "view":
            props = {n: (type_from_schema(p["schema"]), p.get("required", False))
                     for n, p in self.views[s["component"]]["props"].items()}
            self.check_args(sid, s["bind"], props, "T-VIEW")
            return ("record", {})
        raise AssertionError(kind)

    def budget(self):
        """T-BUDGET with E9 and the cost rules carried over from v0.1 (R13, R14)."""
        money, currency, tokens, wall, metered = 0, None, 0, 0, False
        for s in self.steps:
            if s["kind"] not in ("call", "map") or s["capability"] not in self.caps:
                continue
            cap = self.caps[s["capability"]]
            times = (s.get("bound", 1)) * (1 + s.get("retry", 0))
            cost = cap.get("cost", {"class": "free"})
            if cost.get("class") == "metered":
                metered = True
                if currency not in (None, cost["max"]["currency"]):
                    self.problems.append(Problem("T-BUDGET"))
                    return
                currency = cost["max"]["currency"]
                money += parse_decimal(cost["max"]["amount"]) * times
            tokens += cap.get("model", {}).get("max_tokens", 0) * times
            wall += s.get("timeout_s", cap.get("timeout_s", 30)) * times
        b = self.plan.get("budget", {})
        bad = False
        if metered:
            bad |= "max" not in b or b["max"]["currency"] != currency or money > parse_decimal(b["max"]["amount"])
        bad |= "tokens" in b and tokens > b["tokens"]
        bad |= "wall_s" in b and wall > b["wall_s"]
        if bad:
            self.problems.append(Problem("T-BUDGET"))

    # ----- labels (5.2, 5.3)

    def cap_label(self, cap):
        return label(cap.get("data_classes", []), cap.get("integrity", U))

    def ref_label(self, a, sid=None):
        if "lit" in a:
            return BOT
        if "item" in a:
            return self.item_label[sid]
        name, path = a["ref"], path_of(a)
        if self.kinds[name] == "ask" and name in self.ask_labels and path:
            return self.ask_labels[name][0 if path[0] == "index" else 1]
        return self.L[name]

    def labels(self):
        plan = self.plan
        self.L, self.pc, self.ask_labels, self.item_label, self.provenance = {}, {}, {}, {}, set()
        for name, spec in plan.get("inputs", {}).items():
            self.L[name] = label_from_json(spec["label"])            # L-INPUT
            self.pc[name] = BOT                                       # P4
        cont = {s["id"] for s in self.steps if s.get("on_refuse") == "continue"}
        for s in self.steps:
            sid, kind = s["id"], s["kind"]
            args = list(s.get("args", {}).values()) + list(s.get("show", {}).values()) + list(s.get("bind", {}).values())
            deps = {a["ref"] for a in args if "ref" in a}
            deps |= {s[k]["ref"] for k in ("over", "options", "value") if k in s}
            if kind == "expr":
                deps |= {n for n, _, in_done in self.expr_refs.get(sid, ()) if not in_done}
            pc = BOT                                                  # P1
            if "when" in s:
                pc = join(pc, self.L[s["when"]])                      # P2
                deps.add(s["when"])
            for d in sorted(deps):                                    # P3
                pc = join(pc, self.L[d] if d in cont else self.pc[d])
            self.pc[sid] = pc
            if kind == "map":
                self.item_label[sid] = self.ref_label(s["over"])      # L-ITEM
            arg_labels = [self.ref_label(a, sid) for a in s.get("args", {}).values()]
            if kind == "call":                                        # L-CALL
                self.L[sid] = join(self.cap_label(self.caps[s["capability"]]), pc, *arg_labels)
            elif kind == "map":                                       # L-MAP
                self.L[sid] = join(self.cap_label(self.caps[s["capability"]]), self.item_label[sid], pc, *arg_labels)
            elif kind == "expr":                                      # L-EXPR
                parts = []
                for n, first, _ in self.expr_refs.get(sid, ()):
                    if self.kinds[n] == "ask" and n in self.ask_labels and first in ("index", "value"):
                        parts.append(self.ask_labels[n][0 if first == "index" else 1])
                    else:
                        parts.append(self.L[n])
                self.L[sid] = join(pc, *parts)
            elif kind == "ask":                                       # L-ASK
                shown = [self.ref_label(a, sid) for a in s.get("show", {}).values()]
                opts = self.ref_label(s["options"]) if "options" in s else BOT
                choice = (join(pc, opts, *shown)[0], T)
                if "options" in s:
                    self.ask_labels[sid] = (choice, opts)
                    self.L[sid] = join(choice, opts)
                else:
                    self.L[sid] = choice
            elif kind == "declassify":                                # L-DECL
                v = self.ref_label(s["value"])
                kept = [c for c in join(v, pc)[0] if not any(covers(d, c) for d in s["drop"])]
                self.L[sid] = label(kept, T if s["endorse"] else join(v, pc)[1])
            else:
                self.L[sid] = BOT
            if kind in ("call", "map") and s.get("approval") is True and pc[1] == U:
                self.provenance.add(sid)                              # A1

    # ----- flows (5.4)

    def flows(self):
        out = []
        for s in self.steps:
            sid, kind, pc = s["id"], s["kind"], self.pc[s["id"]]
            if kind in ("call", "map"):
                cap = self.caps[s["capability"]]
                pcx = (pc[0], T) if sid in self.provenance else pc
                roles = cap.get("roles", {})
                named = sorted(s["args"].items()) or [("", {"lit": None})]        # F1, F2
                for effect in sorted((e for e in cap["effects"] if e != "compute"), key=EFFECTS.index):
                    for name, a in named:
                        out.append({"step": sid, "sink": "capability", "capability": cap["id"], "effect": effect,
                                    "param": name, "role": roles.get(name, "payload"),
                                    "quarantine": bool(cap.get("quarantine", False)),
                                    "_v": self.ref_label(a, sid), "_pc": pcx})
            elif kind == "view":                                                  # F3
                props = self.views[s["component"]]["props"]
                for name, a in sorted(s["bind"].items()):
                    out.append({"step": sid, "sink": "view", "param": name, "kind": props[name].get("kind", "text"),
                                "_v": self.ref_label(a, sid), "_pc": pc})
            elif kind == "ask":                                                   # F4
                shown = sorted(s.get("show", {}).items())
                if "options" in s:
                    shown.append(("options", s["options"]))
                for name, a in sorted(shown) or [("", {"lit": None})]:
                    out.append({"step": sid, "sink": "ask", "param": name, "_v": self.ref_label(a, sid), "_pc": pc})
        if "result" in self.plan:                                                 # F5
            out.append({"step": None, "sink": "result", "param": "", "_v": self.ref_label(self.plan["result"]),
                        "_pc": BOT})
        return out


def flow_json(f):
    out = {k: v for k, v in f.items() if not k.startswith("_") and v is not None}
    out["value"], out["pc"] = label_json(f["_v"]), label_json(f["_pc"])
    return out


def hard_rule(f):
    """5.5. Returns a rule code or None."""
    arriving = join(f["_v"], f["_pc"])
    if f["sink"] in ("view", "ask", "result"):
        if has_secret(arriving):
            return "H1"
        if f["sink"] == "view" and f["kind"] != "text" and f["_v"][1] == U:
            return "H5"
        return None
    effect = f["effect"]
    if effect == "egress" and has_secret(arriving):
        return "H1"
    if effect != "read" and f["role"] == "target" and f["_v"][1] == U:
        return "H2"
    if f["_pc"][1] == U and (effect in ("delete", "execute", "egress") or (effect == "write" and not f["quarantine"])):
        return "H3"
    return None


def analyse(plan, catalog, prompts=None, views=None):
    """Stages 4.1 and 4.2. Returns (analysis, problems)."""
    a = Analysis(plan, catalog, prompts, views)
    problems = well_formed(plan, a.caps, a.prompts, a.views)
    if not problems:
        a.typing()
        problems = a.problems
    return a, problems


def problems_json(problems, order):
    rows = [{"code": p.code, **({"step": p.step} if p.step else {}), **({"param": p.param} if p.param else {})}
            for p in problems]
    rows.sort(key=lambda r: (order.get(r.get("step"), -1 if r["code"].startswith(("W-J", "W-V")) else 10**6),
                             r["code"], r.get("param", "")))
    return rows


def plan_verify(plan, catalog, policy="none", prompts=None, views=None) -> dict:
    """Operation `plan-verify`. policy: "permit-all" or "none" (5.6)."""
    a, problems = analyse(plan, catalog, prompts, views)
    order = {s.get("id"): i for i, s in enumerate(a.steps) if isinstance(s, dict)}
    if not problems:
        for cap in a.caps.values():
            if cap.get("quarantine") and cap.get("effects") != ["write"]:
                problems.append(Problem("Q1", None, cap["id"]))
        a.labels()
        for s in a.steps:
            if s["kind"] == "declassify":                              # H4
                if has_secret(a.ref_label(s["value"])) or any(is_secret(c) for c in s["drop"]):
                    problems.append(Problem("H4", s["id"]))
                elif policy != "permit-all" and s["drop"]:             # 5.6: action declassify
                    problems.append(Problem("F-POLICY", s["id"]))
        for f in a.flows():
            rule = hard_rule(f)
            if rule:
                problems.append(Problem(rule, f["step"], f["param"] or None))
            elif policy != "permit-all" and join(f["_v"], f["_pc"]) != BOT:
                problems.append(Problem("F-POLICY", f["step"], f["param"] or None))
    if problems:
        return {"verdict": "reject", "problems": problems_json(problems, order)}
    return {"verdict": "accept"}


def plan_flows(plan, catalog, prompts=None, views=None) -> dict:
    """Operation `plan-flows`: labels per step and the flow list, before any rule."""
    a, problems = analyse(plan, catalog, prompts, views)
    if problems:
        order = {s.get("id"): i for i, s in enumerate(a.steps) if isinstance(s, dict)}
        return {"verdict": "reject", "problems": problems_json(problems, order)}
    a.labels()
    labels = {}
    for s in a.steps:
        sid = s["id"]
        labels[sid] = {"value": label_json(a.L[sid]), "pc": label_json(a.pc[sid])}
        if sid in a.ask_labels:
            labels[sid]["index"] = label_json(a.ask_labels[sid][0])
            labels[sid]["chosen"] = label_json(a.ask_labels[sid][1])
        if sid in a.provenance:
            labels[sid]["provenance"] = True
    return {"labels": labels, "flows": [flow_json(f) for f in a.flows()]}


# --------------------------------------------------------------------------- execution (section 6)


def lane_of(cap) -> str:
    effects = set(cap["effects"])
    if effects <= {"compute"}:
        return "internal"
    if effects <= {"compute", "read"}:
        return "read"
    return "airlock"


def plan_run(plan, catalog, inputs=None, script=None, prompts=None, views=None) -> dict:
    """Operation `plan-run`. Runs an accepted plan against scripted backend outcomes.

    script: step id -> outcome.
      call:        {"output": v} or {"state": s, "reason": r}; optional "label" (run-time label, E8),
                   "approval": "declined", "attempts": [outcome, ...] (E10)
      map:         {"elements": [outcome, ...]}
      ask:         {"answer": {"index": i}} or {"answer": "text"} or {"state": "denied", "reason": ...}
      declassify:  {"approve": true | false}
    Returns the state of every step, the audit trace and the result."""
    a, problems = analyse(plan, catalog, prompts, views)
    if problems:
        raise ValueError("plan-run needs a plan that passes 4.1 and 4.2")
    a.labels()
    inputs, script = inputs or {}, script or {}
    json_values = dict(inputs)
    values = {n: internal(v, a.types[n]) for n, v in inputs.items()}
    completed, states, trace = set(), [], []
    stopped = False
    unsynced = False

    def note(entry):
        nonlocal unsynced
        trace.append(entry)
        unsynced = True

    def sync():
        nonlocal unsynced
        if unsynced:
            trace.append({"sync": True})
            unsynced = False

    def resolve(arg, sid, item=None):
        if "lit" in arg:
            return arg["lit"]
        v = item if "item" in arg else json_values[arg["ref"]]
        for p in path_of(arg):
            v = v[p]
        return v

    def one_call(s, cap, args, outcome, extra):
        """One capability invocation. Returns (state, reason, output)."""
        lane = lane_of(cap)
        early = None
        if not conforms(args, cap["input_schema"]):                              # E5
            early = ("refused", "bad-input", None)
        elif s.get("approval") and outcome.get("approval") == "declined":
            early = ("denied", "approval-denied", None)
        if early:
            note({"step": s["id"], "entry": "decision" if lane == "airlock" else "note", **extra})
            if lane == "airlock":
                sync()
            return early
        attempts = outcome.get("attempts", [outcome])
        allowed = 1 + s.get("retry", 0)
        state = reason = out = None
        for n, att in enumerate(attempts[:allowed], start=1):
            tag = dict(extra, **({"attempt": n} if allowed > 1 else {}))
            if lane == "airlock":                                                # E11, E12
                note({"step": s["id"], "entry": "decision", **tag})
                sync()
            if "output" in att:
                out = att["output"]
                if not conforms(out, cap["output_schema"]):                      # E7
                    state, reason, out = "failed", "bad-output", None
                elif "label" in att and not leq(label_from_json(att["label"]), a.L[s["id"]]):
                    state, reason, out = "refused", "label-exceeds-static", None  # E8
                else:
                    state, reason = "completed", None
            else:
                state, reason, out = att["state"], att.get("reason"), None
            note({"step": s["id"], "entry": "outcome" if lane == "airlock" else "note", **tag})
            if lane == "read" and has_secret(a.L[s["id"]]):
                sync()
            if state != "failed":                                                # E10
                break
        return state, reason, out

    for s in a.steps:
        sid, kind = s["id"], s["kind"]
        state, reason, out = None, None, None
        deps = {x["ref"] for g in ("args", "show", "bind") for x in s.get(g, {}).values() if "ref" in x}
        deps |= {s[k]["ref"] for k in ("over", "options", "value") if k in s}
        deps &= {x["id"] for x in a.steps}
        if kind == "expr":
            deps |= {n for n, _, in_done in a.expr_refs[sid] if not in_done and a.kinds[n] != "input"}
        if stopped:
            state, reason = "skipped", "stopped"
        elif "when" in s and s["when"] not in completed:
            state, reason = "skipped", "dependency"                              # E3
        elif "when" in s and json_values[s["when"]] is False:
            state, reason = "skipped", "when"                                    # E2
        elif not deps <= completed:
            state, reason = "skipped", "dependency"                              # E3
        elif kind == "expr":
            try:
                v = evaluate(a.expr_ast[sid], values, completed)
                if v == 0 and a.types[sid] == DEC and not isinstance(v, Dec):
                    v = Dec(0)
                state, out = "completed", external(v)
            except Undefined:
                state, reason = "skipped", "undefined"                           # 3.6
        elif kind == "call":
            cap = a.caps[s["capability"]]
            args = {n: resolve(x, sid) for n, x in s["args"].items()}
            state, reason, out = one_call(s, cap, args, script[sid], {})
        elif kind == "map":
            cap = a.caps[s["capability"]]
            items = resolve(s["over"], sid)
            if len(items) > s["bound"]:                                          # E6
                state, reason = "refused", "bound-exceeded"
                note({"step": sid, "entry": "decision" if lane_of(cap) == "airlock" else "note"})
                if lane_of(cap) == "airlock":
                    sync()
            else:
                outs, state = [], "completed"
                for i, item in enumerate(items):
                    args = {n: resolve(x, sid, item) for n, x in s["args"].items()}
                    st, rs, o = one_call(s, cap, args, script[sid]["elements"][i], {"element": i})
                    if st != "completed":
                        state, reason, outs = st, rs, None
                        break
                    outs.append(o)
                out = outs
        elif kind == "ask":
            note({"step": sid, "entry": "decision"})
            sync()
            sc = script[sid]
            if "answer" not in sc:
                state, reason = sc["state"], sc.get("reason")
            elif "options" in s:
                opts = resolve(s["options"], sid)
                i = sc["answer"]["index"]
                state, out = "completed", {"index": i, "value": opts[i]}
            else:
                state, out = "completed", sc["answer"]
            note({"step": sid, "entry": "outcome"})
        elif kind == "declassify":
            v = resolve(s["value"], sid)
            if len(json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode()) > 2048:   # A2
                state, reason = "refused", "too-large"
                note({"step": sid, "entry": "decision"})
                sync()
            else:
                note({"step": sid, "entry": "decision"})
                sync()
                state, reason, out = ("completed", None, v) if script[sid]["approve"] else ("denied", "approval-denied", None)
                note({"step": sid, "entry": "outcome"})
        else:
            state = "completed"
        if kind in ("expr", "view") or state == "skipped":
            note({"step": sid, "entry": "note"})
        if state == "completed":
            completed.add(sid)
            if kind != "view":
                json_values[sid] = out
                values[sid] = internal(out, a.types[sid])
        elif reason not in ("when", "dependency", "stopped") and s.get("on_refuse", "stop") == "stop":
            stopped = True                                                        # E4
        row = {"id": sid, "state": state}
        if reason:
            row["reason"] = reason
        if state == "completed" and kind != "view":
            row["output"] = out
        states.append(row)
    sync()
    result = {"steps": states, "trace": trace}
    if "result" in plan and plan["result"]["ref"] in completed:
        result["result"] = resolve(plan["result"], None)
    return result
