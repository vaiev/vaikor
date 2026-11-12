#!/usr/bin/env python3
# Copyright 2026 VAIEV
# SPDX-License-Identifier: Apache-2.0
"""Generate spec/test-vectors/plan-v0.2/*.json for VKR-L3 v0.2.

Each vector's input is written here by hand, together with what it is meant to pin down.
The expected value is computed by the reference checker (spec/validate/plan_v02.py) and
then compared with the intent stated here; a mismatch aborts generation. Run from the
repository root:

    python3 spec/test-vectors/tools/gen_plan_v02_vectors.py
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "spec" / "validate"))
import plan_v02 as P  # noqa: E402

OUT = ROOT / "spec" / "test-vectors" / "plan-v0.2"
CAP = "tag:vaikor.com,2026:capability:"

# ---------------------------------------------------------------- schema shorthands
S, I, B, D = {"type": "string"}, {"type": "integer"}, {"type": "boolean"}, {"type": "string", "format": "decimal"}


def R(props, optional=()):
    return {"type": "object", "properties": props, "required": [k for k in props if k not in optional],
            "additionalProperties": False}


def L(items, n=8):
    return {"type": "array", "items": items, "maxItems": n}


PDF = {"type": "blob", "media": "application/pdf"}
MAIL = R({"id": S, "subject": S, "sender": S, "note": S}, optional=("note",))
DRAFT = R({"id": S, "account": S, "amount": D})


def cap(name, effects, classes, inp, out, consequential=False, **extra):
    return {"id": CAP + name, "effects": effects, "data_classes": classes, "consequential": consequential,
            "cost": {"class": "free"}, "input_schema": inp, "output_schema": out, **extra}


CATALOG = {c["id"][len(CAP):]: c for c in [
    cap("mail.search", ["read"], ["communications.content"], R({"query": S}), R({"items": L(MAIL)})),
    cap("settings.get", ["read"], [], R({}), R({"enabled": B, "limit": I, "owner": S, "nickname": S},
                                                 optional=("nickname",)), integrity="trusted"),
    cap("contacts.lookup", ["read"], ["contacts"], R({"name": S}), R({"address": S}), integrity="trusted"),
    cap("secrets.get", ["read"], ["secrets.api_key"], R({"name": S}), R({"value": S}), integrity="trusted"),
    cap("notes.append", ["write"], ["documents"], R({"text": S, "path": S}, optional=("path",)), R({"id": S}),
        roles={"path": "target"}),
    cap("message.send", ["egress"], ["communications.content"], R({"to": S, "body": S}), R({"id": S}),
        consequential=True, roles={"to": "target"}),
    cap("draft.put", ["write"], ["finance.documents"], R({"account": S, "amount": D}), R({"id": S}),
        quarantine=True),
    cap("draft.list", ["read"], ["finance.documents"], R({}), R({"items": L(DRAFT)})),
    cap("ledger.post", ["write"], ["finance.transactions"], R({"account": S, "amount": D}), R({"id": S}),
        idempotent=True),
    cap("qr.decode", ["compute"], [], R({"doc": PDF}), R({"iban": S, "amount": D, "creditor": S})),
    cap("iban.check", ["compute"], [], R({"iban": S}), R({"ok": B}), integrity="trusted"),
    cap("entry.check", ["compute"], [], R({"entry": R({"account": S})}), R({"ok": B}), integrity="trusted"),
    cap("model.infer.kontierung", ["compute"], [], R({"creditor": S, "amount": D}),
        R({"account": S, "confidence": {"type": "integer", "minimum": 0, "maximum": 1000}}),
        model={"base": "sha256:" + "ab" * 32, "adapter": "sha256:" + "cd" * 32, "max_tokens": 64}),
]}
PROMPTS = {"choose_one": {"options": True}, "confirm_text": {"options": False}}
VIEWS = {"Card": {"props": {"title": {"schema": S, "kind": "text", "required": True},
                            "link": {"schema": S, "kind": "url"}}}}


def call(sid, name, args=None, **more):
    return {"id": sid, "kind": "call", "capability": CAP + name, "args": args or {}, **more}


def lit(v):
    return {"lit": v}


def ref(step, field=None):
    return {"ref": step, **({"field": field} if field else {})}


def plan(*steps, **more):
    return {"v": "0.2", **more, "steps": list(steps)}


MAILS = call("mails", "mail.search", {"query": lit("invoice")})
FOUND = {"id": "found", "kind": "expr", "expr": "size(mails.items) > 0"}
KEY = call("key", "secrets.get", {"name": lit("api")})
HASKEY = {"id": "haskey", "kind": "expr", "expr": "size(key.value) > 0"}
THREE_MAILS = {"items": [{"id": f"m{i}", "subject": f"Invoice {i}", "sender": f"CH{i}"} for i in (1, 2, 3)]}

VECTORS = {"expr": [], "verify": [], "flow": [], "run": []}
OPERATION = {"expr": "expr-eval", "verify": "plan-verify", "flow": "plan-flows", "run": "plan-run"}
DESCRIPTION = {
    "expr": "VKR-L3 v0.2 expression language (0003 section 3): typing, total evaluation, limits.",
    "verify": "VKR-L3 v0.2 static checks (0003 sections 4 and 5): typing, fixed flow rules H1 to H5, endorsement.",
    "flow": "VKR-L3 v0.2 labels and flow lists (0003 section 5) before any rule or policy is applied.",
    "run": "VKR-L3 v0.2 execution (0003 section 6): step states, skip and stop, lanes, audit trace order.",
}


def used(p):
    names = sorted({s["capability"][len(CAP):] for s in p["steps"] if "capability" in s})
    return [CATALOG[n] for n in names]


def add(suite, name, rules, pins, check, **inp):
    """Compute the expected value, hold it against `check`, and record the vector."""
    if suite == "expr":
        value = P.expr_eval(inp["env"], inp["expr"])
    else:
        p = inp["plan"]
        inp = {"plan": p, "catalog": used(p), **{k: v for k, v in inp.items() if k != "plan"}}
        if any(s["kind"] == "ask" for s in p["steps"]):
            inp["prompts"] = PROMPTS
        if any(s["kind"] == "view" for s in p["steps"]):
            inp["views"] = VIEWS
        extra = {k: inp[k] for k in ("prompts", "views") if k in inp}
        if suite == "verify":
            value = P.plan_verify(p, inp["catalog"], inp["policy"], **extra)
        elif suite == "flow":
            value = P.plan_flows(p, inp["catalog"], **extra)
        else:
            assert P.plan_verify(p, inp["catalog"], "permit-all", **extra) == {"verdict": "accept"}, name
            value = P.plan_run(p, inp["catalog"], inp.get("inputs"), inp["script"], **extra)
    assert check(value), f"{suite}/{name}: reference result is not what the vector intends:\n{json.dumps(value, indent=1)}"
    VECTORS[suite].append({
        "id": f"plan.v02-{suite}.{len(VECTORS[suite]) + 1:03d}",
        "spec": [{"doc": "L3", "version": "0.2", "section": r} for r in rules],
        "operation": OPERATION[suite],
        "input": inp,
        "expected": {"value": value},
        "status": "normative",
        "note": f"{name}: {pins}",
    })


def rejects(*rows):
    want = [dict(zip(("code", "step", "param"), r)) for r in rows]
    return lambda v: v == {"verdict": "reject", "problems": want}


def accepts(v):
    return v == {"verdict": "accept"}


def states(**want):
    return lambda v: {s["id"]: (s["state"], s.get("reason")) for s in v["steps"]} == want


def entries(v):
    return ["sync" if "sync" in e else e["step"] + ":" + e["entry"] + (f"#{e['attempt']}" if "attempt" in e else "")
            + (f"[{e['element']}]" if "element" in e else "") for e in v["trace"]]


# ================================================================ expr

INT = lambda v: {"type": I, "value": v}  # noqa: E731
OPT = {"type": R({"a": S, "note": S}, optional=("note",)), "value": {"a": "x"}}

add("expr", "overflow-is-undefined", ["V1", "V2"], "i64 overflow is undefined, and undefined propagates through >",
    lambda v: v == {"type": "bool", "undefined": True},
    env={"a": INT(9223372036854775807)}, expr="a + 1 > 0")
add("expr", "and-short-circuits-left-only", ["V3"], "false && undefined is false; the right side is not evaluated",
    lambda v: v == {"type": "bool", "value": False},
    env={"z": INT(0)}, expr="false && 1 / z == 1")
add("expr", "has-guards-optional", ["V5", "X-OPT"], "has() on an absent optional field is false and guards the selection",
    lambda v: v == {"type": "bool", "value": False},
    env={"r": OPT}, expr='has(r.note) && r.note == "y"')
add("expr", "division-truncates", ["V6"], "/ truncates towards zero and % takes the sign of the dividend",
    lambda v: v == {"type": "list<int>[4]", "value": [-3, -1, -3, 1]},
    env={"a": INT(-7), "b": INT(2)}, expr="[a / b, a % b, 7 / -2, 7 % -2]")
add("expr", "decimal-equality-is-numeric", ["V7"], "decimal comparison ignores trailing fractional zeros",
    lambda v: v == {"type": "bool", "value": True},
    env={}, expr='dec("1.50") == dec("1.5")')
add("expr", "depth-17-rejected", ["W-PARSE"], "17 nested brackets exceed the depth limit of 16",
    lambda v: v == {"error": "W-PARSE"},
    env={}, expr="(" * 17 + "1" + ")" * 17)
add("expr", "int-decimal-do-not-mix", ["T-EXPR"], "there is no implicit conversion between int and decimal",
    lambda v: v == {"error": "T-EXPR"},
    env={}, expr='1 + dec("1")')
add("expr", "done-of-skipped-is-false", ["V5"], "done() of a step that did not complete is false, never undefined",
    lambda v: v == {"type": "bool", "value": False},
    env={"s": {"type": R({"x": I}), "step": True, "completed": False}}, expr="done(s)")
# Additional vectors beyond the 30 seeds.
add("expr", "and-undefined-left-is-undefined", ["V3"], "undefined && false is undefined: only the left side short-circuits",
    lambda v: v == {"type": "bool", "undefined": True},
    env={"z": INT(0)}, expr="1 / z == 1 && false")
add("expr", "depth-16-accepted", ["W-PARSE"], "16 nested brackets are within the limit",
    lambda v: v == {"type": "int", "value": 1},
    env={}, expr="(" * 16 + "1" + ")" * 16)
add("expr", "decimal-sum-is-canonical", ["V7", "3.4"], "decimal results are rendered without trailing zeros",
    lambda v: v == {"type": "decimal", "value": "0.3"},
    env={}, expr='sum([dec("0.10"), dec("0.20")])')

# ================================================================ verify

add("verify", "missing-required-arg", ["T-ARGS"], "a required parameter without an argument is a static error",
    rejects(("T-ARGS", "send", "body")), policy="permit-all",
    plan=plan(call("send", "message.send", {"to": lit("contact:bea")}, approval=True)))
add("verify", "record-width-subtype-accepted", ["S5", "T-ARGS"], "a record with extra fields is a subtype of the parameter record",
    accepts, policy="permit-all",
    plan=plan(call("acct", "model.infer.kontierung", {"creditor": lit("ACME AG"), "amount": lit("12.50")}),
              call("ok", "entry.check", {"entry": ref("acct")})))
add("verify", "ref-through-optional-rejected", ["T-PATH"], "an argument cannot be taken through an optional field",
    rejects(("T-PATH", "note")), policy="permit-all",
    plan=plan(call("cfg", "settings.get"), call("note", "notes.append", {"text": ref("cfg", "nickname")})))
add("verify", "parallel-on-write-rejected", ["T-PAR"], "parallel is allowed only for compute and read capabilities",
    rejects(("T-PAR", "each")), policy="permit-all",
    plan=plan(MAILS, {"id": "each", "kind": "map", "capability": CAP + "notes.append", "over": ref("mails", "items"),
                      "bound": 8, "parallel": True, "args": {"text": {"item": True, "field": "subject"}}}))
add("verify", "h1-secret-in-when-to-egress", ["P2", "F1", "H1"], "a secret that only decides whether an egress step runs still reaches it",
    rejects(("H1", "send", "body"), ("H1", "send", "to")), policy="permit-all",
    plan=plan(KEY, HASKEY, call("send", "message.send", {"to": lit("contact:bea"), "body": lit("ready")},
                                when="haskey", approval=True)))
add("verify", "h2-untrusted-recipient", ["L-CALL", "H2"], "an untrusted value cannot fill a target parameter of an egress capability",
    rejects(("H2", "send", "to")), policy="permit-all",
    plan=plan(MAILS, {"id": "addr", "kind": "expr", "expr": "mails.items[0].sender"},
              call("send", "message.send", {"to": ref("addr"), "body": lit("hello")}, approval=True)))
add("verify", "h2-not-lifted-by-approval", ["A1", "H2"], "approval with provenance endorses the control label only; H3 is lifted, H2 is not",
    rejects(("H2", "send", "to")), policy="permit-all",
    plan=plan(MAILS, FOUND, {"id": "addr", "kind": "expr", "expr": "mails.items[0].sender"},
              call("send", "message.send", {"to": ref("addr"), "body": lit("hello")}, when="found", approval=True)))
add("verify", "h3-direct-write-under-untrusted-when", ["P2", "F1", "H3"], "untrusted data cannot decide whether a direct write happens",
    rejects(("H3", "note", "text")), policy="permit-all",
    plan=plan(MAILS, FOUND, call("note", "notes.append", {"text": lit("invoice arrived")}, when="found")))
add("verify", "h3-quarantine-write-accepted", ["H3", "Q1"], "under an untrusted control label a write to a quarantine capability is allowed",
    accepts, policy="permit-all",
    plan=plan(MAILS, FOUND, call("draft", "draft.put", {"account": lit("6500"), "amount": lit("0.00")}, when="found")))
add("verify", "h3-lifted-by-approval-provenance", ["A1", "H3"], "approval: true under an untrusted control label becomes approval with provenance",
    accepts, policy="permit-all",
    plan=plan(MAILS, FOUND, call("note", "notes.append", {"text": lit("invoice arrived")}, when="found", approval=True)))
add("verify", "declassify-secret-rejected", ["H4"], "a value with a secret class cannot be declassified",
    rejects(("H4", "open")), policy="permit-all",
    plan=plan(KEY, {"id": "open", "kind": "declassify", "value": ref("key", "value"), "drop": [], "endorse": True}))
# Additional vectors beyond the 30 seeds.
add("verify", "ask-without-content-still-a-sink", ["F4", "H1"], "an ask with neither options nor show still yields a flow, so a secret control label is caught",
    rejects(("H1", "confirm")), policy="permit-all",
    plan=plan(KEY, HASKEY, {"id": "confirm", "kind": "ask", "prompt": "confirm_text", "when": "haskey"}))
add("verify", "declassify-drop-secret-rejected", ["H4"], "drop cannot name a secret class, so a secret control label cannot be stripped",
    rejects(("H4", "open")), policy="permit-all",
    plan=plan(call("who", "contacts.lookup", {"name": lit("bea")}),
              {"id": "open", "kind": "declassify", "value": ref("who", "address"), "drop": ["secrets"], "endorse": False}))
add("verify", "h5-untrusted-value-in-url-prop", ["F3", "H5"], "an untrusted value binds only to text props of a view",
    rejects(("H5", "card", "link")), policy="permit-all",
    plan=plan(MAILS, {"id": "subj", "kind": "expr", "expr": "mails.items[0].subject"},
              {"id": "card", "kind": "view", "component": "Card", "bind": {"title": lit("Mail"), "link": ref("subj")}}))
add("verify", "consequential-needs-approval", ["T-APPROVAL"], "carried over from v0.1 R7: a consequential capability requires approval: true",
    rejects(("T-APPROVAL", "send")), policy="permit-all",
    plan=plan(call("send", "message.send", {"to": lit("contact:bea"), "body": lit("hello")})))
add("verify", "no-policy-denies-labelled-flow", ["5.6", "F-POLICY"], "without a policy every flow whose label is not bottom is denied",
    rejects(("F-POLICY", "note", "text")), policy="none",
    plan=plan(call("who", "contacts.lookup", {"name": lit("bea")}), call("note", "notes.append", {"text": ref("who", "address")})))

# ================================================================ flow

WHO = call("who", "contacts.lookup", {"name": lit("bea")})
NOTE_WHO = call("note", "notes.append", {"text": ref("who", "address")})
CONTACTS_T = {"classes": ["contacts"], "integrity": "trusted"}
MAIL_U = {"classes": ["communications.content"], "integrity": "untrusted"}
BOTTOM = {"classes": [], "integrity": "trusted"}

add("flow", "pc-through-continue-dependency", ["P3"], "a consumer of an on_refuse: continue step takes that step's value label as control label",
    lambda v: v["labels"]["note"]["pc"] == CONTACTS_T and v["flows"][-1]["pc"] == CONTACTS_T,
    plan=plan({**WHO, "on_refuse": "continue"}, NOTE_WHO))
add("flow", "pc-through-stop-dependency", ["P3"], "a consumer of an on_refuse: stop step takes only that step's control label",
    lambda v: v["labels"]["note"]["pc"] == BOTTOM and v["flows"][-1]["value"] == CONTACTS_T,
    plan=plan(WHO, NOTE_WHO))
add("flow", "done-carries-step-label", ["L-EXPR", "E3"], "done(x) carries L(x); a name used only inside done() is not a dependency",
    lambda v: v["labels"]["ok"] == {"value": MAIL_U, "pc": BOTTOM},
    plan=plan({**MAILS, "on_refuse": "continue"}, {"id": "ok", "kind": "expr", "expr": "done(mails)"}))
add("flow", "ask-index-trusted-value-keeps-label", ["L-ASK", "A3"], "the owner's choice is trusted; what was chosen keeps its label",
    lambda v: v["labels"]["pick"]["index"] == {"classes": ["communications.content"], "integrity": "trusted"}
    and v["labels"]["pick"]["chosen"] == MAIL_U and v["labels"]["first"]["value"]["integrity"] == "trusted",
    plan=plan(MAILS, {"id": "pick", "kind": "ask", "prompt": "choose_one", "options": ref("mails", "items")},
              {"id": "first", "kind": "expr", "expr": "pick.index == 0"}))
add("flow", "declassify-drops-and-endorses", ["L-DECL", "A2"], "declassify removes the dropped classes and, with endorse, yields trusted",
    lambda v: v["labels"]["subject"]["value"] == BOTTOM,
    plan=plan(MAILS, {"id": "pick", "kind": "ask", "prompt": "choose_one", "options": ref("mails", "items")},
              {"id": "subject", "kind": "declassify", "value": ref("pick", "value.subject"),
               "drop": ["communications.content"], "endorse": True}))
# Additional vector beyond the 30 seeds.
add("flow", "drop-covers-subclasses", ["5.1", "L-DECL"], "a class covers its subclasses: dropping finance removes finance.documents",
    lambda v: v["labels"]["n"]["value"] == {"classes": ["finance.documents"], "integrity": "untrusted"}
    and v["labels"]["open"]["value"] == {"classes": [], "integrity": "untrusted"},
    plan=plan(call("drafts", "draft.list"), {"id": "n", "kind": "expr", "expr": "size(drafts.items)"},
              {"id": "open", "kind": "declassify", "value": ref("n"), "drop": ["finance"], "endorse": False}))

# ================================================================ run

add("run", "undefined-expr-stops-by-default", ["3.6", "E4"], "an undefined expr ends skipped (undefined) and, by default, stops the plan",
    states(cfg=("completed", None), share=("skipped", "undefined"), note=("skipped", "stopped")),
    plan=plan(call("cfg", "settings.get"), {"id": "share", "kind": "expr", "expr": "10 / cfg.limit"},
              call("note", "notes.append", {"text": lit("done")})),
    script={"cfg": {"output": {"enabled": True, "limit": 0, "owner": "ada"}}})
add("run", "continue-then-compensate", ["E3", "E4", "V5"], "with continue the plan goes on; dependents are skipped; done() guards a compensating step",
    states(who=("failed", "unavailable"), use=("skipped", "dependency"), missed=("completed", None),
           fallback=("completed", None)),
    plan=plan({**WHO, "on_refuse": "continue"}, {**NOTE_WHO, "id": "use"},
              {"id": "missed", "kind": "expr", "expr": "!done(who)"},
              call("fallback", "notes.append", {"text": lit("lookup failed")}, when="missed")),
    script={"who": {"state": "failed", "reason": "unavailable"}, "fallback": {"output": {"id": "n1"}}})
add("run", "map-over-bound-refused", ["E6"], "a list longer than bound refuses the map before any element runs",
    lambda v: states(mails=("completed", None), each=("refused", "bound-exceeded"))(v)
    and not any(e.get("element") is not None for e in v["trace"]),
    plan=plan(MAILS, {"id": "each", "kind": "map", "capability": CAP + "iban.check", "over": ref("mails", "items"),
                      "bound": 2, "args": {"iban": {"item": True, "field": "sender"}}}),
    script={"mails": {"output": THREE_MAILS}})
add("run", "runtime-label-exceeds-static", ["E8", "Q3"], "a run-time label that is not below the static label refuses the step",
    states(drafts=("refused", "label-exceeds-static"), n=("skipped", "stopped")),
    plan=plan(call("drafts", "draft.list"), {"id": "n", "kind": "expr", "expr": "size(drafts.items)"}),
    script={"drafts": {"output": {"items": []}, "label": {"classes": ["health.records"], "integrity": "untrusted"}}})
add("run", "buffered-entries-flush-before-airlock", ["E11", "6.3"], "internal entries are buffered and become durable with the next airlock decision, before the effect",
    lambda v: entries(v) == ["qr:note", "iban:note", "acct:note", "sure:note", "draft:decision", "sync",
                             "draft:outcome", "sync"],
    plan=plan(call("qr", "qr.decode", {"doc": ref("file")}), call("iban", "iban.check", {"iban": ref("qr", "iban")}),
              call("acct", "model.infer.kontierung", {"creditor": ref("qr", "creditor"), "amount": ref("qr", "amount")}),
              {"id": "sure", "kind": "expr", "expr": "iban.ok && acct.confidence >= 800"},
              call("draft", "draft.put", {"account": ref("acct", "account"), "amount": ref("qr", "amount")}, when="sure"),
              inputs={"file": {"type": PDF, "label": {"classes": ["finance.documents"], "integrity": "untrusted"}}}),
    inputs={"file": {"digest": "sha256:" + "11" * 32, "media": "application/pdf", "size": 48213}},
    script={"qr": {"output": {"iban": "CH9300762011623852957", "amount": "118.40", "creditor": "ACME AG"}},
            "iban": {"output": {"ok": True}}, "acct": {"output": {"account": "6500", "confidence": 912}},
            "draft": {"output": {"id": "d1"}}})
add("run", "parallel-map-keeps-order", ["E6", "E13"], "a parallel map returns outputs in input order and orders audit entries by element index",
    lambda v: v["steps"][1]["output"] == [{"ok": True}, {"ok": False}, {"ok": True}]
    and entries(v) == ["mails:note", "each:note[0]", "each:note[1]", "each:note[2]", "sync"],
    plan=plan(MAILS, {"id": "each", "kind": "map", "capability": CAP + "iban.check", "over": ref("mails", "items"),
                      "bound": 8, "parallel": True, "args": {"iban": {"item": True, "field": "sender"}}}),
    script={"mails": {"output": THREE_MAILS},
            "each": {"elements": [{"output": {"ok": True}}, {"output": {"ok": False}}, {"output": {"ok": True}}]}})
# Additional vector beyond the 30 seeds.
add("run", "retry-writes-a-decision-per-attempt", ["E10"], "each attempt of an airlock step has its own durable decision, hence its own permit",
    lambda v: entries(v) == ["post:decision#1", "sync", "post:outcome#1", "post:decision#2", "sync", "post:outcome#2", "sync"]
    and states(post=("completed", None))(v),
    plan=plan(call("post", "ledger.post", {"account": lit("6500"), "amount": lit("118.40")}, retry=2)),
    script={"post": {"attempts": [{"state": "failed", "reason": "unavailable"}, {"output": {"id": "t1"}}]}})


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    total = 0
    for suite, vectors in VECTORS.items():
        doc = {"category": "plan", "description": DESCRIPTION[suite], "vectors": vectors}
        (OUT / f"{suite}.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        total += len(vectors)
        print(f"{suite}.json: {len(vectors)} vectors")
    print(f"{total} vectors written to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
