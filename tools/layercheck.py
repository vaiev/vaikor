#!/usr/bin/env python3
"""layercheck: enforce runtime/layers.toml against `cargo metadata`.

Usage:
    python3 tools/layercheck.py runtime/layers.toml            # check, exit 1 on mismatch
    python3 tools/layercheck.py runtime/layers.toml --suggest  # print missing [[exception]] blocks
    python3 tools/layercheck.py runtime/layers.toml --wasm32   # print crates CI must build for wasm32
    python3 tools/layercheck.py runtime/layers.toml --metadata FILE   # use a saved metadata JSON

Rules (ids as in the Runde-2 document):
    C1  every workspace member is in exactly one layer
    C2  normal/build edge A -> B only if B is in a lower layer or listed in [[same_layer]]
    C3  target-conditional dependencies count like any other (nothing is filtered by target)
    C4  dev edge A -> B must not point to a higher layer
    C5  no crate from deny_crates in the normal-dependency closure of a layer crate
    C6  no feature from deny_features enabled by a layer crate's own dependency declaration
    C7  forbid_unsafe: `#![forbid(unsafe_code)]` is in the crate's lib root
    C8  the set of violations equals the set of [[exception]] entries (both directions)
    C9  [seal].symbol occurs only in files listed in allowed_in

Standard library only (tomllib needs Python 3.11+). No third-party imports.

Known limits, on purpose:
    C5 uses the workspace-wide resolve graph. Cargo unifies features across the workspace,
       so an optional dependency switched on by a higher crate can show up here. That makes
       C5 conservative: it can report too much, never too little.
    C6 looks at what the layer crate itself declares (features plus default features).
       A feature switched on only by a transitive dependency is not attributed to the crate.
    C9 is a text search, not a name resolution. Keep the sealed symbol's name unique.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tomllib

KINDS = ("edge", "dev-edge", "crate", "feature", "unsafe", "seal", "unassigned")


def load_metadata(manifest: pathlib.Path, saved: str | None) -> dict:
    if saved:
        return json.loads(pathlib.Path(saved).read_text(encoding="utf-8"))
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked",
         "--manifest-path", str(manifest)],
        check=True, capture_output=True, text=True,
    )
    return json.loads(out.stdout)


def key(kind: str, **fields: str) -> tuple:
    """Canonical identity of a violation or an exception."""
    if kind in ("edge", "dev-edge"):
        return (kind, fields["from"], fields["to"])
    if kind == "crate":
        return (kind, fields["crate"], fields["denied"])
    if kind == "feature":
        return (kind, fields["crate"], fields["feature"])
    if kind in ("unsafe", "unassigned"):
        return (kind, fields["crate"])
    if kind == "seal":
        return (kind, fields["file"])
    raise ValueError(f"unknown kind {kind!r}")


def as_toml(k: tuple) -> str:
    names = {
        "edge": ("from", "to"), "dev-edge": ("from", "to"),
        "crate": ("crate", "denied"), "feature": ("crate", "feature"),
        "unsafe": ("crate",), "unassigned": ("crate",), "seal": ("file",),
    }[k[0]]
    lines = ["[[exception]]", f'kind = "{k[0]}"']
    lines += [f'{n} = "{v}"' for n, v in zip(names, k[1:])]
    lines.append('removed_by = "TODO"')
    return "\n".join(lines)


def expand_features(pkg: dict, wanted: list[str], use_default: bool) -> set[str]:
    """Features of `pkg` that a dependency declaration switches on, transitively."""
    table = pkg.get("features", {})
    todo = list(wanted) + (["default"] if use_default else [])
    seen: set[str] = set()
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        for sub in table.get(f, []):
            # "dep:x" and "x/y" entries name other packages; only plain names are ours.
            if not sub.startswith("dep:") and "/" not in sub:
                todo.append(sub)
    return seen


def check(cfg: dict, meta: dict, root: pathlib.Path) -> tuple[set[tuple], list[str]]:
    """Return (violations, config errors). Config errors are never excusable."""
    errors: list[str] = []
    by_id = {p["id"]: p for p in meta["packages"]}
    members = {by_id[i]["name"]: by_id[i] for i in meta["workspace_members"]}

    order = cfg["order"]
    rank: dict[str, int] = {}
    layer_of: dict[str, str] = {}
    for lname, layer in cfg.get("layer", {}).items():
        if lname not in order:
            errors.append(f"layer {lname} is not in `order`")
            continue
        for crate in layer.get("crates", []):
            if crate in layer_of:
                errors.append(f"{crate} is in two layers: {layer_of[crate]} and {lname}")
            layer_of[crate] = lname
            rank[crate] = order.index(lname)
    for crate in layer_of:
        if crate not in members:
            errors.append(f"{crate} is in layers.toml but not a workspace member")

    found: set[tuple] = set()

    # C1
    for crate in members:
        if crate not in layer_of:
            found.add(key("unassigned", crate=crate))

    same = {(s["from"], s["to"]) for s in cfg.get("same_layer", [])}

    # C2, C3, C4: nothing is filtered by `target`, which is the whole point of C3.
    for crate, pkg in members.items():
        if crate not in rank:
            continue
        for dep in pkg["dependencies"]:
            to = dep["name"]
            if to not in members or to not in rank or to == crate:
                continue
            if dep["kind"] == "dev":
                if rank[to] > rank[crate]:
                    found.add(key("dev-edge", **{"from": crate, "to": to}))
            elif rank[to] > rank[crate] or (rank[to] == rank[crate] and (crate, to) not in same):
                found.add(key("edge", **{"from": crate, "to": to}))

    # C5: closure over normal dependencies in the resolve graph.
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

    def closure(pkg_id: str) -> set[str]:
        seen, todo = set(), [pkg_id]
        while todo:
            cur = todo.pop()
            for dep in nodes[cur]["deps"]:
                # Only what ends up in the built crate: skip dev and build dependencies.
                if all(k["kind"] in ("dev", "build") for k in dep["dep_kinds"]):
                    continue
                if dep["pkg"] not in seen:
                    seen.add(dep["pkg"])
                    todo.append(dep["pkg"])
        return seen

    for crate, pkg in members.items():
        layer = cfg["layer"].get(layer_of.get(crate, ""), {})
        denied = set(layer.get("deny_crates", []))
        if denied:
            for name in sorted({by_id[i]["name"] for i in closure(pkg["id"])} & denied):
                found.add(key("crate", crate=crate, denied=name))

        # C6
        by_name = {p["name"]: p for p in meta["packages"]}
        for spec in layer.get("deny_features", []):
            dep_name, feature = spec.split("/", 1)
            for dep in pkg["dependencies"]:
                if dep["name"] != dep_name or dep["kind"] == "dev":
                    continue
                target = by_name.get(dep_name)
                if target and feature in expand_features(
                        target, dep.get("features", []), dep.get("uses_default_features", True)):
                    found.add(key("feature", crate=crate, feature=spec))

        # C7
        if layer.get("forbid_unsafe"):
            libs = [t["src_path"] for t in pkg["targets"] if "lib" in t["kind"]]
            text = "".join(pathlib.Path(p).read_text(encoding="utf-8") for p in libs)
            if "#![forbid(unsafe_code)]" not in text:
                found.add(key("unsafe", crate=crate))

    # C9
    seal = cfg.get("seal")
    if seal:
        allowed = {(root / a).resolve() for a in seal.get("allowed_in", [])}
        for pkg in members.values():
            src = pathlib.Path(pkg["manifest_path"]).parent / "src"
            for path in sorted(src.rglob("*.rs")):
                if seal["symbol"] in path.read_text(encoding="utf-8") and path.resolve() not in allowed:
                    found.add(key("seal", file=str(path.resolve().relative_to(root.resolve()))))

    return found, errors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("layers", type=pathlib.Path)
    ap.add_argument("--metadata", help="saved `cargo metadata` JSON instead of running cargo")
    ap.add_argument("--suggest", action="store_true", help="print missing [[exception]] blocks")
    ap.add_argument("--wasm32", action="store_true", help="print crates of layers with wasm32 = true")
    args = ap.parse_args()

    cfg = tomllib.loads(args.layers.read_text(encoding="utf-8"))
    if cfg.get("version") != 1:
        print("layercheck: layers.toml must say version = 1", file=sys.stderr)
        return 2
    root = args.layers.resolve().parent

    if args.wasm32:
        for lname in cfg["order"]:
            layer = cfg.get("layer", {}).get(lname, {})
            if layer.get("wasm32"):
                print("\n".join(layer.get("crates", [])))
        return 0

    meta = load_metadata(root / cfg.get("manifest", "Cargo.toml"), args.metadata)
    found, errors = check(cfg, meta, root)

    excused: set[tuple] = set()
    for exc in cfg.get("exception", []):
        fields = {k: v for k, v in exc.items() if k not in ("kind", "removed_by", "reason")}
        if exc.get("kind") not in KINDS:
            errors.append(f"exception with unknown kind: {exc}")
            continue
        if not exc.get("removed_by"):
            errors.append(f"exception without removed_by: {exc}")
        try:
            excused.add(key(exc["kind"], **fields))
        except KeyError as missing:
            errors.append(f"exception lacks field {missing}: {exc}")

    new = sorted(found - excused)        # C8, first direction
    stale = sorted(excused - found)      # C8, second direction: the ratchet

    if args.suggest:
        print("\n\n".join(as_toml(k) for k in new))
        return 0

    for e in errors:
        print(f"config error: {e}")
    for k in new:
        print(f"violation without exception: {' '.join(k)}")
    for k in stale:
        print(f"exception without violation (delete it): {' '.join(k)}")
    ok = not (errors or new or stale)
    print(f"layercheck: {'ok' if ok else 'FAILED'} "
          f"({len(found)} known violations, {len(new)} new, {len(stale)} stale)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
