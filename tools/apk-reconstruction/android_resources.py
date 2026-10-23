#!/usr/bin/env python3
"""
android_resources.py — inventory and extract Android `res/` trees.

Works on:
  * a Gradle/Android Studio project (one or many modules, any number of res dirs)
  * a directory decoded by apktool (`res/` + `values/` already plain XML)

It answers "what shared resources does this app have?" without building it:
counts by type, every string/color/dimen/style declaration, the layout and
drawable inventory, and which module owns each one.

Usage:
    python android_resources.py <project-root> -o out/
    python android_resources.py . -o out/ --copy-shared      # copy common/ resources
    python android_resources.py . -o out/ --module main      # only app/src/main/res

Outputs: <out>/resources.json, <out>/resources.md, and with --copy-shared
<out>/shared-res/<module>/<type>/...
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict

RES_DIR_NAMES = ("res",)
VALUE_DIR = re.compile(r"^values(-[A-Za-z0-9+\-]+)?$")
RES_TYPE = re.compile(r"^([a-z][a-z0-9]*)(-[A-Za-z0-9+\-]+)*$")

# Resource file extensions that are real content, not build noise.
CONTENT_EXT = {".xml", ".png", ".webp", ".jpg", ".jpeg", ".gif", ".svg",
               ".9.png", ".ttf", ".otf", ".ttc", ".mp3", ".ogg", ".wav",
               ".json", ".html", ".txt"}

SHARED_MARKERS = ("/common/", "/shared/", "/core/", "/ui/", "/base/")


def iter_res_dirs(root: str, only_module: str | None) -> list[str]:
    found = []
    for dirpath, dirnames, _ in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "build", ".gradle",
                                                        ".idea", "node_modules"}]
        base = os.path.basename(dirpath)
        if base in RES_DIR_NAMES and os.path.isdir(dirpath):
            rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
            if only_module and only_module not in rel:
                continue
            found.append(dirpath)
    return sorted(found)


def module_of(root: str, res_dir: str) -> str:
    rel = os.path.relpath(res_dir, root).replace(os.sep, "/")
    parts = [p for p in rel.split("/") if p]
    if "src" in parts:
        idx = parts.index("src")
        return "/".join(parts[:idx]) or "."
    return "/".join(parts[:-1]) or "."


def is_shared(module: str) -> bool:
    token = f"/{module.strip('/')}/"
    return any(marker in token for marker in SHARED_MARKERS) or module.startswith("common")


def file_kind(path: str, type_dir: str) -> str:
    name = os.path.basename(path)
    if name.endswith(".9.png"):
        return "nine-patch"
    ext = os.path.splitext(name)[1].lower()
    if type_dir.startswith("drawable"):
        return "vector" if ext == ".xml" else "bitmap"
    return ext.lstrip(".") or "unknown"


def parse_values(path: str) -> dict[str, list[dict]]:
    """Return {tag: [{name, value, extra}]} for one values XML file."""
    out: dict[str, list[dict]] = defaultdict(list)
    try:
        root = ET.parse(path).getroot()
    except Exception as exc:  # noqa: BLE001
        out["_parse_error"].append({"file": path, "error": f"{type(exc).__name__}: {exc}"})
        return out
    for node in root:
        tag = node.tag
        if not isinstance(tag, str):
            continue
        name = node.get("name") or ""
        entry = {"name": name, "file": os.path.relpath(path)}
        text = (node.text or "").strip()
        if text:
            entry["value"] = text[:400]
        for attr in ("type", "parent", "translatable", "formatted", "quantity"):
            if node.get(attr) is not None:
                entry[attr] = node.get(attr)
        if tag in {"plurals", "string-array", "integer-array", "array"}:
            entry["items"] = [(item.text or "").strip()[:120] for item in node]
            entry["count"] = len(entry["items"])
        out[tag].append(entry)
    return out


def collect(root: str, only_module: str | None) -> dict:
    res_dirs = iter_res_dirs(root, only_module)
    if not res_dirs:
        raise SystemExit(f"no res/ directory found under {root}")

    report = {
        "root": os.path.abspath(root),
        "res_directories": [],
        "values": defaultdict(lambda: defaultdict(list)),
        "modules": {},
        "totals": Counter(),
    }

    for res_dir in res_dirs:
        module = module_of(root, res_dir)
        rel_res = os.path.relpath(res_dir, root).replace(os.sep, "/")
        info = {"module": module, "path": rel_res, "shared": is_shared(module),
                "types": Counter(), "bytes": 0, "files": 0, "kinds": Counter()}
        report["res_directories"].append(info)

        for dirpath, dirnames, filenames in os.walk(res_dir):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            type_dir = os.path.basename(dirpath)
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                if "__MACOSX" in path:
                    continue
                size = os.path.getsize(path)
                info["files"] += 1
                info["bytes"] += size
                report["totals"]["files"] += 1
                report["totals"]["bytes"] += size

                if VALUE_DIR.match(type_dir):
                    info["types"]["values" if type_dir == "values" else "values-" + type_dir[7:]] += 1
                    for tag, entries in parse_values(path).items():
                        for entry in entries:
                            entry["module"] = module
                            entry["qualifier"] = "" if type_dir == "values" else type_dir[7:]
                            report["values"][tag][entry["name"]].append(entry)
                    continue

                match = RES_TYPE.match(type_dir)
                kind = match.group(1) if match else type_dir
                qualifier = type_dir[len(kind):].lstrip("-") if match else ""
                info["types"][f"{kind} ({qualifier})" if qualifier else kind] += 1
                info["kinds"][file_kind(path, kind)] += 1
                report["totals"][kind] += 1

    report["values"] = {tag: dict(names) for tag, names in report["values"].items()}
    for key in list(report["values"]):
        report["values"][key] = dict(sorted(report["values"][key].items()))
    return report


def uniq(values: list[dict]) -> list[dict]:
    seen, out = set(), []
    for entry in values:
        key = (entry.get("value"), entry.get("qualifier"))
        if key in seen:
            continue
        seen.add(key)
        out.append(entry)
    return out


def md_report(rep: dict, root: str) -> str:
    vals = rep["values"]
    modules = sorted({d["module"] for d in rep["res_directories"]})
    shared = sorted({d["module"] for d in rep["res_directories"] if d["shared"]})

    lines = [
        "# Android resource inventory",
        "",
        f"- project: `{rep['root']}`",
        f"- res directories: {len(rep['res_directories'])}",
        f"- modules: {', '.join(f'`{m}`' for m in modules)}",
        f"- shared modules: {', '.join(f'`{m}`' for m in shared) or 'none detected'}",
        f"- files: {rep['totals']['files']} · {rep['totals']['bytes'] / 1048576:.2f} MB",
        "",
        "## Counts by type",
        "",
        "| type | files |",
        "| --- | --- |",
    ]
    totals = rep["totals"]
    for key, count in sorted(((k, v) for k, v in totals.items() if k not in {"files", "bytes"}),
                             key=lambda kv: -kv[1]):
        lines.append(f"| {key} | {count} |")

    lines += ["", "## Declared values", "", "| element | declared | unique names |",
              "| --- | --- | --- |"]
    for tag in sorted(vals, key=lambda t: -len(vals[t])):
        count = sum(len(v) for v in vals[tag].values())
        lines.append(f"| `{tag}` | {count} | {len(vals[tag])} |")

    for tag in ("string", "color", "dimen", "style", "bool", "integer", "array",
                "string-array", "integer-array", "plurals", "attr", "item"):
        if tag not in vals:
            continue
        names = vals[tag]
        lines += ["", f"## {tag} ({len(names)} names)"]
        if tag == "string":
            translated = sum(1 for v in names.values() if len(v) > 1)
            lines.append(f"- translated in more than one qualifier: {translated}")
            lines.append("")
            lines.append("| name | value | module |")
            lines.append("| --- | --- | --- |")
            for name, entries in list(names.items())[:120]:
                first = entries[0]
                value = (first.get("value") or "").replace("|", "\\|")[:90]
                lines.append(f"| `{name}` | {value} | `{first.get('module')}` |")
            if len(names) > 120:
                lines.append(f"| … | {len(names) - 120} more in resources.json | |")
        elif tag in {"color", "dimen", "bool", "integer"}:
            for name, entries in list(names.items())[:80]:
                values = ", ".join(f"`{e.get('value')}`" for e in uniq(entries)[:4])
                lines.append(f"- `{name}` = {values}")
            if len(names) > 80:
                lines.append(f"- … {len(names) - 80} more in resources.json")
        else:
            for name, entries in list(names.items())[:60]:
                extra = f" (parent `{entries[0].get('parent')}`)" if entries[0].get("parent") else ""
                lines.append(f"- `{name}`{extra} — `{entries[0].get('module')}`")
            if len(names) > 60:
                lines.append(f"- … {len(names) - 60} more in resources.json")

    lines += ["", "## Modules", "", "| module | shared | files | size | top types |",
              "| --- | --- | --- | --- | --- |"]
    for info in sorted(rep["res_directories"], key=lambda d: (d["module"], d["path"])):
        top = ", ".join(f"{k}={v}" for k, v in info["types"].most_common(5))
        lines.append(f"| `{info['module']}` | {'yes' if info['shared'] else ''} | "
                     f"{info['files']} | {info['bytes'] / 1024:.0f} KB | {top} |")

    lines += ["", "## Drawable content", ""]
    kinds = Counter()
    for info in rep["res_directories"]:
        kinds.update(info["kinds"])
    for kind, count in kinds.most_common():
        lines.append(f"- {kind}: {count}")

    lines.append("")
    return "\n".join(lines)


def copy_shared(rep: dict, out_dir: str, root: str) -> int:
    """Copy res trees of shared modules into out_dir/shared-res/<module>/."""
    copied = 0
    dest_base = os.path.join(out_dir, "shared-res")
    for info in rep["res_directories"]:
        if not info["shared"]:
            continue
        src_res = os.path.join(root, info["path"])
        dest = os.path.join(dest_base, info["module"].replace("/", "__"), "res")
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        shutil.copytree(src_res, dest)
        copied += 1
    return copied


def main() -> int:
    ap = argparse.ArgumentParser(description="Inventory and extract Android res/ trees")
    ap.add_argument("root")
    ap.add_argument("-o", "--out", default="resource-out")
    ap.add_argument("--module", default=None, help="substring filter on the res path")
    ap.add_argument("--copy-shared", action="store_true",
                    help="copy res/ trees of common/shared modules into the output")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    rep = collect(root, args.module)
    rep["totals"] = dict(rep["totals"])
    os.makedirs(args.out, exist_ok=True)

    jpath = os.path.join(args.out, "resources.json")
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2, ensure_ascii=False)

    mpath = os.path.join(args.out, "resources.md")
    with open(mpath, "w", encoding="utf-8") as fh:
        fh.write(md_report(rep, root))

    print(f"json -> {jpath}")
    print(f"md   -> {mpath}")
    print(f"res dirs: {len(rep['res_directories'])} · files: {rep['totals']['files']} · "
          f"{rep['totals']['bytes'] / 1048576:.2f} MB")
    for tag, names in sorted(rep["values"].items(), key=lambda kv: -len(kv[1]))[:10]:
        print(f"  {tag:<14} {len(names)} names")

    if args.copy_shared:
        count = copy_shared(rep, args.out, root)
        print(f"copied {count} shared res tree(s) -> {os.path.join(args.out, 'shared-res')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
