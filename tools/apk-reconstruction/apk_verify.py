#!/usr/bin/env python3
"""
apk_verify.py — compare an original APK with a rebuilt / re-signed APK.

Answers one question with evidence: "did the rebuild keep the same app, or did
something change?"

Usage:
    python apk_verify.py original.apk rebuilt.apk
    python apk_verify.py original.apk rebuilt.apk --json out.json
    python apk_verify.py original.apk rebuilt.apk --skip-code   (fast, no DEX parse)

Exit codes: 0 = equivalent (see verdict), 1 = diverged, 2 = bad usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from collections import Counter

os.environ.setdefault("LOGURU_LEVEL", "ERROR")
try:
    from loguru import logger

    logger.remove()
except Exception:  # pragma: no cover
    pass

from androguard.core.apk import APK  # noqa: E402

SIGNATURE_ENTRY = re.compile(r"^META-INF/(?:[^/]+\.(?:SF|RSA|DSA|EC)|MANIFEST\.MF)$")

CATEGORY_RULES = [
    ("signature", lambda n: bool(SIGNATURE_ENTRY.match(n))),
    ("code", lambda n: bool(re.fullmatch(r"classes\d*\.dex", n))),
    ("resources", lambda n: n.startswith("res/") or n == "resources.arsc"),
    ("native", lambda n: n.startswith("lib/")),
    ("assets", lambda n: n.startswith("assets/")),
    ("manifest", lambda n: n == "AndroidManifest.xml"),
]


def category(name: str) -> str:
    for label, test in CATEGORY_RULES:
        if test(name):
            return label
    return "other"


def entry_index(path: str) -> dict[str, dict]:
    index: dict[str, dict] = {}
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            index[info.filename] = {"crc": info.CRC, "size": info.file_size,
                                    "compressed": info.compress_size,
                                    "method": info.compress_type}
    return index


def diff_entries(orig: dict, new: dict) -> dict:
    added = sorted(set(new) - set(orig))
    removed = sorted(set(orig) - set(new))
    changed = sorted(n for n in set(orig) & set(new)
                     if (orig[n]["crc"], orig[n]["size"]) != (new[n]["crc"], new[n]["size"]))
    identical = len(orig) - len(removed) - len(changed)

    def group(names: list[str]) -> dict[str, int]:
        return dict(Counter(category(n) for n in names))

    return {
        "identical_entries": identical,
        "changed": changed,
        "added": added,
        "removed": removed,
        "changed_by_category": group(changed),
        "added_by_category": group(added),
        "removed_by_category": group(removed),
    }


def manifest_facts(path: str) -> dict:
    a = APK(path)
    return {
        "package": a.get_package(),
        "app_name": a.get_app_name(),
        "version_name": a.get_androidversion_name(),
        "version_code": a.get_androidversion_code(),
        "min_sdk": a.get_min_sdk_version(),
        "target_sdk": a.get_target_sdk_version(),
        "main_activity": a.get_main_activity(),
        "permissions": sorted(a.get_permissions() or []),
        "activities": sorted(a.get_activities() or []),
        "services": sorted(a.get_services() or []),
        "receivers": sorted(a.get_receivers() or []),
        "providers": sorted(a.get_providers() or []),
    }


def signing_facts(path: str) -> dict:
    a = APK(path)
    certs = {}
    for scheme, getter in (("v1", a.get_certificates_v1),
                           ("v2", a.get_certificates_v2),
                           ("v3", a.get_certificates_v3)):
        try:
            found = getter() or []
        except Exception:
            found = []
        digests = []
        for c in found:
            try:
                digests.append(str(c.sha256_fingerprint).replace(" ", "").lower())
            except Exception:
                digests.append("unreadable")
        if digests:
            certs[scheme] = sorted(set(digests))
    return {"schemes": sorted(certs), "certificates": certs}


def dex_classes(path: str, limit_files: int = 24) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    with zipfile.ZipFile(path) as zf:
        names = [n for n in zf.namelist() if re.fullmatch(r"classes\d*\.dex", n)]
        names.sort(key=lambda n: (len(n), n))
        from androguard.core.dex import DEX as DexFile

        for name in names[:limit_files]:
            try:
                d = DexFile(zf.read(name))
                result[name] = {c.get_name() for c in d.get_classes()}
            except Exception as exc:  # noqa: BLE001
                result[name] = {f"<error {type(exc).__name__}>"}
    return result


def compare_code(orig_path: str, new_path: str) -> dict:
    o = dex_classes(orig_path)
    n = dex_classes(new_path)
    o_all = set().union(*o.values()) if o else set()
    n_all = set().union(*n.values()) if n else set()
    missing = sorted(o_all - n_all)
    extra = sorted(n_all - o_all)
    return {
        "original_classes": len(o_all),
        "rebuilt_classes": len(n_all),
        "original_files": {k: len(v) for k, v in o.items()},
        "rebuilt_files": {k: len(v) for k, v in n.items()},
        "missing_classes": missing[:200],
        "missing_count": len(missing),
        "extra_count": len(extra),
        "class_parity": (1 - len(missing) / len(o_all)) if o_all else None,
    }


def facts_diff(before: dict, after: dict) -> dict:
    out = {}
    for key in before:
        if key == "permissions":
            added = sorted(set(after[key]) - set(before[key]))
            removed = sorted(set(before[key]) - set(after[key]))
            if added or removed:
                out[key] = {"added": added, "removed": removed}
            continue
        if isinstance(before[key], list):
            a, b = set(before[key]), set(after.get(key) or [])
            if a != b:
                out[key] = {"added": sorted(b - a), "removed": sorted(a - b)}
            continue
        if before[key] != after.get(key):
            out[key] = {"before": before[key], "after": after.get(key)}
    return out


def verdict(entry_diff: dict, manifest_diff: dict, code: dict | None,
            orig_sig: dict, new_sig: dict) -> dict:
    """Classify the rebuild from container, manifest and code evidence."""
    non_signature_changed = {k: v for k, v in entry_diff["changed_by_category"].items()
                             if k != "signature"}
    removed = dict(entry_diff["removed_by_category"])
    added = dict(entry_diff["added_by_category"])
    removed_signature_only = set(removed) <= {"signature"}
    added_clean = set(added) <= {"signature"}
    signature_entries_changed = bool(entry_diff["changed_by_category"].get("signature"))
    code_ok = code is None or not code.get("missing_count")

    reasons = []
    if manifest_diff:
        reasons.append("manifest facts differ: " + ", ".join(sorted(manifest_diff)))
    if code is not None and code.get("missing_count"):
        reasons.append(f"{code['missing_count']} original classes missing from rebuilt DEX")
    if non_signature_changed:
        reasons.append("changed non-signature entries: " + ", ".join(
            f"{k}={v}" for k, v in sorted(non_signature_changed.items())))
    if not removed_signature_only:
        reasons.append("removed entries: " + ", ".join(
            f"{k}={v}" for k, v in sorted(removed.items())))
    if not added_clean:
        reasons.append("added entries: " + ", ".join(
            f"{k}={v}" for k, v in sorted(added.items())))

    if not reasons and not signature_entries_changed:
        level, label = "identical", "byte-identical container"
    elif not reasons:
        level, label = "equivalent", "same app semantics; recompiled bytes"
    else:
        level, label = "diverged", "semantics changed — review the differences"

    return {
        "level": level,
        "label": label,
        "exit_ok": level in {"identical", "equivalent"},
        "reasons": reasons,
        "signature_changed": orig_sig["certificates"] != new_sig["certificates"],
        "note": ("DEX and resources.arsc are recompiled, so their bytes normally differ. "
                 "Equal manifest facts, equal entry inventory and full class parity are "
                 "evidence of a faithful rebuild — not proof of identical runtime behavior, "
                 "which still needs device testing."),
    }


def summarize(report: dict) -> str:
    d, v = report["entry_diff"], report["verdict"]
    lines = [
        f"original : {report['original']['path']}",
        f"rebuilt  : {report['rebuilt']['path']}",
        "",
        f"VERDICT  : {v['level'].upper()} — {v['label']}",
        "",
        f"entries  : {d['identical_entries']} identical, {len(d['changed'])} changed, "
        f"{len(d['added'])} added, {len(d['removed'])} removed",
    ]
    if d["changed_by_category"]:
        lines.append("changed  : " + ", ".join(f"{k}={n}" for k, n in d["changed_by_category"].items()))
    if d["added_by_category"]:
        lines.append("added    : " + ", ".join(f"{k}={n}" for k, n in d["added_by_category"].items()))
    if d["removed_by_category"]:
        lines.append("removed  : " + ", ".join(f"{k}={n}" for k, n in d["removed_by_category"].items()))

    m = report["manifest_diff"]
    lines += ["", "manifest : " + ("unchanged" if not m else "CHANGED")]
    for key, val in m.items():
        lines.append(f"  - {key}: {json.dumps(val, ensure_ascii=False)[:300]}")

    sig = report["signing"]
    lines += ["", f"signing  : original {sig['original']['schemes'] or 'unsigned'} → "
                  f"rebuilt {sig['rebuilt']['schemes'] or 'unsigned'}"]
    if v["signature_changed"]:
        lines.append("  - certificate identity changed (expected when signing with your own key)")

    code = report.get("code")
    if code:
        parity = code["class_parity"]
        lines += ["", f"code     : {code['original_classes']} classes original, "
                      f"{code['rebuilt_classes']} rebuilt, "
                      f"parity {'n/a' if parity is None else f'{parity:.2%}'}"]
        for name in code["missing_classes"][:10]:
            lines.append(f"  - missing {name}")

    if v["reasons"]:
        lines += ["", "why not equivalent:"] + [f"  - {r}" for r in v["reasons"]]
    lines += ["", f"note     : {v['note']}", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare original and rebuilt APKs")
    ap.add_argument("original")
    ap.add_argument("rebuilt")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--skip-code", action="store_true", help="skip DEX class comparison")
    args = ap.parse_args()

    for path in (args.original, args.rebuilt):
        if not os.path.isfile(path):
            print(f"not found: {path}", file=sys.stderr)
            return 2

    def sha(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    report = {
        "original": {"path": os.path.abspath(args.original), "sha256": sha(args.original)},
        "rebuilt": {"path": os.path.abspath(args.rebuilt), "sha256": sha(args.rebuilt)},
        "entry_diff": diff_entries(entry_index(args.original), entry_index(args.rebuilt)),
        "manifest": {},
        "manifest_diff": {},
        "signing": {},
        "code": None,
    }

    orig_facts, new_facts = manifest_facts(args.original), manifest_facts(args.rebuilt)
    report["manifest"] = {"original": orig_facts, "rebuilt": new_facts}
    report["manifest_diff"] = facts_diff(orig_facts, new_facts)

    sig_o, sig_n = signing_facts(args.original), signing_facts(args.rebuilt)
    report["signing"] = {"original": sig_o, "rebuilt": sig_n}

    if not args.skip_code:
        try:
            report["code"] = compare_code(args.original, args.rebuilt)
        except Exception as exc:  # noqa: BLE001
            report["code"] = {"error": f"{type(exc).__name__}: {exc}",
                              "missing_count": 0, "class_parity": None}

    report["verdict"] = verdict(report["entry_diff"], report["manifest_diff"],
                                report["code"], sig_o, sig_n)

    text = summarize(report)
    print(text)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        print(f"json -> {args.json_out}")
    return 0 if report["verdict"]["exit_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
