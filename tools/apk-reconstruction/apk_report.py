#!/usr/bin/env python3
"""
apk_report.py — static APK/XAPK reconnaissance report (JSON + Markdown).

Built for the REA workspace: gives an agent the facts it needs before deciding
how an app is built and how a *similar* app would be reconstructed.

Usage:
    python apk_report.py path/to/app.apk [-o outdir]
    python apk_report.py app.apk --json-only

No network, no Java, no SDK required. Pure static reading of the container.
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
from datetime import datetime, timezone

os.environ.setdefault("LOGURU_LEVEL", "ERROR")

try:
    from loguru import logger

    logger.remove()
except Exception:  # pragma: no cover
    pass

from androguard.core.apk import APK  # noqa: E402

MAX_DEX_BYTES = 220 * 1024 * 1024

KNOWN_FRAMEWORKS = {
    "Flutter": [r"libflutter\.so", r"libapp\.so", r"flutter_assets/"],
    "React Native": [r"libreactnativejni\.so", r"libhermes\.so", r"index\.android\.bundle"],
    "Unity": [r"libunity\.so", r"libil2cpp\.so", r"unity\.default"],
    "Unreal": [r"libUE4\.so", r"libUnreal\.so"],
    "Cordova/Ionic": [r"assets/www/", r"cordova\.js"],
    "Capacitor": [r"assets/public/", r"capacitor\.config"],
    "Expo": [r"assets/.*\.(hbc|js)$"],
    "Xamarin/.NET": [r"libmonodroid\.so", r"libxamarin-app\.so", r"assemblies/"],
    "Godot": [r"libgodot_android\.so", r"assets/.*\.pck$"],
    "Cocos2d": [r"libcocos2d"],
    "Native (JNI)": [r"lib/arm64-v8a/.*\.so"],
}

SDK_HINTS = {
    "Firebase": r"com/google/firebase|com/google/android/gms",
    "Google Play Services": r"com/google/android/gms",
    "AdMob": r"com/google/android/gms/ads",
    "Facebook SDK": r"com/facebook/",
    "AppsFlyer": r"com/appsflyer/",
    "Adjust": r"com/adjust/sdk",
    "OneSignal": r"com/onesignal/",
    "Amplitude": r"com/amplitude/",
    "Sentry": r"io/sentry/",
    "Crashlytics": r"com/google/firebase/crashlytics",
    "Stripe": r"com/stripe/android",
    "PayPal": r"com/paypal/",
    "RevenueCat": r"com/revenuecat/",
    "Supabase": r"io/supabase/",
    "OkHttp": r"okhttp3/",
    "Retrofit": r"retrofit2/",
    "Room": r"androidx/room/",
    "Hilt/Dagger": r"dagger/|javax/inject/",
    "Kotlin coroutines": r"kotlinx/coroutines/",
    "Jetpack Compose": r"androidx/compose/",
    "ExoPlayer": r"androidx/media3/|com/google/android/exoplayer",
    "WebView": r"android/webkit/WebView",
    "Realm": r"io/realm/",
    "SQLCipher": r"net/sqlcipher/",
}

HARDENING_HINTS = {
    "Play Integrity / SafetyNet": r"(?i)playintegrity|safetynet|attestation",
    "Root detection": r"(?i)superuser\.apk|/system/xbin/su|magisk|supersu",
    "Emulator detection": r"(?i)isemulator|generic_x86|goldfish|qemu",
    "Frida/Xposed detection": r"(?i)frida-server|frida-gadget|xposedbridge|libsubstrate",
    "Signature / tamper check": r"(?i)getpackagesignatures|signature.?mismatch|tamper.?detect",
    "Dynamic code loading": r"(?i)dexclassloader|inmemorydexclassloader",
    "Packer (360 / jiagu / tencent)": r"(?i)libjiagu|stubapp|libshella",
    "Native anti-debug": r"(?i)ptrace|anti.?debug",
    "Certificate pinning": r"(?i)certificatepinner|okhttp3/certificatepinner",
}


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe(fn, default=None):
    try:
        value = fn()
        return default if value is None else value
    except Exception:
        return default


def name_str(name) -> str:
    """Render an asn1crypto/cryptography Name as one line."""
    if name is None:
        return ""
    for attr in ("rfc4514_string", "human_friendly"):
        value = getattr(name, attr, None)
        if value is None:
            continue
        try:
            return value() if callable(value) else str(value)
        except Exception:
            continue
    try:
        return ", ".join(f"{k}={v}" for k, v in name.native.items())
    except Exception:
        return str(name)


def collect(path: str) -> dict:
    a = APK(path, raw=False)
    zf = zipfile.ZipFile(path)
    names = zf.namelist()
    sizes = {n: zf.getinfo(n).file_size for n in names}

    dex_names = sorted([n for n in names if re.fullmatch(r"classes\d*\.dex", n)],
                       key=lambda n: (len(n), n))
    native_libs = sorted({n for n in names if n.startswith("lib/") and n.endswith(".so")})
    abis = sorted({n.split("/")[1] for n in native_libs if len(n.split("/")) > 2})

    report: dict = {"file": {}, "signing": {}, "manifest": {}, "components": {},
                    "permissions": {}, "dex": {}, "native": {}, "frameworks": {},
                    "sdks": {}, "hardening": {}, "reconstruction": {}}

    report["file"] = {
        "path": os.path.abspath(path),
        "size_bytes": os.path.getsize(path),
        "sha256": sha256(path),
        "entries": len(names),
        "is_split_apk": safe(lambda: a.is_split(), False),
        "split_names": safe(lambda: a.get_split_names(), []),
        "dex_files": dex_names,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    # ---------- signing ----------
    certs = []
    for label, fn in (("v1", a.get_certificates_v1), ("v2", a.get_certificates_v2),
                      ("v3", a.get_certificates_v3)):
        for c in safe(fn, []) or []:
            certs.append({
                "scheme": label,
                "subject": name_str(c.subject),
                "issuer": name_str(c.issuer),
                "not_valid_before": str(safe(lambda c=c: c.not_valid_before_utc, None)
                                         or safe(lambda c=c: c.not_valid_before, "")),
                "not_valid_after": str(safe(lambda c=c: c.not_valid_after_utc, None)
                                        or safe(lambda c=c: c.not_valid_after, "")),
                "sha256": str(safe(lambda c=c: c.sha256_fingerprint.replace(" ", "").lower(), "")),
                "self_signed": safe(lambda c=c: bool(c.self_signed), None),
            })
    report["signing"] = {
        "signed": bool(certs),
        "schemes": sorted({c["scheme"] for c in certs}),
        "certificates": certs,
    }

    # ---------- manifest ----------
    report["manifest"] = {
        "package": safe(a.get_package),
        "app_name": safe(a.get_app_name),
        "version_name": safe(a.get_androidversion_name),
        "version_code": safe(a.get_androidversion_code),
        "min_sdk": safe(a.get_min_sdk_version),
        "target_sdk": safe(a.get_target_sdk_version),
        "effective_target_sdk": safe(a.get_effective_target_sdk_version),
        "max_sdk": safe(a.get_max_sdk_version),
        "main_activity": safe(a.get_main_activity),
        "activities_count": len(safe(a.get_activities, [])),
        "services_count": len(safe(a.get_services, [])),
        "receivers_count": len(safe(a.get_receivers, [])),
        "providers_count": len(safe(a.get_providers, [])),
        "debuggable": safe(a.get_attribute_value("application", "debuggable")),
        "allow_backup": safe(a.get_attribute_value("application", "allowBackup")),
        "uses_cleartext_traffic": safe(a.get_attribute_value("application", "usesCleartextTraffic")),
        "network_security_config": safe(a.get_attribute_value("application", "networkSecurityConfig")),
        "extract_native_libs": safe(a.get_attribute_value("application", "extractNativeLibs")),
        "app_component_factory": safe(a.get_attribute_value("application", "appComponentFactory")),
        "manifest_sha256": hashlib.sha256(zf.read("AndroidManifest.xml")).hexdigest()
        if "AndroidManifest.xml" in names else None,
    }

    # ---------- components ----------
    for kind, getter in (("activities", a.get_activities), ("services", a.get_services),
                         ("receivers", a.get_receivers), ("providers", a.get_providers)):
        rows = []
        for name in safe(getter, []) or []:
            row = {"name": name,
                   "exported": safe(lambda n=name: a.get_attribute_value(kind[:-1], "exported", name)),
                   "permission": safe(lambda n=name: a.get_attribute_value(kind[:-1], "permission", name))}
            if kind == "activities":
                row["intent_filters"] = safe(lambda n=name: a.get_intent_filters("activity", n), {})
            rows.append(row)
        report["components"][kind] = rows

    # ---------- permissions ----------
    report["permissions"] = {
        "requested": sorted(safe(a.get_permissions, []) or []),
        "declared": sorted(safe(a.get_declared_permissions, []) or []),
        "dangerous_guess": sorted(p for p in (safe(a.get_permissions, []) or [])
                                  if p.split(".")[-1] in {
                                      "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
                                      "ACCESS_COARSE_LOCATION", "READ_CONTACTS", "READ_SMS",
                                      "READ_PHONE_STATE", "CALL_PHONE", "READ_EXTERNAL_STORAGE",
                                      "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
                                      "QUERY_ALL_PACKAGES", "POST_NOTIFICATIONS"}),
    }

    # ---------- dex ----------
    dex_stats = []
    all_classes: list[str] = []
    all_strings: list[str] = []
    for dn in dex_names:
        info = zf.getinfo(dn)
        entry = {"name": dn, "size": info.file_size}
        if info.file_size <= MAX_DEX_BYTES:
            try:
                raw = zf.read(dn)
                entry["magic"] = raw[:4].hex()
                from androguard.core.dex import DEX as DexFile
                d = DexFile(raw)
                classes = [c.get_name() for c in d.get_classes()]
                all_classes.extend(classes)
                entry["classes"] = len(classes)
                entry["methods"] = safe(lambda d=d: len(d.get_methods()), 0)
                entry["strings"] = safe(lambda d=d: len(d.get_strings()), 0)
                if len(all_strings) < 400000:
                    all_strings.extend(safe(lambda d=d: d.get_strings(), [])[:200000])
            except Exception as exc:  # noqa: BLE001
                entry["error"] = f"{type(exc).__name__}: {exc}"
        dex_stats.append(entry)

    packages = Counter(".".join(c.strip("L;").split("/")[:3]) for c in all_classes)
    report["dex"] = {
        "files": dex_stats,
        "total_classes": len(all_classes),
        "top_packages": packages.most_common(40),
        "obfuscation_guess": sum(1 for c in all_classes
                                 if re.search(r"/[a-z]{1,3}(/[a-z]{1,3}){0,2};?$", c)) / len(all_classes)
        if all_classes else None,
        "class_list_sample": all_classes[:200],
    }

    # ---------- native / assets ----------
    report["native"] = {"abis": abis, "libs": native_libs[:200],
                        "total_so": len(native_libs)}

    # ---------- framework / sdk detection ----------
    joined = "\n".join(names)
    fw = {}
    for label, pats in KNOWN_FRAMEWORKS.items():
        hits = [p for p in pats if re.search(p, joined)]
        if hits:
            fw[label] = hits
    report["frameworks"] = fw

    class_blob = "\n".join(all_classes)
    sdks = {label: True for label, pat in SDK_HINTS.items() if re.search(pat, class_blob)}
    report["sdks"] = sorted(sdks)

    string_blob = "\n".join(all_strings[:200000])

    def evidence(pattern: str) -> list[str]:
        found = []
        for blob, kind in ((class_blob, "class"), (string_blob, "string")):
            for match in re.finditer(pattern, blob):
                token = blob[max(0, match.start() - 0): match.end() + 40].splitlines()[0]
                found.append(f"{kind}: {token.strip()[:120]}")
                if len(found) >= 4:
                    return found
        return found

    hard = {}
    for label, pat in HARDENING_HINTS.items():
        hits = evidence(pat)
        if hits:
            hard[label] = hits
    if any(re.search(r"(?i)libjiagu|libshella", n) for n in names):
        hard.setdefault("Packer (360 / jiagu / tencent)", []).append("asset: native packer library")
    report["hardening"] = hard

    # ---------- reconstruction hints ----------
    report["reconstruction"] = {
        "screens_guess": [r["name"] for r in report["components"]["activities"]
                          if not r["name"].startswith(("android.", "androidx.", "com.google."))][:60],
        "asset_count": sum(1 for n in names if n.startswith("assets/")),
        "res_file_count": sum(1 for n in names if n.startswith("res/")),
        "resource_arsc": "resources.arsc" in names,
        "round_trip_risk": _risk(report),
    }
    return report


def _risk(rep: dict) -> dict:
    reasons = []
    if rep["hardening"]:
        reasons.append("hardening/tamper signals present")
    if rep["manifest"].get("app_component_factory"):
        reasons.append("custom appComponentFactory (possible packer/protection)")
    if any("jiagu" in l.lower() for l in rep["native"].get("libs", [])):
        reasons.append("known packer library")
    if rep["file"].get("is_split_apk"):
        reasons.append("split/base APK — needs sibling config splits")
    if rep["frameworks"]:
        reasons.append("cross-platform runtime: source of truth is not the DEX")
    return {
        "level": "high" if len(reasons) >= 3 else "medium" if reasons else "low",
        "reasons": reasons,
        "byte_identical_rebuild_possible": False,
        "note": "A rebuild can be functionally near-identical, never byte-identical: "
                "the signature block is regenerated and zip metadata changes.",
    }


def to_markdown(r: dict) -> str:
    m, f = r["manifest"], r["file"]
    lines = [
        f"# APK report — {m.get('package') or '?'}",
        "",
        f"- **File**: `{os.path.basename(f['path'])}` ({f['size_bytes'] / 1048576:.2f} MB, {f['entries']} entries)",
        f"- **SHA-256**: `{f['sha256']}`",
        f"- **App**: {m.get('app_name') or '?'} · v{m.get('version_name')} ({m.get('version_code')})",
        f"- **SDK**: min {m.get('min_sdk')} · target {m.get('target_sdk')} · effective {m.get('effective_target_sdk')}",
        f"- **Main activity**: `{m.get('main_activity')}`",
        f"- **Signed**: {r['signing']['signed']} · schemes {', '.join(r['signing']['schemes']) or '—'}",
        f"- **Split APK**: {f['is_split_apk']}",
        "",
        "## Frameworks",
    ]
    lines += [f"- {k}: `{', '.join(v)}`" for k, v in r["frameworks"].items()] or ["- (none detected)"]
    lines += ["", "## Signing"]
    for c in r["signing"]["certificates"] or []:
        lines.append(f"- [{c['scheme']}] {c['subject']}  \n  sha256 `{c['sha256']}`  \n  valid {c['not_valid_before']} → {c['not_valid_after']}")
    if not r["signing"]["certificates"]:
        lines.append("- none / unsigned")

    lines += ["", f"## Permissions ({len(r['permissions']['requested'])})"]
    lines += [f"- `{p}`" for p in r["permissions"]["requested"]] or ["- none"]

    lines += ["", "## Components"]
    for kind in ("activities", "services", "receivers", "providers"):
        rows = r["components"][kind]
        exported = [x["name"] for x in rows if str(x.get("exported")).lower() == "true"]
        lines.append(f"- **{kind}** ({len(rows)}), exported: {len(exported)}")
        for name in exported[:15]:
            lines.append(f"  - exported `{name}`")

    lines += ["", "## Code"]
    lines.append(f"- DEX files: {', '.join(d['name'] for d in r['dex']['files']) or 'none'}")
    lines.append(f"- Classes: {r['dex']['total_classes']}")
    for d in r["dex"]["files"]:
        lines.append(f"  - `{d['name']}`: {d.get('classes', '?')} classes, {d.get('methods', '?')} methods")
    lines += ["", "Top packages:", "```"]
    lines += [f"{c:>6}  {p}" for p, c in r["dex"]["top_packages"][:20]]
    lines += ["```"]
    if r["sdks"]:
        lines += ["", "## SDKs", *[f"- {s}" for s in r["sdks"]]]
    if r["hardening"]:
        lines += ["", "## Hardening / anti-tamper signals", *[f"- {k}" for k in r["hardening"]]]
    lines += ["", "## Native", f"- ABIs: {', '.join(r['native']['abis']) or '—'} ({r['native']['total_so']} .so files)"]

    rr = r["reconstruction"]
    lines += ["", "## Reconstruction view",
              f"- Risk: **{rr['round_trip_risk']['level']}** — {', '.join(rr['round_trip_risk']['reasons']) or 'no blockers detected'}",
              f"- resources.arsc: {rr['resource_arsc']} · res files: {rr['res_file_count']} · assets: {rr['asset_count']}",
              "- Screens (non-framework activities):"]
    lines += [f"  - `{s}`" for s in rr["screens_guess"][:30]] or ["  - none"]
    lines += ["", f"> {rr['round_trip_risk']['note']}", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Static APK report (JSON + Markdown)")
    ap.add_argument("apk")
    ap.add_argument("-o", "--out", default=None, help="output directory")
    ap.add_argument("--json-only", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.apk):
        print(f"not found: {args.apk}", file=sys.stderr)
        return 2

    outdir = args.out or os.path.join(os.path.dirname(os.path.abspath(args.apk)), "report")
    os.makedirs(outdir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(args.apk))[0]

    rep = collect(args.apk)
    jpath = os.path.join(outdir, f"{stem}.report.json")
    with open(jpath, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2, ensure_ascii=False)
    print(f"json  -> {jpath}")

    if not args.json_only:
        mpath = os.path.join(outdir, f"{stem}.report.md")
        with open(mpath, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(rep))
        print(f"md    -> {mpath}")
        print()
        print(to_markdown(rep)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
