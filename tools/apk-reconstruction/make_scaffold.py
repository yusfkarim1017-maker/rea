#!/usr/bin/env python3
"""
make_scaffold.py — turn an APK (or an apk_report.py JSON) into a clean Android
project skeleton that mirrors the original app's visible structure.

It does **not** copy decompiled code. It creates a normal, buildable Gradle
project with the same package id, SDK levels, permissions and one stub screen
per original activity, plus a PARITY.md checklist for rebuilding behavior
feature by feature.

Usage:
    python make_scaffold.py app.apk -o out/
    python make_scaffold.py app.report.json -o out/ --name "My App"
    python make_scaffold.py app.apk -o out/ --package com.example.mine

Requires: androguard (for --from apk). Templates need Android Studio / AGP.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

FRAMEWORK_PREFIXES = ("android.", "androidx.", "com.google.", "kotlin.", "kotlinx.",
                      "java.", "javax.", "dalvik.")

AGP_VERSION = "8.5.2"
KOTLIN_VERSION = "2.0.20"
GRADLE_VERSION = "8.7"


def xml_escape(value: str) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "\\'"))


def kotlin_string(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def ident(value: str) -> str:
    cleaned = re.sub(r"[^0-9A-Za-z_]", "_", value)
    if not cleaned or cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned


def project_slug(package: str | None, fallback: str = "rebuiltapp") -> str:
    base = (package or fallback).split(".")[-1] or fallback
    slug = re.sub(r"[^a-z0-9]+", "", base.lower())
    return slug or fallback


def valid_package(package: str | None) -> str:
    if not package or not re.fullmatch(r"[a-zA-Z][\w]*(\.[a-zA-Z][\w]*)+", package):
        raise SystemExit(f"invalid package name: {package!r}")
    keywords = {"in", "is", "as", "class", "object", "fun", "val", "var", "package"}
    parts = []
    for part in package.split("."):
        if part.lower() in keywords:
            part = part + "app"
        parts.append(part)
    return ".".join(parts)


def load_report(source: str) -> dict:
    if source.lower().endswith(".json"):
        with open(source, encoding="utf-8") as fh:
            return json.load(fh)
    if not os.path.isfile(source):
        raise SystemExit(f"not found: {source}")
    from apk_report import collect  # local import keeps --json path dependency-free

    return collect(source)


def screen_list(report: dict) -> list[dict]:
    """Pick user-facing activities and give each a unique, valid class name."""
    activities = [a["name"] for a in report["components"]["activities"]]
    interesting = [a for a in activities if not a.startswith(FRAMEWORK_PREFIXES)]
    if not interesting:
        interesting = [a for a in activities]
    if not interesting:
        interesting = [report["manifest"].get("main_activity") or "MainActivity"]

    launcher = report["manifest"].get("main_activity")
    screens, used = [], {"MainActivity"}
    for full in interesting:
        simple = full.rstrip(";").split(".")[-1]
        simple = ident(re.sub(r"\$(.*)$", r"_\1", simple))
        if not simple.endswith("Activity"):
            simple += "Activity"
        if simple == "MainActivity" or full == launcher:
            continue
        candidate, n = simple, 2
        while candidate in used:
            candidate = f"{simple}{n}"
            n += 1
        used.add(candidate)
        screens.append({"original": full, "cls": candidate,
                        "layout": "activity_" + snake(candidate)})
    return screens


def snake(name: str) -> str:
    s = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    return re.sub(r"[^a-z0-9_]", "_", s)


def binding_name(layout: str) -> str:
    """View binding class for a layout file: activity_foo_bar -> ActivityFooBarBinding."""
    return "".join(part[:1].upper() + part[1:] for part in layout.split("_")) + "Binding"


def render_manifest(pkg: str, label: str, report: dict, screens: list[dict],
                    min_sdk: int, target_sdk: int) -> str:
    perms = "\n".join(f'    <uses-permission android:name="{xml_escape(p)}" />'
                      for p in report["permissions"]["requested"])
    features = ""
    if any("CAMERA" in p for p in report["permissions"]["requested"]):
        features = '    <uses-feature android:name="android.hardware.camera" android:required="false" />\n'
    activities = "\n".join(
        f"""        <activity
            android:name=".features.{s['cls']}"
            android:exported="false"
            android:label="{xml_escape(s['cls'])}" />""" for s in screens)

    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

{perms}
{features}
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:label="@string/app_name"
        android:supportsRtl="true"
        android:theme="@style/Theme.Rebuilt">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

{activities}
    </application>

</manifest>
"""


def render_app_gradle(pkg: str, min_sdk: int, target_sdk: int) -> str:
    compile_sdk = max(target_sdk, 34)
    return f"""plugins {{
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}}

android {{
    namespace = "{pkg}"
    compileSdk = {compile_sdk}

    defaultConfig {{
        applicationId = "{pkg}"
        minSdk = {min_sdk}
        targetSdk = {target_sdk}
        versionCode = 1
        versionName = "1.0"
    }}

    buildTypes {{
        release {{
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }}
    }}

    compileOptions {{
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }}

    kotlinOptions {{ jvmTarget = "17" }}
    buildFeatures {{ viewBinding = true }}
}}

dependencies {{
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
}}
"""


def render_root_gradle() -> str:
    return f"""plugins {{
    id("com.android.application") version "{AGP_VERSION}" apply false
    id("org.jetbrains.kotlin.android") version "{KOTLIN_VERSION}" apply false
}}
"""


def render_main_activity(pkg: str, screens: list[dict]) -> str:
    lines = []
    for index, screen in enumerate(screens):
        var = f"screen{index}Button"
        lines.append(f"""        val {var} = android.widget.Button(this)
        {var}.text = {kotlin_string(screen['cls'])}
        {var}.setOnClickListener {{
            startActivity(Intent(this, features.{screen['cls']}::class.java))
        }}
        binding.screenList.addView({var})""")
    buttons = "\n\n".join(lines) if lines else "        // TODO: add your first screen"

    return f"""package {pkg}

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import {pkg}.databinding.ActivityMainBinding

/**
 * Entry point of the rebuilt app.
 *
 * Each button opens a stub screen. Replace the stubs with behavior you verified
 * from the original app and track progress in PARITY.md.
 */
class MainActivity : AppCompatActivity() {{

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {{
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

{buttons}
    }}
}}
"""


def render_feature_activity(pkg: str, screen: dict) -> str:
    binding = binding_name(screen["layout"])
    return f"""package {pkg}.features

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import {pkg}.databinding.{binding}

/**
 * Stub for `{screen['original']}`.
 *
 * Rebuild here only the behavior you can explain from evidence.
 */
class {screen['cls']} : AppCompatActivity() {{

    private lateinit var binding: {binding}

    override fun onCreate(savedInstanceState: Bundle?) {{
        super.onCreate(savedInstanceState)
        binding = {binding}.inflate(layoutInflater)
        setContentView(binding.root)
        binding.title.text = {kotlin_string(screen['cls'])}
        // TODO: implement the screen
    }}
}}
"""


def render_activity_layout() -> str:
    return """<?xml version="1.0" encoding="utf-8"?>
<ScrollView xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:fillViewport="true">

    <LinearLayout
        android:id="@+id/screenList"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:orientation="vertical"
        android:padding="24dp">

        <TextView
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:text="@string/app_name"
            android:textAppearance="?attr/textAppearanceHeadlineSmall" />

        <TextView
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:layout_marginTop="8dp"
            android:text="@string/scaffold_note"
            android:textAppearance="?attr/textAppearanceBodyMedium" />
    </LinearLayout>
</ScrollView>
"""


def render_feature_layout(screen: dict) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="24dp">

    <TextView
        android:id="@+id/title"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:textAppearance="?attr/textAppearanceHeadlineSmall" />

    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_marginTop="12dp"
        android:text="{xml_escape('Original component: ' + screen['original'])}"
        android:textAppearance="?attr/textAppearanceBodySmall" />

    <!-- TODO: build the real screen here -->
</LinearLayout>
"""


def render_strings(app_name: str) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">{xml_escape(app_name)}</string>
    <string name="scaffold_note">Scaffold generated from an APK report. Each screen is a stub; implement behavior verified against the original app.</string>
</resources>
"""


def render_theme() -> tuple[str, str]:
    themes = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <style name="Theme.Rebuilt" parent="Theme.Material3.DayNight.NoActionBar">
        <item name="colorPrimary">@color/brand</item>
    </style>
</resources>
"""
    colors = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <color name="brand">#3F51B5</color>
    <color name="ic_launcher_background">#3F51B5</color>
</resources>
"""
    return themes, colors


def launcher_icon_files() -> list[tuple[str, str]]:
    foreground = """<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path
        android:fillColor="#FFFFFF"
        android:pathData="M34,34h40v40h-40z" />
</vector>
"""
    adaptive = """<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@color/ic_launcher_background" />
    <foreground android:drawable="@drawable/ic_launcher_foreground" />
</adaptive-icon>
"""
    legacy = """<?xml version="1.0" encoding="utf-8"?>
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path
        android:fillColor="#3F51B5"
        android:pathData="M0,0h108v108h-108z" />
    <path
        android:fillColor="#FFFFFF"
        android:pathData="M34,34h40v40h-40z" />
</vector>
"""
    return [
        ("drawable/ic_launcher_foreground.xml", foreground),
        ("mipmap-anydpi-v26/ic_launcher.xml", adaptive),
        ("mipmap-anydpi-v26/ic_launcher_round.xml", adaptive),
        ("mipmap-anydpi/ic_launcher.xml", legacy),
        ("mipmap-anydpi/ic_launcher_round.xml", legacy),
    ]


def render_parity(report: dict, screens: list[dict]) -> str:
    m = report["manifest"]
    rows = ["| Layer | Original | Status |", "| --- | --- | --- |"]
    rows.append(f"| Package | `{m.get('package')}` | copied |")
    rows.append(f"| Version | {m.get('version_name')} ({m.get('version_code')}) | copied |")
    rows.append(f"| SDK | min {m.get('min_sdk')} / target {m.get('target_sdk')} | copied |")
    rows.append(f"| Permissions | {len(report['permissions']['requested'])} | copied, re-check each |")
    for kind in ("activities", "services", "receivers", "providers"):
        count = len(report["components"][kind])
        rows.append(f"| {kind} | {count} | review |")
    rows.append("| Behavior | — | **not copied** — rebuild from evidence |")

    detail = []
    for s in screens:
        detail.append(f"- [ ] `{s['cls']}` ← `{s['original']}`")
    for svc in report["components"]["services"]:
        detail.append(f"- [ ] service `{svc['name']}`")
    for rec in report["components"]["receivers"]:
        detail.append(f"- [ ] receiver `{rec['name']}`")
    for prov in report["components"]["providers"]:
        detail.append(f"- [ ] provider `{prov['name']}`")

    fw = ", ".join(report["frameworks"]) or "none detected"
    hard = ", ".join(report["hardening"]) or "none detected"
    return f"""# Parity checklist

Original package: `{m.get('package')}`
Frameworks: {fw}
Hardening signals: {hard}

{chr(10).join(rows)}

## Work items

{chr(10).join(detail) if detail else '- [ ] main screen'}

## Rules that keep the rebuild honest

- Rebuild behavior, not bytes. Anything not observed should stay unknown.
- Server-side logic, keys and signing identity do not transfer.
- Test each item on a device before ticking it.
"""


def write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate an Android project skeleton from an APK")
    ap.add_argument("source", help="APK path or apk_report.py JSON")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--name", default=None, help="app display name")
    ap.add_argument("--package", default=None, help="override applicationId")
    ap.add_argument("--min-sdk", type=int, default=None)
    ap.add_argument("--target-sdk", type=int, default=None)
    args = ap.parse_args()

    report = load_report(args.source)
    m = report["manifest"]
    pkg = valid_package(args.package or m.get("package") or "com.example.rebuilt")
    app_name = args.name or m.get("app_name") or pkg.split(".")[-1].title()
    min_sdk = args.min_sdk or int(m.get("min_sdk") or 24)
    target_sdk = args.target_sdk or int(m.get("target_sdk") or max(min_sdk, 34))
    if target_sdk < min_sdk:
        target_sdk = min_sdk

    root = os.path.join(args.out, project_slug(pkg))
    pkg_path = os.path.join(root, "app", "src", "main", "java", *pkg.split("."))
    screens = screen_list(report)

    write(os.path.join(root, "settings.gradle.kts"),
          'rootProject.name = "%s"\ninclude(":app")\n' % project_slug(pkg))
    write(os.path.join(root, "build.gradle.kts"), render_root_gradle())
    write(os.path.join(root, "gradle.properties"),
          "org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8\nandroid.useAndroidX=true\n"
          "kotlin.code.style=official\n")
    write(os.path.join(root, "gradle", "wrapper", "gradle-wrapper.properties"),
          f"distributionUrl=https\\://services.gradle.org/distributions/gradle-{GRADLE_VERSION}-bin.zip\n"
          "distributionPath=wrapper/dists\nnetworkTimeout=10000\nvalidateDistributionUrl=true\n"
          "zipStoreBase=GRADLE_USER_HOME\nzipStorePath=wrapper/dists\n")
    write(os.path.join(root, ".gitignore"),
          "*.iml\n.gradle\nlocal.properties\n.idea\nbuild\ncaptures\n.externalNativeBuild\n.cxx\n")

    write(os.path.join(root, "app", "build.gradle.kts"),
          render_app_gradle(pkg, min_sdk, target_sdk))
    write(os.path.join(root, "app", "proguard-rules.pro"), "# Add keep rules only when you see a real problem.\n")
    write(os.path.join(root, "app", "src", "main", "AndroidManifest.xml"),
          render_manifest(pkg, app_name, report, screens, min_sdk, target_sdk))

    write(os.path.join(pkg_path, "MainActivity.kt"), render_main_activity(pkg, screens))
    for s in screens:
        write(os.path.join(pkg_path, "features", s["cls"] + ".kt"),
              render_feature_activity(pkg, s))
        write(os.path.join(root, "app", "src", "main", "res", "layout", s["layout"] + ".xml"),
              render_feature_layout(s))

    res = os.path.join(root, "app", "src", "main", "res")
    write(os.path.join(res, "layout", "activity_main.xml"), render_activity_layout())
    write(os.path.join(res, "values", "strings.xml"), render_strings(app_name))
    themes, colors = render_theme()
    write(os.path.join(res, "values", "themes.xml"), themes)
    write(os.path.join(res, "values", "colors.xml"), colors)
    for rel, content in launcher_icon_files():
        write(os.path.join(res, rel), content)

    write(os.path.join(root, "PARITY.md"), render_parity(report, screens))
    write(os.path.join(root, "README.md"), f"""# {app_name} (reconstruction scaffold)

Generated from `{os.path.basename(str(args.source))}` by `make_scaffold.py`.

- package: `{pkg}`
- SDK: min {min_sdk} / target {target_sdk}
- screens: {len(screens) + 1} (MainActivity + {len(screens)} stubs)

## Build

```bash
# Android Studio: File > Open > this folder (it supplies the Gradle wrapper)
# or with a local Gradle + JDK 17:
gradle wrapper --gradle-version {GRADLE_VERSION}
gradle :app:assembleDebug
```

The APK lands in `app/build/outputs/apk/debug/app-debug.apk`.

## Continue

1. Open `PARITY.md` and tick items as you reproduce them.
2. Keep every implemented behavior traceable to evidence from the original app.
3. Do not ship the original app's assets, brand or signing key.
""")

    print(f"scaffold -> {os.path.abspath(root)}")
    print(f"  package : {pkg}")
    print(f"  screens : {len(screens)} stub + MainActivity")
    print(f"  parity  : {os.path.join(root, 'PARITY.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
