# APK reconstruction toolkit

Static analysis, faithful rebuild, and clean-slate reconstruction for Android
APKs. No Java required for the analysis half; JDK 17+ for the rebuild half.

> کوردی: [README.ku.md](README.ku.md)

| Tool                                 | What it answers                                        | Needs                         |
| ------------------------------------ | ------------------------------------------------------ | ----------------------------- |
| `apk_report.py`                      | What is inside this APK?                               | Python + androguard           |
| `rebuild_apk.ps1` / `rebuild_apk.sh` | Rebuild the APK from its decoded resources and sign it | JDK 17+, internet (first run) |
| `apk_verify.py`                      | Did the rebuild keep the same app?                     | Python + androguard           |
| `make_scaffold.py`                   | How do I build a similar app from scratch?             | Python (+ JDK only to build)  |

## Install (once)

```bash
python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install androguard
```

## 1. Report

```bash
python apk_report.py app.apk -o work/
```

Writes `work/app.report.json` and `work/app.report.md`: package, version, SDK
levels, signing certificates, permissions, exported components, DEX class
counts, top packages, detected SDKs, framework/runtime (Flutter, React Native,
Unity, .NET, Cordova…), native ABIs, hardening signals with the strings that
triggered them, and a round-trip risk estimate.

No APK is executed and nothing leaves the machine.

## 2. Rebuild

Windows:

```powershell
.\rebuild_apk.ps1 -Apk app.apk -OutDir work
```

macOS / Linux:

```bash
./rebuild_apk.sh app.apk -o work
```

The script resolves and downloads Apktool and uber-apk-signer on first use,
verifies the SHA-256 when the release publishes a digest, decodes the APK,
rebuilds it, zipaligns, and signs it with v1+v2+v3.

- Edit anything under `work/decoded/` first, then re-run with `-ReuseDecoded`
  (`--reuse`) to rebuild your edits.
- Bring your own key: `-Keystore my.jks -KsAlias mykey -StorePass … -KeyPass …`.
  Without one, a local `work/rebuilt.keystore` is generated.
- Result: `work/signed/rebuilt-signed.apk`.

A rebuild is **functionally faithful, never byte-identical**: `classes.dex` and
`resources.arsc` are recompiled, zip metadata changes, and the signature block
is regenerated with your key. That also means the rebuild installs _beside_ the
original app instead of updating it, and any signature/tamper check inside the
original will fail on the rebuild.

## 3. Verify

```bash
python apk_verify.py app.apk work/signed/rebuilt-signed.apk --json work/verify.json
```

Compares the zip entry inventory (CRC + size per entry), manifest facts
(package, version, SDK, permissions, components, launcher), signing schemes and
certificates, and DEX class parity. Verdict is one of `identical`,
`equivalent`, `diverged`; exit code 0 for the first two. DEX/resources bytes are
expected to differ — the report says so instead of hiding it.

## 4. Build a similar app

```bash
python make_scaffold.py app.apk -o new/
```

Generates a normal, buildable Kotlin/Gradle project with the original package
id, SDK levels, permissions and one stub screen per activity, plus `PARITY.md`
to track what still has to be implemented. It contains no decompiled code — it
is a clean starting point for rebuilding the behavior you verified.

```bash
cd new/<slug>
gradle wrapper --gradle-version 8.7
gradle :app:assembleDebug
```

## Pair with REA

Where [REA](https://rea.tools/) is installed, use `inspect_android_package` for
decoded sources and the Apktool family for resource tables before rebuilding;
this toolkit covers the container, the round trip, and the reconstruction
project around them. See `docs/android-analysis.md` and
`docs/apktool-resource-analysis.md` in the repository root.

## Scope

Use this on apps you own or are authorised to modify. A rebuild keeps the
original's assets, brand and code; publishing that as your own app is a
copyright problem even when the build succeeds. The scaffold path exists so a
new app can be built from understood behavior instead of copied files.
