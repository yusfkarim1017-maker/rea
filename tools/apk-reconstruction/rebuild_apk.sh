#!/usr/bin/env bash
# Rebuild an APK on macOS/Linux — decode, rebuild, align, sign, verify.
#
# Usage:
#   ./rebuild_apk.sh app.apk
#   ./rebuild_apk.sh app.apk -o work -k my.jks -a mykey -p storepass -P keypass
#   ./rebuild_apk.sh app.apk --no-sign
#
# Requirements: JDK 17+ (java, keytool), curl, python3, internet on first run.

set -euo pipefail

APK=""
OUT_DIR="./rebuild-out"
TOOLS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/apk-reconstruction/tools"
KEYSTORE=""
ALIAS="rebuilt"
STORE_PASS=""
KEY_PASS=""
DO_SIGN=1
DO_VERIFY=1
REUSE=0

say() { printf '\033[36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m!!  %s\033[0m\n' "$*" >&2; }
die() { printf '\033[31mXX  %s\033[0m\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out) OUT_DIR="$2"; shift 2 ;;
    -k|--keystore) KEYSTORE="$2"; shift 2 ;;
    -a|--alias) ALIAS="$2"; shift 2 ;;
    -p|--storepass) STORE_PASS="$2"; shift 2 ;;
    -P|--keypass) KEY_PASS="$2"; shift 2 ;;
    --reuse) REUSE=1; shift ;;
    --no-sign) DO_SIGN=0; shift ;;
    --no-verify) DO_VERIFY=0; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) APK="$1"; shift ;;
  esac
done

[[ -n "$APK" && -f "$APK" ]] || die "APK not found: ${APK:-<none>}"
APK="$(cd "$(dirname "$APK")" && pwd)/$(basename "$APK")"
mkdir -p "$OUT_DIR" "$TOOLS_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

command -v java >/dev/null || die "Java not found. Install a JDK 17+ (Adoptium, SDKMAN, apt install openjdk-17-jdk)."
JAVA_MAJOR="$(java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1)"
[[ -n "$JAVA_MAJOR" ]] || die "Could not read the Java version."
(( JAVA_MAJOR >= 17 )) || die "Java $JAVA_MAJOR is too old; JDK 17+ is required."
say "Java $JAVA_MAJOR OK"
command -v python3 >/dev/null || die "python3 is required (used for downloads and verification)."

fetch_latest_jar() { # repo pattern target
  local repo="$1" pattern="$2" target="$3" dest="$TOOLS_DIR/$3"
  if [[ -f "$dest" ]]; then printf '%s\n' "$dest"; return 0; fi
  say "Downloading $target (first run only)" >&2
  local url
  url="$(curl -fsSL -H 'User-Agent: apk-reconstruction' \
        "https://api.github.com/repos/$repo/releases/latest" |
        python3 -c '
import json,sys,re
pat = re.compile(sys.argv[1])
rel = json.load(sys.stdin)
for a in rel.get("assets", []):
    if pat.search(a["name"]):
        print(a["browser_download_url"]); break
' "^${pattern}$")"
  [[ -n "$url" ]] || { echo "No asset matching $pattern in the latest $repo release." >&2; exit 1; }
  curl -fsSL --retry 3 -o "$dest.part" "$url" || { echo "download failed: $url" >&2; exit 1; }
  mv "$dest.part" "$dest"
  printf '%s\n' "$dest"
}

APKTOOL="$(fetch_latest_jar iBotPeaches/Apktool 'apktool_.*\.jar' apktool.jar)"
say "Apktool: $APKTOOL"
SIGNER=""
if (( DO_SIGN )); then
  SIGNER="$(fetch_latest_jar patrickfav/uber-apk-signer 'uber-apk-signer-.*\.jar' uber-apk-signer.jar)"
  say "Signer : $SIGNER"
fi

DECODED="$OUT_DIR/decoded"
if (( REUSE )) && [[ -d "$DECODED" ]]; then
  say "Reusing existing decode: $DECODED"
else
  rm -rf "$DECODED"
  say "Decoding (apktool d)"
  if ! java -jar "$APKTOOL" d -f --use-aapt2 -o "$DECODED" "$APK"; then
    warn "Decode with --use-aapt2 failed; retrying without it."
    rm -rf "$DECODED"
    java -jar "$APKTOOL" d -f -o "$DECODED" "$APK" || die "Apktool could not decode this APK."
  fi
  say "Decoded to $DECODED — edit files there, then re-run with --reuse"
fi

UNSIGNED="$OUT_DIR/rebuilt-unsigned.apk"
say "Building (apktool b)"
java -jar "$APKTOOL" b "$DECODED" -o "$UNSIGNED" || die "Apktool build failed (check the errors above)."
[[ -f "$UNSIGNED" ]] || die "Apktool reported success but produced no APK."
say "Unsigned APK: $UNSIGNED"

FINAL="$UNSIGNED"
if (( DO_SIGN )); then
  if [[ -z "$KEYSTORE" ]]; then
    KEYSTORE="$OUT_DIR/rebuilt.keystore"
    if [[ ! -f "$KEYSTORE" ]]; then
      STORE_PASS="${STORE_PASS:-rebuilt123}"
      KEY_PASS="${KEY_PASS:-$STORE_PASS}"
      say "Creating a local signing key: $KEYSTORE (alias $ALIAS)"
      keytool -genkeypair -noprompt -keystore "$KEYSTORE" -alias "$ALIAS" \
        -storepass "$STORE_PASS" -keypass "$KEY_PASS" -keyalg RSA -keysize 2048 \
        -validity 10000 -dname "CN=Rebuilt App, O=Local Build, C=IQ" >/dev/null
    fi
  fi
  [[ -n "$STORE_PASS" ]] || die "Keystore password required (-p) when an existing keystore is used."
  KEY_PASS="${KEY_PASS:-$STORE_PASS}"

  say "Aligning + signing (v1/v2/v3)"
  mkdir -p "$OUT_DIR/signed"
  java -jar "$SIGNER" --apks "$UNSIGNED" --ks "$KEYSTORE" --ksAlias "$ALIAS" \
    --ksPass "$STORE_PASS" --ksKeyPass "$KEY_PASS" \
    --out "$OUT_DIR/signed" --fileName "rebuilt-signed.apk" --overwrite \
    || die "Signing failed (check the alias and passwords)."
  FINAL="$OUT_DIR/signed/rebuilt-signed.apk"
  [[ -f "$FINAL" ]] || FINAL="$(find "$OUT_DIR/signed" -name '*signed*.apk' | head -1)"
  [[ -f "$FINAL" ]] || die "Signer finished but produced no signed APK."
fi

say "Result: $FINAL"
warn "The rebuild uses YOUR key: it installs beside the original and cannot update it."

if (( DO_VERIFY )); then
  if python3 -c 'import androguard' >/dev/null 2>&1; then
    say "Comparing original and rebuilt APK"
    python3 "$(dirname "$0")/apk_verify.py" "$APK" "$FINAL" | tee "$OUT_DIR/verify.txt" || true
    say "Verify log: $OUT_DIR/verify.txt"
  else
    warn "androguard not installed; skipping structural comparison (pip install androguard)."
  fi
fi
