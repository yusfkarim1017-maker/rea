# Rebuild an APK on Windows — decode, rebuild, align, sign, verify.
#
# Usage:
#   .\rebuild_apk.ps1 -Apk C:\path\app.apk
#   .\rebuild_apk.ps1 -Apk app.apk -Keystore my.jks -KsAlias mykey -StorePass pass -KeyPass pass
#   .\rebuild_apk.ps1 -Apk app.apk -OutDir .\work -NoSign
#
# Requirements: JDK 17+ on PATH (or -JavaHome), internet for the first run
# (downloads Apktool + uber-apk-signer into the tools folder).
#
# Output: <OutDir>\rebuilt-signed.apk + <OutDir>\verify.txt

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Apk,
    [string]$OutDir = ".\rebuild-out",
    [string]$ToolsDir = "",
    [string]$JavaHome = "",
    [string]$Keystore = "",
    [string]$KsAlias = "rebuilt",
    [string]$StorePass = "",
    [string]$KeyPass = "",
    [switch]$ReuseDecoded,
    [switch]$NoSign,
    [switch]$NoVerify
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "!!  $msg" -ForegroundColor Yellow }
function Die($msg) { Write-Host "XX  $msg" -ForegroundColor Red; exit 1 }

if (-not (Test-Path -LiteralPath $Apk)) { Die "APK not found: $Apk" }
$Apk = (Resolve-Path -LiteralPath $Apk).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path

if (-not $ToolsDir) {
    $ToolsDir = Join-Path $env:LOCALAPPDATA "apk-reconstruction\tools"
}
New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

# ---------------------------------------------------------------- Java
$java = "java"
if ($JavaHome) { $java = Join-Path $JavaHome "bin\java.exe" }
try {
    $javaVersion = (& $java -version 2>&1 | Out-String)
} catch {
    Die "Java not found. Install a JDK 17+ (https://adoptium.net) and reopen the terminal."
}
if ($javaVersion -notmatch 'version "(\d+)') { Die "Could not read the Java version. Output: $javaVersion" }
$major = [int]$Matches[1]
if ($major -lt 17) { Die "Java $major is too old. Apktool and apksigner need JDK 17+." }
Say "Java $major OK ($java)"

# ---------------------------------------------------------------- tools
function Get-LatestJar {
    param([string]$Repo, [string]$Pattern, [string]$TargetName)

    $dest = Join-Path $ToolsDir $TargetName
    if (Test-Path -LiteralPath $dest) { return $dest }

    Say "Downloading $TargetName (first run only)"
    $headers = @{ "User-Agent" = "apk-reconstruction" }
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
    $asset = $release.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
    if (-not $asset) { Die "No asset matching $Pattern in the latest $Repo release." }

    $tmp = "$dest.download"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tmp -Headers $headers
    if ($asset.digest -and $asset.digest -match '^sha256:(.+)$') {
        $expected = $Matches[1].ToLower()
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash.ToLower()
        if ($actual -ne $expected) {
            Remove-Item -LiteralPath $tmp -Force
            Die "SHA-256 mismatch for $($asset.name): expected $expected, got $actual"
        }
        Say "SHA-256 verified against the GitHub release digest"
    }
    Move-Item -LiteralPath $tmp -Destination $dest -Force
    return $dest
}

$apktool = Get-LatestJar -Repo "iBotPeaches/Apktool" -Pattern '^apktool_.*\.jar$' -TargetName "apktool.jar"
Say "Apktool: $apktool"

$signer = $null
if (-not $NoSign) {
    $signer = Get-LatestJar -Repo "patrickfav/uber-apk-signer" -Pattern '^uber-apk-signer-.*\.jar$' -TargetName "uber-apk-signer.jar"
    Say "Signer : $signer"
}

# ---------------------------------------------------------------- decode
$decoded = Join-Path $OutDir "decoded"
if ($ReuseDecoded -and (Test-Path -LiteralPath $decoded)) {
    Say "Reusing existing decode: $decoded"
} else {
    if (Test-Path -LiteralPath $decoded) { Remove-Item -LiteralPath $decoded -Recurse -Force }
    Say "Decoding (apktool d)"
    & $java -jar $apktool d -f --use-aapt2 -o $decoded $Apk
    if ($LASTEXITCODE -ne 0) {
        Warn "Decode with --use-aapt2 failed. Retrying without it."
        if (Test-Path -LiteralPath $decoded) { Remove-Item -LiteralPath $decoded -Recurse -Force }
        & $java -jar $apktool d -f -o $decoded $Apk
        if ($LASTEXITCODE -ne 0) { Die "Apktool could not decode this APK (see the errors above)." }
    }
    Say "Decoded to $decoded"
    Write-Host "    Edit files there, then re-run with -ReuseDecoded to rebuild them."
}

# ---------------------------------------------------------------- build
$unsigned = Join-Path $OutDir "rebuilt-unsigned.apk"
Say "Building (apktool b)"
& $java -jar $apktool b $decoded -o $unsigned
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $unsigned)) {
    Die "Apktool build failed. Common causes: missing framework resources, aapt2 version mismatch, or an edited XML that no longer parses."
}
Say "Unsigned APK: $unsigned"

$final = $unsigned
if (-not $NoSign) {
    # ------------------------------------------------------------ keystore
    if (-not $Keystore) {
        $Keystore = Join-Path $OutDir "rebuilt.keystore"
        if (-not (Test-Path -LiteralPath $Keystore)) {
            if (-not $StorePass) { $StorePass = "rebuilt123" }
            if (-not $KeyPass) { $KeyPass = $StorePass }
            $keytool = "keytool"
            if ($JavaHome) { $keytool = Join-Path $JavaHome "bin\keytool.exe" }
            Say "Creating a local signing key: $Keystore (alias $KsAlias)"
            & $keytool -genkeypair -noprompt -keystore $Keystore -alias $KsAlias `
                -storepass $StorePass -keypass $KeyPass -keyalg RSA -keysize 2048 `
                -validity 10000 -dname "CN=Rebuilt App, O=Local Build, C=IQ"
            if ($LASTEXITCODE -ne 0) { Die "keytool failed to create a keystore." }
        }
    } else {
        $Keystore = (Resolve-Path -LiteralPath $Keystore).Path
    }
    if (-not $StorePass) { $StorePass = Read-Host "Keystore password" -AsSecureString | ConvertFrom-SecureString -AsPlainText }
    if (-not $KeyPass) { $KeyPass = $StorePass }

    # ------------------------------------------------------------ sign
    Say "Aligning + signing (v1/v2/v3)"
    $signOut = Join-Path $OutDir "signed"
    New-Item -ItemType Directory -Force -Path $signOut | Out-Null
    & $java -jar $signer --apks $unsigned --ks $Keystore --ksAlias $KsAlias `
        --ksPass $StorePass --ksKeyPass $KeyPass --out $signOut --fileName "rebuilt-signed.apk" --overwrite
    if ($LASTEXITCODE -ne 0) { Die "Signing failed (check keystore alias and passwords)." }

    $final = Join-Path $signOut "rebuilt-signed.apk"
    if (-not (Test-Path -LiteralPath $final)) {
        $candidate = Get-ChildItem -Path $signOut -Filter "*signed*.apk" | Select-Object -First 1
        if ($candidate) { $final = $candidate.FullName } else { Die "Signer finished but no signed APK was produced." }
    }
}

Say "Result: $final"
Write-Host ""
Write-Host "Reminder: the rebuild carries YOUR key, so it installs beside the original" -ForegroundColor Yellow
Write-Host "and cannot update it. Keep the original app's assets and brand out of any release." -ForegroundColor Yellow

# ---------------------------------------------------------------- verify
if (-not $NoVerify -and -not $NoSign) {
    $hasPython = Get-Command python -ErrorAction SilentlyContinue
    if ($hasPython) {
        $script = Join-Path $PSScriptRoot "apk_verify.py"
        if (Test-Path -LiteralPath $script) {
            Say "Comparing original and rebuilt APK"
            $log = Join-Path $OutDir "verify.txt"
            & python $script $Apk $final | Tee-Object -FilePath $log
            Write-Host ""
            Write-Host "Verify log: $log"
        }
    } else {
        Warn "Python not found — skipping the structural comparison (install Python + androguard to enable it)."
    }
}
