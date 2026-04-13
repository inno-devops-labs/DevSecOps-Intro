$ErrorActionPreference = "Stop"

if (-not $env:DD_API) { throw "DD_API is not set" }
if (-not $env:DD_TOKEN) { throw "DD_TOKEN is not set" }
if (-not $env:DD_PRODUCT_TYPE) { throw "DD_PRODUCT_TYPE is not set" }
if (-not $env:DD_PRODUCT) { throw "DD_PRODUCT is not set" }
if (-not $env:DD_ENGAGEMENT) { throw "DD_ENGAGEMENT is not set" }

$OutDir = "labs\lab10\imports"
New-Item -ItemType Directory -Force $OutDir | Out-Null

function Import-DojoScan {
    param(
        [string]$Label,
        [string]$ScanType,
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        Write-Host "[skip] $Label : file not found -> $Path"
        return
    }

    $OutFile = Join-Path $OutDir "$Label.json"
    Write-Host "[*] Importing $Label ($ScanType) from $Path"

    $args = @(
        "-sS",
        "-o", $OutFile,
        "-w", "%{http_code}",
        "-X", "POST", "$env:DD_API/reimport-scan/",
        "-H", "Authorization: Token $env:DD_TOKEN",
        "-F", "scan_type=$ScanType",
        "-F", "minimum_severity=Info",
        "-F", "active=true",
        "-F", "verified=true",
        "-F", "close_old_findings=false",
        "-F", "auto_create_context=true",
        "-F", "product_type_name=$env:DD_PRODUCT_TYPE",
        "-F", "product_name=$env:DD_PRODUCT",
        "-F", "engagement_name=$env:DD_ENGAGEMENT",
        "-F", "test_title=$Label",
        "-F", "do_not_reactivate=false",
        "-F", "file=@$Path"
    )

    $httpCode = & curl.exe @args

    Write-Host "    HTTP $httpCode -> $OutFile"

    if ([int]$httpCode -lt 200 -or [int]$httpCode -ge 300) {
        Write-Host "[error] Import failed for $Label"
        Get-Content $OutFile
        throw "Import failed for $Label"
    }
}

Import-DojoScan -Label "zap"     -ScanType "ZAP Scan"            -Path "labs\lab5\zap\zap-report-noauth.json"
Import-DojoScan -Label "semgrep" -ScanType "Semgrep JSON Report" -Path "labs\lab5\semgrep\semgrep-results.json"
Import-DojoScan -Label "trivy"   -ScanType "Trivy Scan"          -Path "labs\lab4\trivy\trivy-vuln-detailed.json"
Import-DojoScan -Label "nuclei"  -ScanType "Nuclei"              -Path "labs\lab5\nuclei\nuclei-results.json"
Import-DojoScan -Label "grype"   -ScanType "Anchore Grype"       -Path "labs\lab4\syft\grype-vuln-results.json"

Write-Host ""
Write-Host "[done] Import responses saved under $OutDir"
