$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = if ($ScriptDir -match "labs\\lab10\\imports") { Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $ScriptDir)) } else { Get-Location }

function Resolve-ProjectPath {
    param($RelativePath)
    $Full = Join-Path $ProjectRoot $RelativePath
    if (Test-Path $Full) { return $Full }
    return $null
}

$DD_API = if ($env:DD_API) { $env:DD_API } else { "http://localhost:8080/api/v2" }
$DD_TOKEN = if ($env:DD_TOKEN) { $env:DD_TOKEN } else { "268519587e3e68b8447c691da729289cbbd6995a" }

if (-not $DD_TOKEN) {
    Write-Error "DD_TOKEN environment variable is required."
    exit 1
}

$DD_PRODUCT_TYPE = if ($env:DD_PRODUCT_TYPE) { $env:DD_PRODUCT_TYPE } else { "Engineering" }
$DD_PRODUCT = if ($env:DD_PRODUCT) { $env:DD_PRODUCT } else { "Juice Shop" }
$DD_ENGAGEMENT = if ($env:DD_ENGAGEMENT) { $env:DD_ENGAGEMENT } else { "Labs Security Testing" }

Write-Host "Using context:"
Write-Host "  ProjectRoot=$ProjectRoot"
Write-Host "  DD_API=$DD_API"
Write-Host "  DD_PRODUCT_TYPE=$DD_PRODUCT_TYPE"
Write-Host "  DD_PRODUCT=$DD_PRODUCT"
Write-Host "  DD_ENGAGEMENT=$DD_ENGAGEMENT"

$Headers = @{
    "Authorization" = "Token $DD_TOKEN"
}

Write-Host "Discovering importer names from /test_types/ ..."
try {
    $response = Invoke-RestMethod -Uri "$DD_API/test_types/?limit=2000" -Headers $Headers -Method Get
    $types = $response.results.name
} catch {
    Write-Warning "Failed to fetch test types from API. Using defaults."
    $types = @()
}

function Get-ScanType {
    param($Pattern, $Fallback)
    $match = $types | Where-Object { $_ -match $Pattern } | Select-Object -First 1
    if ($match) { return $match }
    return $Fallback
}

$SCAN_ZAP = Get-ScanType "^ZAP Scan" "ZAP Scan"
$SCAN_SEMGREP = Get-ScanType "^Semgrep JSON Report" "Semgrep JSON Report"
$SCAN_TRIVY = Get-ScanType "^Trivy Scan" "Trivy Scan"
$SCAN_NUCLEI = Get-ScanType "^Nuclei Scan" "Nuclei Scan"
$SCAN_GRYPE = Get-ScanType "^Anchore Grype|^Grype" "Anchore Grype"

Write-Host "Importer names:"
Write-Host "  ZAP      = $SCAN_ZAP"
Write-Host "  Semgrep  = $SCAN_SEMGREP"
Write-Host "  Trivy    = $SCAN_TRIVY"
Write-Host "  Nuclei   = $SCAN_NUCLEI"
Write-Host "  Grype    = $SCAN_GRYPE"

function Import-ScanFile {
    param($ScanType, $FilePath)
    
    if (-not $FilePath) { return }
    if (-not (Test-Path $FilePath)) {
        Write-Host "SKIP: $ScanType file not found: $FilePath" -ForegroundColor Yellow
        return
    }

    Write-Host "Importing $ScanType from $FilePath" -ForegroundColor Cyan
    
    $outBase = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    $outPath = Join-Path (Join-Path $ProjectRoot "labs\lab10\imports") "import-$($outBase -replace '[^A-Za-z0-9_.-]', '_').json"

    $UploadFile = $FilePath
    if ($ScanType -match "Nuclei") {
        $content = Get-Content $FilePath -Raw
        if ($content -match '}\s*{') {
            Write-Host "  Detected JSON-L format for Nuclei, converting to array..." -ForegroundColor Gray
            $jsonArray = "[" + ($content -replace '}\s*{', '},{') + "]"
            $UploadFile = Join-Path $env:TEMP "nuclei-fixed.json"
            $jsonArray | Out-File -FilePath $UploadFile -Encoding utf8
        }
    }

    curl.exe -sS -X POST "$DD_API/import-scan/" `
        -H "Authorization: Token $DD_TOKEN" `
        -F "scan_type=$ScanType" `
        -F "file=@$UploadFile" `
        -F "product_type_name=$DD_PRODUCT_TYPE" `
        -F "product_name=$DD_PRODUCT" `
        -F "engagement_name=$DD_ENGAGEMENT" `
        -F "auto_create_context=true" `
        -F "minimum_severity=Info" `
        -F "close_old_findings=false" `
        -F "push_to_jira=false" `
        -o "$outPath"

    if (Test-Path $outPath) {
        $res = Get-Content $outPath | ConvertFrom-Json
        if ($res.engagement -or $res.engagement_id -or $res.test -or $res.test_id) {
            Write-Host "SUCCESS: Imported into engagement $($res.engagement_id)" -ForegroundColor Green
        } else {
            Write-Host "WARNING: Import returned unexpected response. Check $outPath" -ForegroundColor Yellow
            if ($res.message) { Write-Host "  Message: $($res.message)" -ForegroundColor Red }
        }
    } else {
        Write-Error "FAILED to import $ScanType : No response saved."
    }
}

$Reports = @(
    @{ Type = $SCAN_ZAP; Path = Resolve-ProjectPath "labs/lab5/zap/zap-report-noauth.json" },
    @{ Type = $SCAN_SEMGREP; Path = Resolve-ProjectPath "labs/lab5/semgrep/semgrep-results.json" },
    @{ Type = $SCAN_TRIVY; Path = Resolve-ProjectPath "labs/lab4/trivy/juice-shop-trivy-detailed.json" },
    @{ Type = $SCAN_NUCLEI; Path = Resolve-ProjectPath "labs/lab5/nuclei/nuclei-results.json" },
    @{ Type = $SCAN_GRYPE; Path = Resolve-ProjectPath "labs/lab4/syft/grype-vuln-results.json" }
)

foreach ($report in $Reports) {
    Import-ScanFile -ScanType $report.Type -FilePath $report.Path
}

Write-Host "Done. Import process completed."
