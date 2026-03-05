$ErrorActionPreference = "Stop"

$Lab5Dir   = Resolve-Path (Join-Path $PSScriptRoot "..")
$AnaDir    = Join-Path $Lab5Dir "analysis"
$ZapDir    = Join-Path $Lab5Dir "zap"
$Nuclei    = Join-Path $Lab5Dir "nuclei\nuclei-results.json"
$Nikto     = Join-Path $Lab5Dir "nikto\nikto-results.txt"
$SqlmapDir = Join-Path $Lab5Dir "sqlmap"

New-Item -ItemType Directory -Force -Path $AnaDir | Out-Null

function ZapCounts([string]$htmlPath) {
  if (!(Test-Path $htmlPath)) {
    return @{ High = 0; Med = 0; Low = 0; Info = 0; Total = 0 }
  }

  $h = Get-Content -Raw -LiteralPath $htmlPath -Encoding UTF8
  $high = [regex]::Matches($h, 'class="risk-3"').Count
  $med  = [regex]::Matches($h, 'class="risk-2"').Count
  $low  = [regex]::Matches($h, 'class="risk-1"').Count
  $info = [regex]::Matches($h, 'class="risk-0"').Count

  $high = [int]($high / 2)
  $med  = [int]($med / 2)
  $low  = [int]($low / 2)
  $info = [int]($info / 2)

  return @{
    High  = $high
    Med   = $med
    Low   = $low
    Info  = $info
    Total = ($high + $med + $low + $info)
  }
}

function NucleiStats([string]$path) {
  if (!(Test-Path $path)) {
    return @{ Total = 0; By = @{} }
  }

  $by = @{}
  $lines = Get-Content -LiteralPath $path -Encoding UTF8 | Where-Object { $_.Trim().Length -gt 0 }

  foreach ($l in $lines) {
    try {
      $o = $l | ConvertFrom-Json

      $sev = $null
      if ($o.info -and $o.info.severity) {
        $sev = $o.info.severity.ToString().ToLowerInvariant()
      } else {
        $sev = "unknown"
      }

      if ($by.ContainsKey($sev)) {
        $by[$sev]++
      } else {
        $by[$sev] = 1
      }
    }
    catch {
      if ($by.ContainsKey("parse_error")) {
        $by["parse_error"]++
      } else {
        $by["parse_error"] = 1
      }
    }
  }

  return @{
    Total = $lines.Count
    By    = $by
  }
}

function NiktoCount([string]$path) {
  if (!(Test-Path $path)) { return 0 }
  return (Get-Content -LiteralPath $path -Encoding UTF8 | Where-Object { $_.StartsWith("+ ") }).Count
}

function SqlmapCount([string]$root) {
  if (!(Test-Path $root)) {
    return @{ Total = 0; Csv = $null }
  }

  $csv = Get-ChildItem -Path $root -Recurse -Filter "results-*.csv" -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $csv) {
    return @{ Total = 0; Csv = $null }
  }

  $lines = Get-Content -LiteralPath $csv.FullName -Encoding UTF8 | Where-Object { $_.Trim().Length -gt 0 }

  return @{
    Total = [Math]::Max(0, $lines.Count - 1)
    Csv   = $csv.FullName
  }
}

$zapNo = ZapCounts (Join-Path $ZapDir "report-noauth.html")
$zapAu = ZapCounts (Join-Path $ZapDir "report-auth.html")
$nuc   = NucleiStats $Nuclei
$nik   = NiktoCount $Nikto
$sql   = SqlmapCount $SqlmapDir

$sum = @()
$sum += "=== DAST Summary ==="
$sum += ""
$sum += ("ZAP (noauth): Total={0} High={1} Med={2} Low={3} Info={4}" -f $zapNo.Total, $zapNo.High, $zapNo.Med, $zapNo.Low, $zapNo.Info)
$sum += ("ZAP (auth):   Total={0} High={1} Med={2} Low={3} Info={4}" -f $zapAu.Total, $zapAu.High, $zapAu.Med, $zapAu.Low, $zapAu.Info)
$sum += ""
$sum += ("Nuclei: Total matches={0}" -f $nuc.Total)

if ($nuc.By.Count -gt 0) {
  $sum += "  By severity:"
  foreach ($k in ($nuc.By.Keys | Sort-Object)) {
    $sum += ("    - {0}: {1}" -f $k, $nuc.By[$k])
  }
}

$sum += ""
$sum += ("Nikto: server issues={0}" -f $nik)
$sum += ("SQLmap: findings(rows in results-*.csv)={0}" -f $sql.Total)

if ($sql.Csv) {
  $sum += ("  CSV: {0}" -f $sql.Csv)
}

$sumPath = Join-Path $AnaDir "dast-summary.txt"
$sum -join "`r`n" | Set-Content -LiteralPath $sumPath -Encoding UTF8

$sevParts = @()
foreach ($k in ($nuc.By.Keys | Sort-Object)) {
  $sevParts += ("{0}:{1}" -f $k, $nuc.By[$k])
}
$sevStr = if ($sevParts.Count -gt 0) { $sevParts -join " " } else { "n/a" }

$md = @()
$md += "| Tool | Findings | Severity Breakdown | Best Use Case |"
$md += "|---|---:|---|---|"
$md += ("| ZAP (auth) | {0} | High:{1} Med:{2} Low:{3} Info:{4} | Comprehensive scan + auth + active/passive |" -f $zapAu.Total, $zapAu.High, $zapAu.Med, $zapAu.Low, $zapAu.Info)
$md += ("| ZAP (noauth) | {0} | High:{1} Med:{2} Low:{3} Info:{4} | Public surface baseline |" -f $zapNo.Total, $zapNo.High, $zapNo.Med, $zapNo.Low, $zapNo.Info)
$md += ("| Nuclei | {0} | {1} | Fast template-based checks (known issues/CVEs) |" -f $nuc.Total, $sevStr)
$md += ("| Nikto | {0} | n/a | Server misconfig/headers/default files |" -f $nik)
$md += ("| SQLmap | {0} | n/a | Deep SQLi confirmation + extraction |" -f $sql.Total)

$mdPath = Join-Path $AnaDir "dast-matrix.md"
$md -join "`r`n" | Set-Content -LiteralPath $mdPath -Encoding UTF8

$sum -join "`r`n"
"Saved: $sumPath"
"Saved: $mdPath"