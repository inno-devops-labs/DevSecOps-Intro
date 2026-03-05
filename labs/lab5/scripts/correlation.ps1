$ErrorActionPreference = "Stop"

$Lab5Dir   = Resolve-Path (Join-Path $PSScriptRoot "..")
$AnaDir    = Join-Path $Lab5Dir "analysis"
New-Item -ItemType Directory -Force -Path $AnaDir | Out-Null

$Semgrep = Join-Path $Lab5Dir "semgrep\semgrep-results.json"
$ZapAuth = Join-Path $Lab5Dir "zap\report-auth.html"
$Nuclei  = Join-Path $Lab5Dir "nuclei\nuclei-results.json"
$Nikto   = Join-Path $Lab5Dir "nikto\nikto-results.txt"
$SqlmapDir = Join-Path $Lab5Dir "sqlmap"

function Count-Semgrep($p){
  if(!(Test-Path $p)){ return 0 }
  $o = Get-Content -Raw -LiteralPath $p -Encoding UTF8 | ConvertFrom-Json
  return @($o.results).Count
}
function Count-Zap($p){
  if(!(Test-Path $p)){ return 0 }
  $h=Get-Content -Raw -LiteralPath $p -Encoding UTF8
  $med=[regex]::Matches($h,'class="risk-2"').Count
  $high=[regex]::Matches($h,'class="risk-3"').Count
  return [int](($med/2)+($high/2))
}
function Count-Lines($p){
  if(!(Test-Path $p)){ return 0 }
  return (Get-Content -LiteralPath $p -Encoding UTF8 | Where-Object { $_.Trim().Length -gt 0 }).Count
}
function Count-Nikto($p){
  if(!(Test-Path $p)){ return 0 }
  return (Get-Content -LiteralPath $p -Encoding UTF8 | Where-Object { $_.StartsWith("+ ") }).Count
}
function Count-Sqlmap($root){
  if(!(Test-Path $root)){ return 0 }
  $csv = Get-ChildItem -Path $root -Recurse -Filter "results-*.csv" -ErrorAction SilentlyContinue | Select-Object -First 1
  if(-not $csv){ return 0 }
  $lines = Get-Content -LiteralPath $csv.FullName -Encoding UTF8 | Where-Object { $_.Trim().Length -gt 0 }
  return [Math]::Max(0,$lines.Count-1)
}

$sast = Count-Semgrep $Semgrep
$zap  = Count-Zap $ZapAuth
$nuc  = Count-Lines $Nuclei
$nik  = Count-Nikto $Nikto
$sql  = Count-Sqlmap $SqlmapDir

$out = @()
$out += "=== SAST/DAST Correlation Report ==="
$out += ""
$out += "Security Testing Results Summary:"
$out += ""
$out += "SAST (Semgrep): $sast code-level findings"
$out += "DAST (ZAP authenticated): $zap alerts"
$out += "DAST (Nuclei): $nuc template matches"
$out += "DAST (Nikto): $nik server issues"
$out += "DAST (SQLmap): $sql SQL injection vulnerabilities"
$out += ""
$out += "Key Insights:"
$out += ""
$out += "SAST (Static Analysis):"
$out += "  - Finds code-level vulnerabilities before deployment"
$out += "  - Detects: hardcoded secrets, SQL injection patterns, insecure crypto"
$out += "  - Fast feedback in development phase"
$out += ""
$out += "DAST (Dynamic Analysis):"
$out += "  - Finds runtime configuration and deployment issues"
$out += "  - Detects: missing security headers, authentication flaws, server misconfigs"
$out += "  - Authenticated scanning reveals much more attack surface"
$out += ""
$out += "Recommendation: Use BOTH approaches for comprehensive security coverage"

$path = Join-Path $AnaDir "correlation.txt"
$out -join "`r`n" | Set-Content -LiteralPath $path -Encoding UTF8
$out -join "`r`n"
"Saved: $path"