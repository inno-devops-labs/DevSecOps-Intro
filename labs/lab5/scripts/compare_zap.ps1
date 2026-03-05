$ErrorActionPreference = "Stop"

$Lab5Dir = Resolve-Path (Join-Path $PSScriptRoot "..")
$ZapDir  = Join-Path $Lab5Dir "zap"
$AnaDir  = Join-Path $Lab5Dir "analysis"
New-Item -ItemType Directory -Force -Path $AnaDir | Out-Null

$NoAuthLog    = Join-Path $ZapDir "zap-noauth.log"
$AuthLog      = Join-Path $ZapDir "zap-auth.log"
$NoAuthReport = Join-Path $ZapDir "report-noauth.html"
$AuthReport   = Join-Path $ZapDir "report-auth.html"

function Get-TextOrEmpty([string]$p){ if(Test-Path $p){Get-Content -Raw -LiteralPath $p}else{""} }

function FirstInt([string]$t, [string[]]$pats){
  foreach($p in $pats){
    $m=[regex]::Match($t,$p,[Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if($m.Success){ return [int]$m.Groups[1].Value }
  }
  return $null
}

function ZapCounts([string]$htmlPath){
  if(!(Test-Path $htmlPath)){ return @{High=0;Med=0;Low=0;Info=0;Total=0} }
  $h=Get-Content -Raw -LiteralPath $htmlPath -Encoding UTF8
  $high=[regex]::Matches($h,'class="risk-3"').Count
  $med =[regex]::Matches($h,'class="risk-2"').Count
  $low =[regex]::Matches($h,'class="risk-1"').Count
  $info=[regex]::Matches($h,'class="risk-0"').Count
  $high=[int]($high/2); $med=[int]($med/2); $low=[int]($low/2); $info=[int]($info/2)
  return @{High=$high;Med=$med;Low=$low;Info=$info;Total=($high+$med+$low+$info)}
}

function AdminEndpoints([string]$htmlPath,[int]$max=10){
  if(!(Test-Path $htmlPath)){ return @() }
  $h=Get-Content -Raw -LiteralPath $htmlPath -Encoding UTF8
  $ms=[regex]::Matches($h,'/rest/admin/[A-Za-z0-9\-\._~/%\?\=&]+')
  $set=New-Object 'System.Collections.Generic.HashSet[string]'
  foreach($m in $ms){ [void]$set.Add($m.Value) }
  return $set | Select-Object -First $max
}

$noAuthText = Get-TextOrEmpty $NoAuthLog
$authText   = Get-TextOrEmpty $AuthLog

$noAuthUrls = FirstInt $noAuthText @(
  'Job spider found\s+(\d+)\s+URLs',
  'found\s+(\d+)\s+URLs',
  'Total of\s+(\d+)\s+URLs'
)
$authSpider = FirstInt $authText   @('Job spider found\s+(\d+)\s+URLs')
$authAjax   = FirstInt $authText   @('Job spiderAjax found\s+(\d+)\s+URLs','AJAX spider.*found\s+(\d+)\s+URLs')

$noAuthAlerts = ZapCounts $NoAuthReport
$authAlerts   = ZapCounts $AuthReport
$admin = AdminEndpoints $AuthReport 12

$out = @()
$out += "=== ZAP Auth vs No-Auth Comparison ==="
$out += ""
$out += "No-Auth:"
$out += ("  URLs discovered (from log): {0}" -f ($(if($null -eq $noAuthUrls){"N/A"}else{$noAuthUrls})))
$out += ("  Alerts (HTML): Total={0} High={1} Med={2} Low={3} Info={4}" -f $noAuthAlerts.Total,$noAuthAlerts.High,$noAuthAlerts.Med,$noAuthAlerts.Low,$noAuthAlerts.Info)
$out += ""
$out += "Auth:"
$out += ("  Spider URLs (from log): {0}" -f ($(if($null -eq $authSpider){"N/A"}else{$authSpider})))
$out += ("  AJAX Spider URLs (from log): {0}" -f ($(if($null -eq $authAjax){"N/A"}else{$authAjax})))
$out += ("  Alerts (HTML): Total={0} High={1} Med={2} Low={3} Info={4}" -f $authAlerts.Total,$authAlerts.High,$authAlerts.Med,$authAlerts.Low,$authAlerts.Info)
$out += ""

if($admin.Count -gt 0){
  $out += "Admin/authenticated endpoints examples:"
  foreach($e in $admin){ $out += "  - $e" }
}else{
  $out += "Admin/authenticated endpoints examples: N/A"
}

$outPath = Join-Path $AnaDir "zap-compare.txt"
$out -join "`r`n" | Set-Content -LiteralPath $outPath -Encoding UTF8
$out -join "`r`n"
"Saved: $outPath"