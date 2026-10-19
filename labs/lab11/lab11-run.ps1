# Lab 11 - hardened reverse proxy + CRS WAF, Windows + Docker Desktop.
# Run from the repo root (or double-click labs\lab11\lab11-run.bat).
# Every proof goes to labs\lab11\results\. Claude writes submissions\lab11.md from it.
param([switch]$BonusOnly)
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$Root  = (Get-Location).Path
$Lab   = Join-Path $Root "labs\lab11"
$Res   = Join-Path $Lab "results"
$Certs = Join-Path $Lab "reverse-proxy\certs"
New-Item -ItemType Directory -Force $Res, $Certs, (Join-Path $Lab "logs") | Out-Null
$log = Join-Path $Res "run-log.txt"
if (-not $BonusOnly) { Remove-Item $log -ErrorAction SilentlyContinue }
function Say($m) { Write-Host $m -ForegroundColor Cyan; "`n## $m" | Out-File -Append -Encoding utf8 $log }
# Run a block, append output to run-log, optionally also save it to results\<file>
function Log($name, [scriptblock]$cmd, $file) {
  "### $name" | Out-File -Append -Encoding utf8 $log
  $o = & $cmd 2>&1 | ForEach-Object { "$_" }
  $o | Out-File -Append -Encoding utf8 $log
  if ($file) { $o | Set-Content -Encoding utf8 (Join-Path $Res $file) }
  $o
}
function WriteLF($path, $text) { [IO.File]::WriteAllText($path, ($text -replace "`r`n", "`n")) }

if (-not $BonusOnly) {
# ---------------------------------------------------------------- images
function Get-Image($img) {
  docker image inspect $img *> $null
  if ($LASTEXITCODE -eq 0) { return "have $img" }
  foreach ($src in @($img, "mirror.gcr.io/$img")) {
    for ($t = 1; $t -le 2; $t++) {
      Write-Host "  pulling $src (try $t)"
      docker pull $src 2>&1 | Select-Object -Last 1 | ForEach-Object { "$_" }
      if ($LASTEXITCODE -eq 0) { if ($src -ne $img) { docker tag $src $img }; return "using $src" }
    }
  }
  return "FAILED $img"
}
Log "versions" { docker --version; docker compose version; curl.exe --version | Select-Object -First 1 }
Say "Pulling images"
$JuiceImg = "bkimminich/juice-shop:v20.0.0"
foreach ($i in @($JuiceImg, "nginx:stable-alpine", "alpine/openssl:latest", "drwetter/testssl.sh:3.2", "curlimages/curl:latest", "owasp/modsecurity-crs:nginx")) {
  $r = Log "pull $i" { Get-Image $i }
  if ("$r" -match "FAILED" -and $i -eq $JuiceImg -and (Test-Path (Join-Path $Root "juice-shop.tar"))) {
    Log "load juice-shop.tar" { $l = docker load -i (Join-Path $Root "juice-shop.tar") 2>&1 | Out-String; $l
      if ($l -match "Loaded image: (\S+)") { docker tag $Matches[1] $JuiceImg; "tagged $($Matches[1]) as $JuiceImg" } }
  }
}

}
# ---------------------------------------------------------------- ports
function Busy($p) { [bool](Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue) }
$HttpPort = 80; $HttpsPort = 443
if ((Busy 80) -or (Busy 443)) {
  $owner = docker ps --filter "publish=80" --filter "label=com.docker.compose.project=lab11" -q
  if (-not $owner) { $HttpPort = 8088; $HttpsPort = 8448 }
}
$env:LAB11_HTTP_PORT = "$HttpPort"; $env:LAB11_HTTPS_PORT = "$HttpsPort"; $env:LAB11_WAF_PORT = "8880"
$HTTP  = if ($HttpPort -eq 80) { "http://127.0.0.1" } else { "http://127.0.0.1:$HttpPort" }
$HTTPS = if ($HttpsPort -eq 443) { "https://127.0.0.1" } else { "https://127.0.0.1:$HttpsPort" }
$WAF   = "http://127.0.0.1:8880"
Log "ports" { "http=$HttpPort https=$HttpsPort waf=8880  ($HTTP, $HTTPS, $WAF)" } "ports.txt"

if (-not $BonusOnly) {
# ---------------------------------------------------------------- certs
Say "Generating self-signed certificate"
if (-not (Test-Path (Join-Path $Certs "localhost.crt"))) {
  Log "openssl req" { docker run --rm -v "${Certs}:/c" alpine/openssl:latest req -x509 -nodes -newkey rsa:2048 -days 30 `
      -keyout /c/localhost.key -out /c/localhost.crt -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" }
}

}
# ---------------------------------------------------------------- compose up
$Net = "lab11_default"
function DC { docker compose -p lab11 -f docker-compose.yml @args }
function DCW { docker compose -p lab11 -f docker-compose.yml -f waf/docker-compose.override.yml @args }
Push-Location $Lab
Say "11.2 compose up"
Log "compose up" { DC up -d }
Pop-Location
Say "Waiting for Juice Shop behind nginx..."
$t0 = Get-Date
do { Start-Sleep 3; $c = curl.exe -sk -o NUL --max-time 5 -w "%{http_code}" "$HTTPS/rest/admin/application-version"; Write-Host "  HTTP $c" } while ($c -ne "200" -and ((Get-Date) - $t0).TotalMinutes -lt 5)
Push-Location $Lab
Log "compose ps" { DC ps } "compose-ps.txt"
Log "nginx -t" { DC exec -T nginx nginx -t; DC exec -T nginx nginx -v } "nginx-t.txt"
Log "nginx -T (key directives)" { DC exec -T nginx nginx -T 2>&1 | Select-String -Pattern "limit_|_timeout|ssl_protocols|ssl_ciphers|ssl_conf_command|return 30|add_header" | ForEach-Object { $_.Line.Trim() } } "nginx-T-directives.txt"
Pop-Location

# helper scripts run inside containers on the compose network (target nginx:443 directly)
WriteLF (Join-Path $Res "tls.sh") @'
#!/bin/sh
H=nginx:443
echo "== TLS 1.3, default client offer"
echo | openssl s_client -connect $H -tls1_3 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
echo "== TLS 1.2, default client offer"
echo | openssl s_client -connect $H -tls1_2 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
echo "== TLS 1.3 TLS_AES_128_GCM_SHA256 (in list, must work)"
echo | openssl s_client -connect $H -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -brief 2>&1 | grep -E 'Protocol|Ciphersuite'
echo "== TLS 1.3 TLS_CHACHA20_POLY1305_SHA256 (not in list, must fail)"
echo | openssl s_client -connect $H -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -iE 'alert|failure|error|Cipher is'
echo "grep -icE 'alert|failure' => $(echo | openssl s_client -connect $H -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 2>&1 | grep -icE 'alert|failure')"
echo "== TLS 1.2 ECDHE-RSA-CHACHA20-POLY1305 (not in list, must fail)"
echo | openssl s_client -connect $H -tls1_2 -cipher ECDHE-RSA-CHACHA20-POLY1305 2>&1 | grep -iE 'alert|failure|error|Cipher is'
echo "== TLS 1.2 ECDHE-RSA-AES256-SHA384 (CBC, must fail)"
echo | openssl s_client -connect $H -tls1_2 -cipher ECDHE-RSA-AES256-SHA384 2>&1 | grep -iE 'alert|failure|error|Cipher is'
echo "== certificate served"
echo | openssl s_client -connect $H 2>/dev/null | openssl x509 -noout -subject -serial -dates -fingerprint -sha256
'@
WriteLF (Join-Path $Res "certinfo.sh") @'
#!/bin/sh
echo | openssl s_client -connect nginx:443 2>/dev/null | openssl x509 -noout -serial -enddate -fingerprint -sha256
'@
WriteLF (Join-Path $Res "timeout.sh") @'
#!/bin/sh
# Slowloris-style: open TLS, send the request line and one header, then go silent.
start=$(date +%s)
echo "$(date -u +%T) sent 'GET / HTTP/1.1' + 'Host:' and then nothing (no blank line)"
( printf 'GET / HTTP/1.1\r\nHost: localhost\r\n'; sleep 40 ) | \
( timeout 60 openssl s_client -connect nginx:443 -quiet 2>&1 | tail -n 3
  end=$(date +%s)
  echo "$(date -u +%T) connection closed by nginx after $((end-start))s" )
'@
WriteLF (Join-Path $Res "load.sh") @'
#!/bin/sh
end=$(( $(date +%s) + 25 ))
while [ $(date +%s) -lt $end ]; do
  curl -sk -o /dev/null --max-time 5 -w '%{http_code}\n' https://nginx/rest/admin/application-version
done
'@
function OSSL($script) { docker run --rm --network $Net -v "${Res}:/r" --entrypoint sh alpine/openssl:latest "/r/$script" }

if (-not $BonusOnly) {
# ---------------------------------------------------------------- Task 1
Say "11.3 Task 1 proofs"
Log "http redirect" { curl.exe -sI "$HTTP/" } "http-redirect.txt"
Log "http redirect of a POST keeps the method (308)" { curl.exe -sk -o NUL -L -X POST -w "final=%{url_effective} code=%{http_code} redirects=%{num_redirects}`n" "$HTTP/rest/user/login" -H "Content-Type: application/json" --data-raw "{}" } "redirect-post.txt"
Log "tls checks" { OSSL "tls.sh" } "tls.txt"
Log "tls13" { Get-Content (Join-Path $Res "tls.txt") | Select-Object -Skip 1 -First 2 } "tls13.txt"
Log "headers" { curl.exe -skI "$HTTPS/" } "headers.txt"
Log "headers on a 404" { curl.exe -skI "$HTTPS/does-not-exist.js" } "headers-404.txt"
Say "testssl --protocols (1-2 min)"
Log "testssl protocols" { docker run --rm --network $Net drwetter/testssl.sh:3.2 --protocols --color 0 --warnings batch https://nginx } "protocols.txt"
Say "testssl cipher per protocol (1-2 min)"
Log "testssl ciphers" { docker run --rm --network $Net drwetter/testssl.sh:3.2 -E --color 0 --warnings batch https://nginx } "ciphers.txt"

# ---------------------------------------------------------------- Task 2
Say "11.5 Rate limit"
WriteLF (Join-Path $Res "login-bad.json") '{"email":"a@b.c","password":"x"}'
$bad = Join-Path $Res "login-bad.json"
Log "14 login POSTs" { $s = ""; for ($i = 1; $i -le 14; $i++) { $s += (curl.exe -sk -o NUL -w "%{http_code}" -X POST "$HTTPS/rest/user/login" -H "Content-Type: application/json" -d "@$bad") + " " }; $s } "ratelimit.txt"
Log "headers on the 429" { curl.exe -sk -D - -o NUL -X POST "$HTTPS/rest/user/login" -H "Content-Type: application/json" -d "@$bad" } "ratelimit-429-headers.txt"
Log "rest of the site is not limited (20 GETs)" { $s = ""; for ($i = 1; $i -le 20; $i++) { $s += (curl.exe -sk -o NUL -w "%{http_code}" "$HTTPS/rest/admin/application-version") + " " }; $s } "ratelimit-other.txt"
Log "nginx error.log limiting lines" { Get-Content (Join-Path $Lab "logs\error.log") -ErrorAction SilentlyContinue | Select-String "limiting" | Select-Object -Last 3 | ForEach-Object { $_.Line } } "ratelimit-errorlog.txt"

Say "Timeout firing (client_header_timeout, ~10s)"
Log "slowloris timeout" { OSSL "timeout.sh" } "timeout.txt"
Start-Sleep 2
Log "access.log 408" { Get-Content (Join-Path $Lab "logs\access.log") | Select-String '" 408 ' | Select-Object -Last 2 | ForEach-Object { $_.Line } } "timeout-accesslog.txt"

Say "Certificate rotation under load"
Push-Location $Lab
Log "cert before" { OSSL "certinfo.sh" } "rotation-before.txt"
docker rm -f lab11-load *> $null
Log "start load" { docker run -d --name lab11-load --network $Net -v "${Res}:/r" --entrypoint sh curlimages/curl:latest /r/load.sh; "load started $(Get-Date -Format HH:mm:ss)" }
Start-Sleep 5
$New = Join-Path $Certs "new"; $Old = Join-Path $Certs "old"
New-Item -ItemType Directory -Force $New, $Old | Out-Null
Log "1 new key+cert" { docker run --rm -v "${New}:/c" alpine/openssl:latest req -x509 -nodes -newkey rsa:2048 -days 90 `
      -keyout /c/localhost.key -out /c/localhost.crt -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"; "generated $(Get-Date -Format HH:mm:ss)" } "rotation-steps.txt"
Log "2 key matches cert" { docker run --rm -v "${New}:/c" --entrypoint sh alpine/openssl:latest -c "openssl x509 -in /c/localhost.crt -noout -pubkey | sha256sum; openssl pkey -in /c/localhost.key -pubout | sha256sum; openssl x509 -in /c/localhost.crt -noout -serial -enddate" }
Log "3 backup old" { Copy-Item (Join-Path $Certs "localhost.*") $Old -Force; "backed up to certs\old" }
Log "4 install new" { Copy-Item (Join-Path $New "localhost.*") $Certs -Force; "installed $(Get-Date -Format HH:mm:ss)" }
Log "5 nginx -t" { DC exec -T nginx nginx -t }
Log "6 reload" { DC exec -T nginx nginx -s reload; "reloaded $(Get-Date -Format HH:mm:ss)" }
Start-Sleep 3
Log "7 cert after" { OSSL "certinfo.sh" } "rotation-after.txt"
docker wait lab11-load *> $null
Log "load result (status code counts during rotation)" { docker logs lab11-load 2>&1 | Group-Object | ForEach-Object { "$($_.Count) x $($_.Name)" } } "rotation-load.txt"
docker rm -f lab11-load *> $null
(Get-Content $log -Raw) -split "### " | Where-Object { $_ -match "^(1|2|3|4|5|6|7) " } | Set-Content -Encoding utf8 (Join-Path $Res "rotation-steps.txt")

}
Push-Location $Lab
Log "juice not published" { "docker compose port juice 3000 -> '$(DC port juice 3000 2>&1)'"; "curl 127.0.0.1:3000 -> $(curl.exe -s -o NUL --max-time 3 -w '%{http_code}' http://127.0.0.1:3000/)" } "juice-exposure.txt"
Pop-Location

# ---------------------------------------------------------------- Bonus
Say "Bonus: WAF up"
Push-Location $Lab
Log "compose up waf" { DCW up -d }
Pop-Location
$t0 = Get-Date
do { Start-Sleep 3; $c = curl.exe -s -o NUL --max-time 5 -w "%{http_code}" "$WAF/rest/admin/application-version"; Write-Host "  WAF HTTP $c" } while ($c -ne "200" -and ((Get-Date) - $t0).TotalMinutes -lt 3)
Push-Location $Lab; Log "compose ps (with waf)" { DCW ps } "compose-ps-waf.txt"; Pop-Location
Say "Waiting 65s so the login rate limit refills"
Start-Sleep 65

$sqli = "/rest/products/search?q=%27%20OR%201%3D1--"
Log "sqli via plain proxy" { curl.exe -sk -o (Join-Path $Res "sqli-proxy-body.txt") -w "%{http_code}" "$HTTPS$sqli"; "`n"; Get-Content (Join-Path $Res "sqli-proxy-body.txt") -Raw | ForEach-Object { $_.Substring(0, [Math]::Min(400, $_.Length)) } } "sqli-proxy.txt"
Log "sqli via waf" { curl.exe -s -o (Join-Path $Res "sqli-waf-body.txt") -w "%{http_code}" "$WAF$sqli"; "`n"; Get-Content (Join-Path $Res "sqli-waf-body.txt") -Raw | ForEach-Object { $_.Substring(0, [Math]::Min(400, $_.Length)) } } "sqli-waf.txt"

# false-positive hunt: legitimate requests through both paths
WriteLF (Join-Path $Res "login-jim.json") '{"email":"jim@juice-sh.op","password":"ncc-1701"}'
WriteLF (Join-Path $Res "login-strongpw.json") '{"email":"maria.oconnor@example.com","password":"Xk9''#;--Pa$$w0rd!"}'
WriteLF (Join-Path $Res "feedback.json") '{"comment":"Great shop -- I''d select the apple juice again; 5/5 & fast delivery","rating":5}'
WriteLF (Join-Path $Res "basket-qty.json") '{"quantity":2}'
$jim = curl.exe -s -X POST "$WAF/rest/user/login" -H "Content-Type: application/json" -d "@$(Join-Path $Res 'login-jim.json')" | Out-String
try { $auth = ($jim | ConvertFrom-Json).authentication } catch { $auth = $null }
if (-not $auth) { $jim = curl.exe -sk -X POST "$HTTPS/rest/user/login" -H "Content-Type: application/json" -d "@$(Join-Path $Res 'login-jim.json')" | Out-String; try { $auth = ($jim | ConvertFrom-Json).authentication } catch {} }
$tok = $auth.token; $bid = $auth.bid
$item = 1
try { $b = curl.exe -sk "$HTTPS/rest/basket/$bid" -H "Authorization: Bearer $tok" | ConvertFrom-Json; if ($b.data.Products.Count -gt 0) { $item = $b.data.Products[0].BasketItem.id } } catch {}
Log "jim auth" { "token length=$("$tok".Length) bid=$bid basketItem=$item" }
function Both($label, $method, $path, $body, [switch]$Auth) {
  $a = @("-s", "-o", "NUL", "-w", "%{http_code}", "-X", $method)
  if ($body) { $a += @("-H", "Content-Type: application/json", "-d", "@$(Join-Path $Res $body)") }
  if ($Auth) { $a += @("-H", "Authorization: Bearer $tok") }
  $p = & curl.exe -k @a "$HTTPS$path"; $w = & curl.exe @a "$WAF$path"
  "{0,-58} proxy={1} waf={2}" -f "$label [$method $path]", $p, $w
}
Log "false-positive hunt" {
  Both "home page" GET "/"
  Both "main js bundle" GET "/main.js"
  Both "product search 'apple'" GET "/rest/products/search?q=apple"
  Both "product search with apostrophe (O'Reilly)" GET "/rest/products/search?q=O%27Reilly"
  Both "product search 'select'" GET "/rest/products/search?q=select%20juice"
  Both "product details" GET "/api/Products/1"
  Both "login, normal credentials" POST "/rest/user/login" "login-jim.json"
  Both "login, strong password with ' # ; --" POST "/rest/user/login" "login-strongpw.json"
  Both "own basket" GET "/rest/basket/$bid" -Auth
  Both "change basket quantity (PUT)" PUT "/api/BasketItems/$item" "basket-qty.json" -Auth
  Both "feedback with -- ; ' & in text" POST "/api/Feedbacks" "feedback.json" -Auth
} "fp-hunt.txt"
Push-Location $Lab
Log "waf logs" { DCW logs --no-color waf } "waf.log"
Pop-Location
Log "rule ids fired" { Get-Content (Join-Path $Res "waf.log") | ForEach-Object { [regex]::Matches($_, '(?:\[id "|"ruleId":")(\d{6})') | ForEach-Object { $_.Groups[1].Value } } | Group-Object | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) x$($_.Count)" } } "waf-rule-ids.txt"

"DONE" | Out-File -Append -Encoding utf8 $log
Write-Host ""
Write-Host "Done. Results are in labs\lab11\results\. Tell Claude." -ForegroundColor Green
Write-Host "Containers are left running; clean up later with: docker compose -p lab11 -f labs/lab11/docker-compose.yml -f labs/lab11/waf/docker-compose.override.yml down -v" -ForegroundColor Green
