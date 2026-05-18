#!/bin/bash
set -euo pipefail

node <<'NODE'
const fs = require('fs')

function readJson (path) {
  return JSON.parse(fs.readFileSync(path, 'utf8').replace(/^\uFEFF/, ''))
}

function groupByRisk (alerts) {
  const out = {}
  for (const alert of alerts) out[alert.risk] = (out[alert.risk] || 0) + 1
  return out
}

const zap = readJson('labs/lab5/zap/zap-report-auth.json').alerts || []
const zapUrls = readJson('labs/lab5/zap/zap-urls-auth.json').urls || []
const nuclei = readJson('labs/lab5/nuclei/nuclei-summary.json')
const nikto = readJson('labs/lab5/nikto/nikto-summary.json')
const sqlmap = readJson('labs/lab5/sqlmap/sqlmap-summary.json')

console.log('=== DAST Multi-Tool Results Summary ===')
console.log('')
console.log('--- OWASP ZAP (Authenticated) ---')
console.log(`  Total alert instances: ${zap.length}`)
for (const [risk, count] of Object.entries(groupByRisk(zap)).sort()) console.log(`  ${risk}: ${count}`)
console.log(`  URLs discovered: ${zapUrls.length}`)
console.log('')
console.log('--- Nuclei-compatible template checks ---')
console.log(`  Total matches: ${nuclei.total}`)
for (const item of nuclei.bySeverity) console.log(`  ${item.severity}: ${item.count}`)
console.log('')
console.log('--- Nikto-compatible HTTP checks ---')
console.log(`  Total findings: ${nikto.total}`)
console.log('')
console.log('--- SQL injection validation ---')
console.log(`  Injectable parameters: ${sqlmap.injectableParameters}`)
console.log(`  Extracted user rows: ${sqlmap.extractedUserRows}`)
console.log('')
console.log('=== End of Summary ===')
NODE
