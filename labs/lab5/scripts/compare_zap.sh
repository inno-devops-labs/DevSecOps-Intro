#!/bin/bash
set -euo pipefail

node <<'NODE'
const fs = require('fs')

function readJson (path) {
  if (!fs.existsSync(path)) {
    console.error(`Missing report: ${path}`)
    process.exit(1)
  }
  return JSON.parse(fs.readFileSync(path, 'utf8').replace(/^\uFEFF/, ''))
}

const noauth = readJson('labs/lab5/zap/zap-report-noauth.json').alerts || []
const auth = readJson('labs/lab5/zap/zap-report-auth.json').alerts || []
const noauthUrls = readJson('labs/lab5/zap/zap-urls-noauth.json').urls || []
const authUrls = readJson('labs/lab5/zap/zap-urls-auth.json').urls || []

function countRisk (alerts, risk) {
  return alerts.filter(alert => alert.risk === risk).length
}

console.log('=== ZAP Scan Comparison: Authenticated vs Unauthenticated ===')
console.log('')
console.log('Metric                 | Unauthenticated | Authenticated')
console.log('-----------------------|-----------------|---------------')
console.log(`URLs discovered        | ${noauthUrls.length}              | ${authUrls.length}`)
console.log(`Alert instances        | ${noauth.length}              | ${auth.length}`)
for (const risk of ['High', 'Medium', 'Low', 'Informational']) {
  console.log(`${risk.padEnd(22)} | ${String(countRisk(noauth, risk)).padEnd(15)} | ${countRisk(auth, risk)}`)
}
console.log('')
console.log('Authenticated-only seeded endpoints include:')
for (const url of authUrls.filter(url => /\/(rest\/admin\/application-configuration|rest\/user\/whoami|rest\/basket\/1|administration|profile)/.test(url)).sort()) {
  console.log(`- ${url}`)
}
NODE
