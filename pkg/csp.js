// A strict Content-Security-Policy, delivered as a report-only trial, and the collector of what browsers report about it.
//
//   cspHeaders({ nonce, reportPath, trustedTypes, integrity }) -> { nonce, headers }
//   parseReports(text, contentType)                            -> [{ directive, blocked }]
//
// The policy NEVER blocks anything: it is sent as Content-Security-Policy-Report-Only (and Integrity-Policy-Report-Only), so the browser only
// says what it would have refused. The reports go to a path of YOUR OWN site (first party, so ad blockers do not drop them), where the package
// reads them and tells Bitora only the KIND of violation (the directive) and the HOST involved. It never keeps the script sample, the full URL or
// the page's query string.

export function makeNonce() {
  const b = new Uint8Array(16)
  globalThis.crypto.getRandomValues(b)
  let s = ''
  for (const x of b) s += String.fromCharCode(x)
  return btoa(s)
}

export function cspHeaders({ nonce, reportPath = '/_bitora/r', trustedTypes = true, integrity = true } = {}) {
  const n = nonce || makeNonce()
  if (!/^[A-Za-z0-9+/=_-]{8,}$/.test(n)) throw new TypeError('the nonce must be base64 text of at least 8 characters')
  if (!/^\/[A-Za-z0-9/_.-]{0,100}$/.test(reportPath)) throw new TypeError('reportPath must be a path of your own site')
  const policy = [`script-src 'nonce-${n}' 'strict-dynamic'`, "object-src 'none'", "base-uri 'none'"]
  if (trustedTypes) policy.push("require-trusted-types-for 'script'")
  policy.push('report-uri ' + reportPath, 'report-to bitora')
  const headers = {
    'Content-Security-Policy-Report-Only': policy.join('; '),
    'Reporting-Endpoints': `bitora="${reportPath}"`,
  }
  if (integrity) headers['Integrity-Policy-Report-Only'] = 'blocked-destinations=(script), endpoints=(bitora)'
  return { nonce: n, headers }
}

// Pages of browser extensions and of the browser itself are not your site's scripts.
const IGNORED_SCHEMES = /^(chrome-extension|moz-extension|safari-extension|safari-web-extension|ms-browser-extension|about|chrome|resource|webkit-masked-url):/i
const MAX_REPORTS = 20

// Normalises the two formats a browser uses: the old application/csp-report ({ "csp-report": {...} }) and Reporting API
// (application/reports+json, a list of { type, body }). Returns only { directive, blocked }: the directive that was violated and what was
// blocked, as a host or one of the words inline, eval or sink. Nothing else of the report survives.
export function parseReports(text) {
  let data
  try {
    data = JSON.parse(String(text).slice(0, 65536))
  } catch {
    return []
  }
  const raw = []
  if (Array.isArray(data)) {
    for (const r of data) if (r && r.type === 'csp-violation' && r.body && typeof r.body === 'object') raw.push({ directive: r.body.effectiveDirective || r.body.violatedDirective, blocked: r.body.blockedURL ?? r.body.blockedUri, disposition: r.body.disposition })
  } else if (data && typeof data === 'object' && data['csp-report'] && typeof data['csp-report'] === 'object') {
    const b = data['csp-report']
    raw.push({ directive: b['effective-directive'] || b['violated-directive'], blocked: b['blocked-uri'] ?? b.blockedURL, disposition: b.disposition })
  }
  const out = []
  for (const r of raw.slice(0, MAX_REPORTS)) {
    const directive = String(r.directive || '').split(/\s+/)[0].toLowerCase()
    if (!/^[a-z-]{3,40}$/.test(directive)) continue
    let blocked = String(r.blocked ?? '').trim()
    if (IGNORED_SCHEMES.test(blocked)) continue
    if (blocked === '' || blocked === 'inline') blocked = 'inline'
    else if (blocked === 'eval' || blocked === 'wasm-eval') blocked = 'eval'
    else if (blocked === 'trusted-types-sink' || blocked === 'trusted-types-policy') blocked = 'sink'
    else {
      try {
        blocked = new URL(blocked).hostname.toLowerCase()
      } catch {
        continue
      }
      if (!blocked) continue
    }
    out.push({ directive, blocked })
  }
  return out
}
