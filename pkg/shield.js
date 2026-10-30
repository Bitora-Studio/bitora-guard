// The Shield: looks at what a request carries (path, query, a few headers and, when the adapter can read it, the JSON or
// form body) and scores it the way the OWASP Core Rule Set does: every rule that matches adds points (critical 5, error 4,
// warning 3, notice 2) and the request is flagged when the sum reaches the threshold (5 by default).
//
// It is defence in depth, not a cure: parameterised queries and output escaping remain the fix. The rules are written so
// that ordinary text does not trip them: an apostrophe, a quote or "--" alone means nothing (O'Brien, a password, an
// anchor); a rule needs the shape of an attack (a UNION SELECT, a tautology after a quote, a <script> tag...).
//
// Paranoia levels, as in CRS: level 1 has rules that almost never fire on legitimate traffic; level 2 adds rules that
// catch more and are wrong more often (a sentence that reads like SQL). Exclusions silence a rule on a parameter or route.
// Only the NAME of a parameter and the id of a rule leave the server, never the value.

const MAX_VALUES = 200
const MAX_LEN = 4000
const SQL_WORDS = 'select|insert|update|delete|drop|create|alter|truncate|exec|execute|union|merge|declare|waitfor|raiserror|shutdown'

// ---- decoding ----
function decode(v) {
  let s = String(v)
  for (let i = 0; i < 2; i++) {
    try {
      const d = decodeURIComponent(s.replace(/\+/g, ' '))
      if (d === s) break
      s = d
    } catch {
      break
    }
  }
  return s
}

// What a SQL parser would see: comments gone, whitespace collapsed, lower case.
const sqlView = (s) =>
  s
    .replace(/\/\*!?\d*([\s\S]*?)\*\//g, ' $1 ')
    .replace(/\s+/g, ' ')
    .toLowerCase()

const OPERATORS = new Set(['$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$where', '$regex', '$exists', '$or', '$and', '$nor', '$expr', '$function', '$accumulator', '$elemmatch'])

const PRIVATE_HOST =
  /^(localhost|0\.0\.0\.0|\[?::1\]?|\[?::ffff:[\da-f.:]+\]?|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|0x[\da-f]+|\d{8,10}|[a-z0-9.-]+\.(internal|local|localhost))$/i
const METADATA_HOST = /^(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254|\[fd00:ec2::254\])$/i

function urlHost(v) {
  const m = /^\s*(?:[a-z][a-z0-9+.-]*:)?\/\/(?:[^/@\s]*@)?(\[[^\]]+\]|[^/:?#\s]+)/i.exec(v)
  return m ? m[1] : ''
}

// ---- rules ----
// id, paranoia, points, where ('value' = values of parameters and the path, 'key' = names of parameters, 'header'), test.
export const RULES = [
  // SQL injection: needs SQL structure, not a punctuation mark.
  { id: 'sqli.union', pl: 1, pts: 5, w: 'value', test: (v) => /\bunion\b(?: all| distinct)? select\b/.test(sqlView(v)) },
  { id: 'sqli.tautology', pl: 1, pts: 5, w: 'value', test: (v) => /(?:['")]|\b\d+) ?(?:or|and) ?\(?(['"]?)(\w+)\1 ?(?:=|like) ?\1\2\b/.test(sqlView(v)) },
  { id: 'sqli.stacked', pl: 1, pts: 5, w: 'value', test: (v) => new RegExp(`['")\\d] ?; ?(?:${SQL_WORDS})\\b`).test(sqlView(v)) },
  // What sqlmap sends when it has no error to read (found by running it against the guard, deploy/lab-attack): conditions built with
  // CASE WHEN, comparisons of two numbers after AND/OR, ORDER BY n followed by a comment, and subqueries that start with a SQL token.
  { id: 'sqli.case-when', pl: 1, pts: 5, w: 'value', test: (v) => /\bcase when\b[^&]{0,80}[=<>][^&]{0,40}\bthen\b/.test(sqlView(v)) },
  { id: 'sqli.numeric-compare', pl: 1, pts: 5, w: 'value', test: (v) => /\b(?:and|or) \(*\d{2,}\)* ?= ?\(*\d{2,}/.test(sqlView(v)) },
  { id: 'sqli.order-by-comment', pl: 1, pts: 5, w: 'value', test: (v) => /\border by \d+ ?(?:--|#|\/\*)/.test(sqlView(v)) },
  { id: 'sqli.subquery', pl: 1, pts: 5, w: 'value', test: (v) => /\(\s?select (?:\(|@@|\*|\d|null\b|count\b|case\b|chr\b|char\b|concat\b|cast\b|top\b|distinct\b|user\b|version\b|database\b|sleep\b|extractvalue\b|updatexml\b)/.test(sqlView(v)) },
  { id: 'sqli.function', pl: 1, pts: 5, w: 'value', test: (v) => /\b(?:sleep|benchmark|pg_sleep|load_file|extractvalue|updatexml|dbms_pipe\.receive_message)\s?\(|\bwaitfor delay\b/.test(sqlView(v)) },
  { id: 'sqli.schema', pl: 1, pts: 4, w: 'value', test: (v) => /\b(?:information_schema|pg_catalog|sqlite_master|sysobjects|mysql\.user)\b/.test(sqlView(v)) },
  { id: 'sqli.comment-after-quote', pl: 2, pts: 3, w: 'value', test: (v) => /['"] ?(?:--(?: |$)|#$|\/\*)/.test(sqlView(v)) && /['"]/.test(v) && /(?:\b(?:or|and|union|select)\b)/.test(sqlView(v)) },
  { id: 'sqli.select-from', pl: 2, pts: 3, w: 'value', test: (v) => /\bselect\b.{1,120}\bfrom\b/.test(sqlView(v)) && /[*,()]|\bfrom \w+ ?(?:where|limit|order|$)/.test(sqlView(v)) },

  // Cross-site scripting
  { id: 'xss.script-tag', pl: 1, pts: 5, w: 'value', test: (v) => /<\s*script\b/i.test(v) },
  { id: 'xss.event-handler', pl: 1, pts: 5, w: 'value', test: (v) => /<[a-z][^>]*[\s/"']on[a-z]{3,20}\s*=/i.test(v) },
  { id: 'xss.javascript-url', pl: 1, pts: 5, w: 'value', test: (v) => /^\s*(?:javascript|vbscript)\s*:\s*[\w.$]+\s*\(/i.test(v.replace(/[\t\n\r]/g, '')) || /(?:href|src|action)\s*=\s*["']?\s*javascript:/i.test(v) },
  { id: 'xss.dangerous-tag', pl: 2, pts: 4, w: 'value', test: (v) => /<\s*(?:iframe|object|embed|meta|link|base|form|svg|math)\b[^>]*>/i.test(v) },

  // Path traversal and file inclusion
  { id: 'lfi.traversal', pl: 1, pts: 5, w: 'value', test: (v) => /(?:\.\.[/\\]){2,}/.test(v) },
  { id: 'lfi.sensitive-file', pl: 1, pts: 5, w: 'value', test: (v) => /\/etc\/(?:passwd|shadow|hosts)\b|\/proc\/self\/|\bboot\.ini\b|\bwindows\\(?:system32|win\.ini)/i.test(v) },
  { id: 'lfi.wrapper', pl: 1, pts: 5, w: 'value', test: (v) => /^\s*(?:php|phar|expect|gopher|dict|ldap|jar|file):\/\//i.test(v) || /php:\/\/(?:filter|input)/i.test(v) },
  { id: 'lfi.null-byte', pl: 1, pts: 4, w: 'value', test: (v) => v.includes('\0') },

  // Command injection
  { id: 'rce.shell', pl: 1, pts: 5, w: 'value', test: (v) => /(?:[;|&`]|\$\(|\|\||&&) ?(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|zsh|powershell|cmd(?:\.exe)?|python3?|perl|ruby|php|rm|chmod|chown)\b(?: +-\w| +\/\w| +\.\.?\/| +https?:| *(?:$|[;|&)`]))/.test(v) },
  { id: 'rce.log4shell', pl: 1, pts: 5, w: 'any', test: (v) => /\$\{\s*(?:jndi|\$\{|lower|upper|env|sys)[:\s}]/i.test(v) },
  { id: 'rce.function-call', pl: 2, pts: 3, w: 'value', test: (v) => /\b(?:eval|system|passthru|shell_exec|popen|proc_open|assert)\s?\(/i.test(v) },

  // NoSQL operators and prototype pollution arrive as parameter NAMES
  { id: 'nosql.operator', pl: 1, pts: 5, w: 'key', test: (k) => OPERATORS.has(k.toLowerCase()) || /\[(\$[a-z]+)\]/i.test(k) && OPERATORS.has(/\[(\$[a-z]+)\]/i.exec(k)[1].toLowerCase()) },
  { id: 'proto.pollution', pl: 1, pts: 5, w: 'key', test: (k, n) => k === '__proto__' || /(?:^|\.)constructor\.prototype(?:\.|$)/.test(n || k) || /__proto__/.test(k) },

  // A parameter that carries a URL aimed at the inside of the network (SSRF)
  { id: 'ssrf.metadata', pl: 1, pts: 5, w: 'value', test: (v) => METADATA_HOST.test(urlHost(v)) },
  { id: 'ssrf.internal-host', pl: 2, pts: 3, w: 'value', test: (v) => PRIVATE_HOST.test(urlHost(v)) },

  // Template injection: a weak signal on its own
  { id: 'ssti.expression', pl: 2, pts: 2, w: 'value', test: (v) => /\{\{[^}]{0,60}(?:\d ?[*+\-/] ?\d|constructor|__class__|self\.|config)[^}]*\}\}|<%=?[^%]{1,60}%>|#\{[^}]{1,60}\}/.test(v) },

  // Tools that announce themselves
  { id: 'scanner.agent', pl: 1, pts: 5, w: 'agent', test: (v) => /\b(?:sqlmap|nikto|nuclei|acunetix|nessus|masscan|zgrab|wpscan|dirbuster|gobuster|feroxbuster|ffuf|hydra|havij|burpcollaborator|netsparker|openvas|w3af)\b/i.test(v) },
]

// A parameter or a body, flattened to [{ name, value }] and the names of every key. Values are decoded; sizes are capped.
export function flatten(source, prefix, out, depth = 0) {
  if (out.values.length >= MAX_VALUES || depth > 12) return
  if (source === null || source === undefined) return
  if (typeof source === 'string' || typeof source === 'number' || typeof source === 'boolean') {
    out.values.push({ name: prefix, value: String(source).slice(0, MAX_LEN) })
    return
  }
  if (typeof source !== 'object') return
  const keys = Array.isArray(source) ? source.map((_, i) => String(i)) : Object.keys(source)
  for (const k of keys.slice(0, MAX_VALUES)) {
    const name = prefix ? prefix + '.' + k : k
    if (!Array.isArray(source)) out.keys.push({ name, key: k })
    flatten(source[k], name, out, depth + 1)
  }
}

function queryParams(search) {
  const out = []
  for (const part of String(search || '').replace(/^\?/, '').split('&').slice(0, MAX_VALUES)) {
    if (!part) continue
    const i = part.indexOf('=')
    const rawKey = i < 0 ? part : part.slice(0, i)
    const rawVal = i < 0 ? '' : part.slice(i + 1)
    out.push([decode(rawKey), decode(rawVal).slice(0, MAX_LEN)])
  }
  return out
}

const safeName = (n) => String(n).replace(/[^\w.$\[\]-]/g, '').slice(0, 60)

export function createShield(cfg = {}) {
  const level = cfg.paranoia === 2 ? 2 : 1
  const exclusions = cfg.exclusions || []
  const rules = RULES.filter((r) => r.pl <= level)

  const excluded = (route, name, id) =>
    exclusions.some(
      (x) =>
        (!x.match || route.startsWith(x.match)) &&
        (!x.params || x.params.some((p) => name === p || name.startsWith(p + '.'))) &&
        (!x.rules || x.rules.some((r) => id === r || id.startsWith(r + '.'))),
    )

  // input: { path, search, body, agent, referer }. Returns the score and what matched (rule ids and parameter NAMES).
  function scan(input) {
    const route = input.path || '/'
    const out = { values: [], keys: [] }
    out.values.push({ name: 'path', value: decode(route).slice(0, MAX_LEN) })
    for (const [k, v] of queryParams(input.search)) {
      out.keys.push({ name: 'query.' + k, key: k })
      out.values.push({ name: 'query.' + k, value: v })
    }
    if (input.body && typeof input.body === 'object') flatten(input.body, 'body', out)
    else if (typeof input.body === 'string') out.values.push({ name: 'body', value: input.body.slice(0, MAX_LEN) })
    const hits = new Map() // rule id -> { points, param }
    const add = (r, name) => {
      if (hits.has(r.id) || excluded(route, name, r.id)) return
      hits.set(r.id, { points: r.pts, param: name })
    }
    for (const { name, value } of out.values) {
      if (!value) continue
      const v = decode(value)
      for (const r of rules) if ((r.w === 'value' || r.w === 'any') && safely(r, v)) add(r, name)
    }
    for (const { name, key } of out.keys) for (const r of rules) if (r.w === 'key' && safely(r, key, name)) add(r, name)
    for (const [name, v] of [['header.user-agent', input.agent], ['header.referer', input.referer]]) {
      if (!v) continue
      for (const r of rules) if ((r.w === 'agent' && name === 'header.user-agent') || r.w === 'any') if (safely(r, decode(v))) add(r, name)
    }
    let score = 0
    const matched = []
    for (const [id, h] of hits) {
      score += h.points
      matched.push({ id, param: safeName(h.param) })
    }
    return { score, matched }
  }
  return { scan, level, threshold: cfg.threshold || 5 }
}

function safely(r, v, n) {
  try {
    return r.test(v, n)
  } catch {
    return false
  }
}
