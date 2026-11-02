// Leaks in what your own server answers: a stack trace, a database error, a secret, a debug page. An attacker reads them as a map of your code
// and sometimes as a password. The detector reads the FIRST bytes of a text answer (JSON, HTML or plain text) and returns only the KIND of leak,
// never the text it matched, so nothing sensitive ever leaves your server through the report.
//
// It is a pattern reader: it can miss a leak that looks like nothing in the list, and it can flag a page that explains errors on purpose (a
// documentation page about stack traces). It says "this answer looks like it leaks"; the owner decides.

const MAX_SCAN = 16 * 1024

// Each kind: patterns that need to be seen together, or one that is distinctive enough alone.
const STACK = [
  /(?:\n|^)\s+at [\w$.<>\[\] ]+ \([^)\n]+:\d+:\d+\)(?:\n\s+at [^\n]+){1,}/, // Node: several "at fn (file:line:col)" lines
  /Traceback \(most recent call last\):/, // Python
  /(?:\n|^)\s+at (?:[\w$]+\.){2,}[\w$<>]+\([\w$.]+(?::\d+)?\)(?:\n\s+at [^\n]+){1,}/, // Java / Kotlin / .NET frames
  /Exception in thread "[^"]+"/,
  /Fatal error:.{0,160} in \/[^\s]+ on line \d+/, // PHP
  /Stack trace:\s*\n#0 /, // PHP
  /\.rb:\d+:in [`'][^'\n]+'/, // Ruby
  /goroutine \d+ \[(?:running|runnable|select)\]/, // Go
  / in [A-Za-z]:\\[^\n]+:line \d+/, // .NET
]

const DB = [
  /duplicate key value violates unique constraint/i,
  /\bsyntax error at or near\b/i,
  // Inside a JSON answer the quotes arrive escaped (\"orders\"), so a backslash may come before each quote.
  /\brelation \\?"[^"\\]+\\?" does not exist\b/i,
  /\bcolumn \\?"[^"\\]+\\?" (?:of relation \\?"[^"\\]+\\?" )?does not exist\b/i,
  /You have an error in your SQL syntax/i,
  /SQLSTATE\[[0-9A-Z]+\]/,
  /\bORA-\d{5}\b/,
  /\bSQLITE_(?:ERROR|CONSTRAINT)\b/,
  /Unclosed quotation mark after the character string/i,
  /\bMongo(?:Server|Network)?Error\b/,
  /\bPostgrestError\b|"code":"(?:42P01|42703|23505|42501)"/,
  /\bPG::[A-Z][A-Za-z]+Error\b|\bpsycopg2\.[A-Za-z.]+Error\b|\borg\.postgresql\.util\.PSQLException\b/,
  /\bUnknown column '[^']+' in '(?:field|where) list'/i,
]

const SECRET = [
  /\bsk_live_[A-Za-z0-9]{16,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/,
  /\bsb_secret_[A-Za-z0-9_-]{20,}/,
  /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s/@]+:[^@\s/]{3,}@/i, // a connection string with its password
]

const DEBUG = [/Werkzeug Debugger|<title>[^<]*DoesNotExist|Whoops!? There was an error|Ignition[^<]{0,40}Laravel|phpinfo\(\)|Django Debug Toolbar|Rails\.root:|Server Error in '\/' Application/i]

// A JWT whose payload says it is the service role of Supabase is a secret even though it looks like any token.
function serviceRoleJwt(text) {
  for (const m of text.matchAll(/\beyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{8,}/g)) {
    try {
      const b64 = m[1].replace(/-/g, '+').replace(/_/g, '/')
      const json = typeof atob === 'function' ? atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4)) : Buffer.from(b64, 'base64').toString()
      if (/"role"\s*:\s*"service_role"/.test(json)) return true
    } catch {
      /* not a JWT after all */
    }
  }
  return false
}

const anyOf = (list, text) => list.some((re) => re.test(text))

// scanResponse({ status, contentType, body }) -> the kinds of leak that answer shows: 'stack-trace', 'db-error', 'secret', 'debug'.
export function scanResponse({ status = 200, contentType = '', body = '' } = {}) {
  try {
    if (status < 100 || (contentType && !/(?:json|html|text|xml|javascript)/i.test(contentType))) return []
    let text = typeof body === 'string' ? body : body && typeof body.toString === 'function' ? body.toString('utf8') : ''
    if (!text) return []
    text = text.slice(0, MAX_SCAN)
    const out = []
    if (anyOf(STACK, text)) out.push('stack-trace')
    if (anyOf(DB, text)) out.push('db-error')
    if (anyOf(SECRET, text) || serviceRoleJwt(text)) out.push('secret')
    if (anyOf(DEBUG, text)) out.push('debug')
    return out
  } catch {
    return []
  }
}

// collector() gathers the first bytes of an answer as it is written, so an adapter can scan it when it ends. Chunks may be strings or bytes.
export function collector(limit = MAX_SCAN) {
  const parts = []
  let size = 0
  return {
    add(chunk) {
      if (size >= limit || chunk === undefined || chunk === null || typeof chunk === 'function') return
      const s = typeof chunk === 'string' ? chunk : typeof chunk.toString === 'function' ? chunk.toString('utf8') : ''
      const part = s.slice(0, limit - size)
      parts.push(part)
      size += part.length
    },
    text: () => parts.join(''),
  }
}
