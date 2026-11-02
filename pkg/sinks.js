// Sinks: the places where a value that came from a visitor does something to your server. The Shield looks at the request and guesses from
// its shape; a sink looks at what the value does at the moment it is used. Wrapping the few calls that matter (a SQL string you build, a
// path you open, a PostgREST filter, an object you hand to .insert()) catches an attack the Shield missed, with almost no false positives,
// because the question asked is exact: did this input change the STRUCTURE of the query, or leave the folder it should stay in?
//
//   import { createGuard } from '@bitora/guard'
//   import { createSinks } from '@bitora/guard/sinks'      (Node: it uses node:path)
//   const guard = createGuard({ secret: process.env.BITORA_SECRET })
//   const sink = createSinks(guard)
//
//   sink.sql(query, [req.query.id])          // the SQL text you built and the values the visitor controls
//   sink.path('/srv/uploads', req.query.f)   // the path inside the folder it must stay in
//   sink.filterValue(req.query.name)         // a value you put inside a PostgREST .or('name.eq.' + v)
//   sink.pick(req.body, ['name', 'email'])   // only the fields you allow reach .insert() / .update()
//
// In "observe" mode a sink never throws: it lets the call through and reports (the NAME of the sink, never the value). In "enforce" it throws
// a BlockedSinkError. Without an active licence, like the rest of the package, it does nothing. This code was written from the public idea of
// checking the structure of a query; it is not derived from any other firewall.
import path from 'node:path'

export class BlockedSinkError extends Error {
  constructor(sink) {
    super('blocked by @bitora/guard: unsafe ' + sink)
    this.name = 'BlockedSinkError'
    this.sink = sink
  }
}

// ---- a small SQL tokenizer: enough to tell whether a piece of text stayed inside one value ----
// Tokens: string literals ('...' with '' as an escaped quote), quoted identifiers ("..." or `...`), comments (-- # /* */), numbers, words and
// single punctuation marks. Whitespace is skipped.
export function tokenizeSql(sql) {
  const tokens = []
  const n = sql.length
  let i = 0
  while (i < n) {
    const c = sql[i]
    if (/\s/.test(c)) {
      i++
      continue
    }
    const start = i
    if (c === "'") {
      i++
      while (i < n) {
        if (sql[i] === "'" && sql[i + 1] === "'") i += 2
        else if (sql[i] === "'") {
          i++
          break
        } else if (sql[i] === '\\' && i + 1 < n) i += 2
        else i++
      }
      tokens.push({ type: 'string', start, end: i })
    } else if (c === '"' || c === '`') {
      i++
      while (i < n && sql[i] !== c) i++
      i = Math.min(n, i + 1)
      tokens.push({ type: 'ident', start, end: i })
    } else if (c === '-' && sql[i + 1] === '-') {
      while (i < n && sql[i] !== '\n') i++
      tokens.push({ type: 'comment', start, end: i })
    } else if (c === '#') {
      while (i < n && sql[i] !== '\n') i++
      tokens.push({ type: 'comment', start, end: i })
    } else if (c === '/' && sql[i + 1] === '*') {
      const close = sql.indexOf('*/', i + 2)
      i = close < 0 ? n : close + 2
      tokens.push({ type: 'comment', start, end: i })
    } else if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(sql[i + 1] || ''))) {
      while (i < n && /[0-9a-fx.eE]/.test(sql[i])) i++
      tokens.push({ type: 'number', start, end: i })
    } else if (/[A-Za-z_@$]/.test(c)) {
      while (i < n && /[A-Za-z0-9_@$]/.test(sql[i])) i++
      tokens.push({ type: 'word', start, end: i })
    } else {
      i++
      tokens.push({ type: 'punct', start, end: i })
    }
  }
  return tokens
}

// Did the text at [s, e) stay inside ONE token of the query (a string, a number, a word)? If it spans several, or it opened or closed a
// quote, or it started a comment, the visitor changed the structure of the statement.
function stayedInOneToken(tokens, s, e) {
  const over = tokens.filter((t) => t.start < e && t.end > s)
  if (over.length !== 1) return over.length === 0 // whitespace only: nothing to change
  const t = over[0]
  if (t.type === 'comment' || t.type === 'punct') return false
  return t.start <= s && t.end >= e
}

// sqlStructure says whether any of the inputs changed the structure of the SQL text where it appears in it.
export function sqlStructure(query, inputs) {
  const q = String(query)
  const tokens = tokenizeSql(q)
  for (const raw of inputs || []) {
    if (typeof raw !== 'string' && typeof raw !== 'number') continue
    const input = String(raw)
    if (input.length < 2 || input.length > 500) continue
    let from = 0
    for (let k = 0; k < 10; k++) {
      const at = q.indexOf(input, from)
      if (at < 0) break
      if (!stayedInOneToken(tokens, at, at + input.length)) return { injected: true }
      from = at + 1
    }
  }
  return { injected: false }
}

export function createSinks(guard) {
  const on = () => typeof guard?.licensed !== 'function' || guard.licensed()
  const enforcing = () => guard?.options?.mode === 'enforce'
  const flag = (name, a = {}) => {
    try {
      guard?.note?.('sink_blocked', { param: name, ip: a.ip, ipSource: a.ipSource })
    } catch {
      /* reporting never changes the outcome */
    }
    if (enforcing()) throw new BlockedSinkError(name)
  }

  return {
    // sql(query, inputs): throws (enforce) or reports (observe) if a value of the visitor changed the structure of the query you built.
    // Prefer parameterised queries; this is for the places where you still build SQL as text. Returns the query.
    sql(query, inputs, a) {
      if (on() && sqlStructure(query, inputs).injected) flag('sql', a)
      return query
    },

    // path(base, ...parts): the resolved path, which must stay inside base. Returns it.
    path(base, ...parts) {
      const root = path.resolve(base)
      const full = path.resolve(root, ...parts.map(String))
      if (on() && full !== root && !full.startsWith(root + path.sep)) flag('path')
      return full
    },

    // filterValue(v): a value you are about to put inside a PostgREST filter string, like .or('name.eq.' + v). A comma or a parenthesis in it
    // adds conditions to the filter. Returns the value, or (when it is unsafe and you are not enforcing) the value quoted so it stays one value.
    filterValue(value, a) {
      const v = String(value)
      if (!on() || !/[,()]/.test(v)) return v
      flag('postgrest-filter', a)
      return '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'
    },

    // pick(body, allowed): only the fields you list reach your insert or update. This is a fix, not a detection: the extra fields are always
    // dropped, and a visitor who sent some (role, is_admin, price…) is reported by field NAME.
    pick(body, allowed) {
      if (!on() || body === null || typeof body !== 'object') return body
      const out = {}
      const extra = []
      for (const k of Object.keys(body)) {
        if (allowed.includes(k)) out[k] = body[k]
        else extra.push(k)
      }
      if (extra.length) {
        try {
          guard?.note?.('sink_blocked', { param: 'mass-assignment' })
        } catch {
          /* ignore */
        }
      }
      return out
    },
  }
}
