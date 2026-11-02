// Measures the Shield: how much of an attack corpus it flags (per family and per way of sending it), how much ordinary text it flags by mistake, and
// what it costs per request. Run from internal/guardpkg:
//   node bench/bench.mjs            prints the numbers
//   node bench/bench.mjs --json     prints them as JSON
// The numbers are only as good as the corpus (corpus.mjs, written for this file): they say how the Shield does against THESE payloads, not
// against every attack. bench.test.mjs fails when a number gets worse than the thresholds recorded there.
import { pathToFileURL } from 'node:url'
// BENCH_SHIELD=/path/to/shield.js measures another version of the Shield (to compare with the one in the package).
const { createShield } = await import(process.env.BENCH_SHIELD ? pathToFileURL(process.env.BENCH_SHIELD).href : '../pkg/shield.js')
import { ATTACKS, CHANNELS, EVASIONS, LEGIT } from './corpus.mjs'

const enc = (s) => encodeURIComponent(s)

// A string is the value of one parameter; an object says how the same thing travels as keys in each channel.
function request(channel, value) {
  if (typeof value === 'object') return channel === 'query' ? { path: '/api/search', search: '?' + value.query } : { path: '/api/search', search: '', body: value.body }
  return channel === 'query' ? { path: '/api/search', search: '?q=' + enc(value) } : { path: '/api/search', search: '', body: { q: value } }
}
const label = (v) => (typeof v === 'object' ? v.query : v)

export function measure({ paranoia = 1, threshold = 5 } = {}) {
  const shield = createShield({ enabled: true, paranoia, threshold })
  const flagged = (req) => shield.scan(req).score >= shield.threshold
  const signalled = (req) => shield.scan(req).score > 0

  // "caught" = flagged (the request would be refused in enforce mode); "signal" = at least one rule matched (it adds points but may not be enough alone).
  const families = {}
  const byEvasion = {}
  const missed = []
  let total = 0
  let caught = 0
  let signal = 0
  for (const [family, payloads] of Object.entries(ATTACKS)) {
    const f = (families[family] = { total: 0, caught: 0, signal: 0 })
    for (const payload of payloads) {
      // A key-shaped attack has no string to encode: it is measured as it is sent.
      const evasions = typeof payload === 'object' ? { plain: EVASIONS.plain } : Object.fromEntries(Object.entries(EVASIONS).filter(([, e]) => e.families.includes(family)))
      for (const [evName, ev] of Object.entries(evasions)) {
        for (const channel of CHANNELS) {
          const req = request(channel, typeof payload === 'object' ? payload : ev.fn(payload))
          const hit = flagged(req)
          const sig = hit || signalled(req)
          f.total++
          total++
          const e = (byEvasion[evName] ||= { total: 0, caught: 0, signal: 0 })
          e.total++
          if (sig) {
            f.signal++
            e.signal++
            signal++
          }
          if (hit) {
            f.caught++
            e.caught++
            caught++
          } else if (evName === 'plain') missed.push({ family, channel, payload: label(payload), signal: sig })
        }
      }
    }
  }

  const falsePositives = []
  for (const text of LEGIT) {
    for (const channel of CHANNELS) {
      if (flagged(request(channel, text))) falsePositives.push({ channel, text: text.slice(0, 80), matched: shield.scan(request(channel, text)).matched.map((m) => m.id) })
    }
  }

  // Cost: the time one scan takes over the whole mixed corpus, as a distribution.
  const all = [...Object.values(ATTACKS).flat(), ...LEGIT]
  const times = []
  for (let round = 0; round < 5; round++) {
    for (const v of all) {
      const req = request('query', v)
      const t0 = performance.now()
      shield.scan(req)
      times.push(performance.now() - t0)
    }
  }
  times.sort((a, b) => a - b)
  const pct = (p) => times[Math.min(times.length - 1, Math.floor((p / 100) * times.length))]

  return {
    paranoia,
    attacks: { total, caught, rate: caught / total, signalRate: signal / total },
    families: Object.fromEntries(Object.entries(families).map(([k, v]) => [k, { ...v, rate: v.caught / v.total, signalRate: v.signal / v.total }])),
    evasions: Object.fromEntries(Object.entries(byEvasion).map(([k, v]) => [k, { ...v, rate: v.caught / v.total, signalRate: v.signal / v.total }])),
    plainMissed: missed,
    legit: { total: LEGIT.length * CHANNELS.length, falsePositives: falsePositives.length, rate: falsePositives.length / (LEGIT.length * CHANNELS.length), examples: falsePositives.slice(0, 12) },
    cost: { p50_ms: +pct(50).toFixed(4), p99_ms: +pct(99).toFixed(4), samples: times.length },
  }
}

const pctText = (x) => (x * 100).toFixed(1) + ' %'

export function report(r) {
  const lines = [`Paranoia ${r.paranoia}: bloquea ${pctText(r.attacks.rate)} y avisa de ${pctText(r.attacks.signalRate)} de ${r.attacks.total} envíos de ataque; marca por error ${r.legit.falsePositives} de ${r.legit.total} textos legítimos (${pctText(r.legit.rate)}); coste p50 ${r.cost.p50_ms} ms, p99 ${r.cost.p99_ms} ms.`, '', 'Por familia (envío sin y con cada ofuscación):']
  for (const [k, v] of Object.entries(r.families)) lines.push(`  ${k.padEnd(6)} bloquea ${pctText(v.rate).padStart(7)}  avisa ${pctText(v.signalRate).padStart(7)}  (${v.caught}/${v.total})`)
  lines.push('', 'Por forma de enviarlo:')
  for (const [k, v] of Object.entries(r.evasions)) lines.push(`  ${k.padEnd(20)} bloquea ${pctText(v.rate).padStart(7)}  avisa ${pctText(v.signalRate).padStart(7)}  (${v.caught}/${v.total})`)
  if (r.plainMissed.length) {
    lines.push('', 'Ataques en claro que NO se detectan:')
    for (const m of r.plainMissed.slice(0, 15)) lines.push(`  [${m.family}/${m.channel}] ${m.payload}${m.signal ? '   (avisa, no bloquea sola)' : '   (ni siquiera avisa)'}`)
  }
  if (r.legit.examples.length) {
    lines.push('', 'Textos legítimos marcados por error:')
    for (const m of r.legit.examples) lines.push(`  [${m.channel}] ${m.text}  -> ${m.matched.join(', ')}`)
  }
  return lines.join('\n')
}

if (import.meta.url === new URL(process.argv[1], 'file://').href || process.argv[1]?.endsWith('bench.mjs')) {
  const results = [measure({ paranoia: 1 }), measure({ paranoia: 2 })]
  console.log(process.argv.includes('--json') ? JSON.stringify(results, null, 2) : results.map(report).join('\n\n----\n\n'))
}
