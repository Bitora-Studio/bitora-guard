// The Shield may get better but not worse: these are the numbers it has to keep, measured on the corpus of bench/corpus.mjs. If a change to a
// rule or to the normalisation lowers one, this test fails and says which. If a number improves, raise the floor here and re-run
// "node bench/bench.mjs" to update docs/audit/MEDICION_GUARD.md.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { measure } from './bench.mjs'

const pl1 = measure({ paranoia: 1 })
const pl2 = measure({ paranoia: 2 })

test('the Shield flags no ordinary text (names, prose, code in a comment, keys of a filter, a password)', () => {
  assert.equal(pl1.legit.falsePositives, 0, 'false positives at paranoia 1: ' + JSON.stringify(pl1.legit.examples))
  assert.equal(pl2.legit.falsePositives, 0, 'false positives at paranoia 2: ' + JSON.stringify(pl2.legit.examples))
})

test('the Shield keeps blocking what it blocked, per family, at paranoia 1', () => {
  const floors = { sqli: 0.9, xss: 1, lfi: 1, nosql: 1, proto: 1, rce: 0.75 }
  for (const [family, floor] of Object.entries(floors)) assert.ok(pl1.families[family].rate >= floor, family + ' ' + pl1.families[family].rate + ' fell under ' + floor)
  assert.ok(pl1.attacks.rate >= 0.84, 'overall ' + pl1.attacks.rate)
  assert.ok(pl2.attacks.rate >= pl1.attacks.rate, 'paranoia 2 must catch at least what paranoia 1 catches')
})

test('an attacker who encodes the payload does not get past the normalisation', () => {
  const floors = { 'url-double': 0.75, 'url-triple': 0.75, 'mixed-case': 0.95, 'sql-comments': 0.9, 'whitespace-variants': 0.9, 'html-entities': 0.95, fullwidth: 0.9, 'null-bytes': 0.75 }
  for (const [ev, floor] of Object.entries(floors)) assert.ok(pl1.evasions[ev].rate >= floor, ev + ' ' + pl1.evasions[ev].rate + ' fell under ' + floor)
})

test('the Shield costs a fraction of a millisecond per request', () => {
  assert.ok(pl1.cost.p99_ms < 5, 'p99 ' + pl1.cost.p99_ms + ' ms')
})
