// What a model says back to your users. Two things leave through an AI feature that nobody meant to give away: the instructions you wrote for it
// (the system prompt) and anything secret that reached its context. This reads the model's OUTPUT, before you send it on:
//
//   canary(secret)            -> a token to put inside your system prompt. It is derived from your key, so every instance of your server knows it
//                                without sharing state, and nobody who has not seen the prompt can guess it.
//   scan(text, canary)        -> the KINDS found in the text: 'prompt-leak' (the canary came out), 'secret' (a key or connection string) and 'card'
//                                (a number that passes the Luhn check). Never the text itself.
//   redact(text)              -> the text with secrets and card numbers replaced by [redacted].
//
// It is a pattern reader. A model can leak your prompt paraphrased, without the canary; this catches the verbatim copy, which is what most
// extraction attacks produce.
import { hasSecret, redactSecrets } from './leaks.js'

const CARD = /\b\d(?:[ -]?\d){12,18}\b/g

function luhn(digits) {
  let sum = 0
  let alt = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48
    if (alt) {
      n *= 2
      if (n > 9) n -= 9
    }
    sum += n
    alt = !alt
  }
  return sum % 10 === 0
}

function cards(text) {
  const out = []
  for (const m of text.matchAll(CARD)) {
    const d = m[0].replace(/[ -]/g, '')
    if (d.length >= 13 && d.length <= 19 && !/^(\d)\1+$/.test(d) && luhn(d)) out.push(m[0])
  }
  return out
}

export async function canary(secret) {
  const key = await globalThis.crypto.subtle.importKey('raw', new TextEncoder().encode(String(secret || 'unlicensed')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, new TextEncoder().encode('bitora-canary-v1')))
  return 'bsc_' + [...mac.slice(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function scan(text, canaryToken) {
  const t = String(text ?? '').slice(0, 65536)
  const kinds = []
  if (canaryToken && t.includes(canaryToken)) kinds.push('prompt-leak')
  if (hasSecret(t)) kinds.push('secret')
  if (cards(t).length) kinds.push('card')
  return kinds
}

export function redact(text, canaryToken) {
  let t = redactSecrets(String(text ?? ''))
  for (const c of new Set(cards(t))) t = t.split(c).join('[redacted]')
  if (canaryToken) t = t.split(canaryToken).join('[redacted]')
  return t
}
