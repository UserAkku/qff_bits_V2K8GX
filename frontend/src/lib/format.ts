export function formatBits(bits: number): string {
  if (bits >= 1_000_000) return `${(bits / 1_000_000).toFixed(2)} Mbit`
  if (bits >= 10_000) return `${(bits / 1000).toFixed(1)} kbit`
  if (bits >= 1000) return `${(bits / 1000).toFixed(2)} kbit`
  return `${Math.round(bits)} bit`
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(2)} MB`
  if (bytes >= 1000) return `${(bytes / 1000).toFixed(1)} kB`
  return `${bytes} B`
}

export const percent = (x: number, digits = 1) => `${(x * 100).toFixed(digits)}%`

export function formatDuration(seconds: number): string {
  return seconds < 1 ? `${Math.round(seconds * 1000)} ms` : `${seconds.toFixed(1)} s`
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

export function fromHex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16)
  return out
}

export function toBase64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

export function fromBase64(text: string): Uint8Array {
  const raw = atob(text)
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i)
  return out
}

export const shortId = (id: string) => id.slice(0, 8)
