import type {
  EtsiKey,
  EtsiStatus,
  LinkConfig,
  LinkSnapshot,
  QkdEvent,
  RelayEnvelope,
  RelayLogEntry,
  SessionRequest,
  SessionSummary,
  UserName,
} from './types'

export class ApiError extends Error {
  status: number
  body: unknown
  constructor(status: number, message: string, body: unknown) {
    super(message)
    this.status = status
    this.body = body
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  })
  const text = await response.text()
  const body = text ? JSON.parse(text) : null
  if (!response.ok) {
    const message =
      (body && (body.message ?? body.detail)) ?? `${response.status} ${response.statusText}`
    throw new ApiError(response.status, typeof message === 'string' ? message : JSON.stringify(message), body)
  }
  return body as T
}

const post = <T>(path: string, body?: unknown, headers?: HeadersInit) =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body), headers })
const put = <T>(path: string, body: unknown) => request<T>(path, { method: 'PUT', body: JSON.stringify(body) })

// ---- link control ----
export const getLink = () => request<LinkSnapshot>('/api/link')
export const configureLink = (update: Partial<LinkConfig>) => put<LinkSnapshot>('/api/link/config', update)
export const provisionLink = () => post<LinkSnapshot>('/api/link/provision')
export const startSession = (req: SessionRequest) => post<SessionSummary>('/api/link/sessions', req)
export const listSessions = () => request<SessionSummary[]>('/api/link/sessions')
export const getSession = (id: string) =>
  request<SessionSummary & { events: QkdEvent[] }>(`/api/link/sessions/${id}`)

/** Follow a session's events (replays history first). Returns a function that closes the stream. */
export function followSession(
  id: string,
  onEvent: (event: QkdEvent) => void,
  onEnd: () => void,
): () => void {
  const source = new EventSource(`/api/link/sessions/${id}/events`)
  source.onmessage = (message) => onEvent(JSON.parse(message.data) as QkdEvent)
  source.addEventListener('end', () => {
    source.close()
    onEnd()
  })
  source.onerror = () => {
    source.close()
    onEnd()
  }
  return () => source.close()
}

// ---- credentials and KME (ETSI GS QKD 014) ----
export interface Credentials {
  sae_tokens: Record<string, string>
  kme_paths: Record<UserName, string>
}
export const getCredentials = () => request<Credentials>('/api/demo/credentials')

const bearer = (token: string): HeadersInit => ({ Authorization: `Bearer ${token}` })

export const kmeStatus = (who: UserName, peerSae: string, token: string) =>
  request<EtsiStatus>(`/kme/${who}/api/v1/keys/${peerSae}/status`, { headers: bearer(token) })

export const kmeEncKeys = (
  who: UserName,
  slaveSae: string,
  token: string,
  body: { number?: number; size?: number; extension_optional?: Record<string, unknown>[] },
) => post<{ keys: EtsiKey[] }>(`/kme/${who}/api/v1/keys/${slaveSae}/enc_keys`, body, bearer(token))

export const kmeDecKeys = (who: UserName, masterSae: string, token: string, keyIds: string[]) =>
  post<{ keys: EtsiKey[] }>(
    `/kme/${who}/api/v1/keys/${masterSae}/dec_keys`,
    { key_IDs: keyIds.map((key_ID) => ({ key_ID })) },
    bearer(token),
  )

export const kmeLedger = (who: UserName) =>
  request<{ snapshot: unknown; ledger: { t: number; kind: string; bits: number; key_id: string | null; direction: string | null }[] }>(
    `/api/kme/${who}/ledger`,
  )

// ---- relay ----
export const relaySend = (envelope: RelayEnvelope) => post<{ accepted: boolean; relay_action: string; delivered: number }>('/relay/send', envelope)
export const relayLog = () => request<{ mode: string; log: RelayLogEntry[] }>('/relay/log')
export const relayConfig = (mode: 'honest' | 'flip_ciphertext' | 'replay_last' | 'drop') => put<{ mode: string }>('/relay/config', { mode })
export const relayClear = () => request<{ cleared: boolean }>('/relay/messages', { method: 'DELETE' })

export function relaySocket(user: UserName, onEnvelope: (envelope: RelayEnvelope) => void): () => void {
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws'
  let socket: WebSocket | null = null
  let closed = false
  const open = () => {
    socket = new WebSocket(`${scheme}://${location.host}/relay/ws/${user}`)
    socket.onmessage = (message) => {
      const data = JSON.parse(message.data)
      if (data.type === 'message') onEnvelope(data.envelope as RelayEnvelope)
    }
    socket.onclose = () => {
      if (!closed) setTimeout(open, 1000)
    }
  }
  open()
  return () => {
    closed = true
    socket?.close()
  }
}
