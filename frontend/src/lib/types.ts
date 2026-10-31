// Shapes of the backend's JSON (see backend/src/server). Keep in sync with server/schemas.py and server/link.py.

export type DeviceName =
  | 'FakeTorino'
  | 'FakeFez'
  | 'FakeKingston'
  | 'FakeMarrakesh'
  | 'FakeBrisbane'
  | 'FakeSherbrooke'

export interface ChannelConfig {
  length_km: number
  attenuation_db_per_km: number
  detector_efficiency: number
  dark_count_prob: number
  depolarizing: number
  misalignment_deg: number
  device: DeviceName | null
}

export type EveBasis = 'random' | 'z' | 'x' | 'breidbart'

export interface AttackConfig {
  kind: 'none' | 'intercept_resend'
  fraction: number
  basis: EveBasis
}

export type TamperKind = 'none' | 'flip_estimate' | 'flip_bases'

export interface SessionRequest {
  protocol?: 'bb84'
  n_key?: number
  k_test?: number
  q_tol?: number
  seed?: number | null
  channel?: ChannelConfig | null
  attack?: AttackConfig | null
  tamper?: TamperKind | null
}

export interface LinkConfig {
  channel: ChannelConfig
  attack: AttackConfig
  tamper: TamperKind
}

export interface KmeSnapshot {
  kme_id: string
  sae_id: string
  outgoing_bits: number
  incoming_bits: number
  reserved_keys: number
  reserved_bits: number
  issued_bits: number
  delivered_bits: number
  deposited_bits: number
}

export interface LinkSnapshot {
  config: LinkConfig
  auth_pool: { alice_bytes: number; bob_bytes: number; consumed: number; replenished: number }
  kme: { alice: KmeSnapshot; bob: KmeSnapshot }
  busy: boolean
}

export type SessionStatus = 'queued' | 'running' | 'success' | 'aborted' | 'error'

export interface KeyLengthBreakdown {
  length: number
  n: number
  k: number
  q_tol: number
  mu: number
  eps: number
  eps_bar: number
  phase_error_bound: number
  entropy_term: number
  leak_ec: number
  correctness_cost: number
  secrecy_cost: number
  extra_cost: number
  asymptotic: number
}

export interface SessionStats {
  sent: number
  detected: number
  sifted_key: number
  sifted_test: number
  qber: number
  errors: number
  key_error_rate: number
  leak_ec: number
  ec_rounds: number
  reconciliation_efficiency: number
  verification_bits: number
  key_length: KeyLengthBreakdown
  classical_bytes: number
  classical_messages: number
  elapsed_s: number
  auth_burned_bytes: number
  auth_refill_bits: number
  delivered_key_bits: number
  p_x: number
  timings: Record<string, number>
}

export interface GroundTruth {
  attack: { name: string; fraction?: number; basis?: string } | null
  eve_attempted: number
  eve_correct: number
  eve_guess_accuracy?: number
  eve_info_bits: number
  eve_info_fraction?: number
}

export interface SessionResult {
  ok: boolean
  key_bits: number
  abort: { stage: string; reason: string; detail: Record<string, unknown> } | null
  stats: SessionStats
  ground_truth: GroundTruth
  deposited_bits: Record<string, number>
  auth_pool_bytes: number
  error?: string
}

export interface SessionSummary {
  id: string
  number: number
  status: SessionStatus
  created: number
  request: SessionRequest & { channel: ChannelConfig; attack: AttackConfig; tamper: TamperKind }
  result: SessionResult | null
}

export interface QkdEvent {
  stage: string
  kind: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: Record<string, any>
  t: number
  session: string
}

// ETSI GS QKD 014 V1.1.1 shapes
export interface EtsiStatus {
  source_KME_ID: string
  target_KME_ID: string
  master_SAE_ID: string
  slave_SAE_ID: string
  key_size: number
  stored_key_count: number
  max_key_count: number
  max_key_per_request: number
  max_key_size: number
  min_key_size: number
  max_SAE_ID_count: number
}

export interface EtsiKey {
  key_ID: string
  key: string // base64
}

export interface RelayEnvelope {
  id: string
  sender: string
  recipient: string
  mode: 'otp-wc' | 'aes-gcm'
  seq: number
  key_ids: string[]
  ciphertext: string // base64
  tag?: string // hex
  nonce?: string // hex
  aad?: string
}

export interface RelayLogEntry {
  n: number
  t: number
  relay_action: string
  delivered: number
  envelope: RelayEnvelope
}

export type UserName = 'alice' | 'bob'
export const SAE_ID: Record<UserName, string> = { alice: 'sae-alice', bob: 'sae-bob' }
export const PEER: Record<UserName, UserName> = { alice: 'bob', bob: 'alice' }
