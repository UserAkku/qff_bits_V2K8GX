import { create } from 'zustand'
import * as api from '@/lib/api'
import type { LinkConfig, LinkSnapshot } from '@/lib/types'

interface LinkState {
  snapshot: LinkSnapshot | null
  error: string | null
  refresh: () => Promise<void>
  configure: (update: Partial<LinkConfig>) => Promise<void>
  provision: () => Promise<void>
}

export const useLink = create<LinkState>((set) => ({
  snapshot: null,
  error: null,
  refresh: async () => {
    try {
      set({ snapshot: await api.getLink(), error: null })
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) })
    }
  },
  configure: async (update) => set({ snapshot: await api.configureLink(update) }),
  provision: async () => set({ snapshot: await api.provisionLink() }),
}))

interface CredentialState {
  tokens: Record<string, string> | null
  load: () => Promise<Record<string, string>>
}

export const useCredentials = create<CredentialState>((set, get) => ({
  tokens: null,
  load: async () => {
    const existing = get().tokens
    if (existing) return existing
    const { sae_tokens } = await api.getCredentials()
    set({ tokens: sae_tokens })
    return sae_tokens
  },
}))
