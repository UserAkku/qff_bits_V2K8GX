# Design principles

The interface has to make an unfamiliar idea (a key that can reveal its own eavesdropper) understandable in a few minutes, and still feel like a tool a person would trust with a conversation. These rules come from the anti-slop design guidance the team adopted and are applied to this product specifically. The frontend is reviewed against the quality gate at the end of this file before each merge.

## Identity

A lab instrument that happens to carry a messenger. Dense, precise, quiet. The memorable thing is the **key-establishment instrument**: the live view where photons, bases, errors and leakage are visible and numbered. Everything around it stays calm so that view carries the weight.

Archetype: technical dense (the guidance's "Archetype B"), adapted. The accent colours are not decoration: each carries a meaning that is used consistently across the whole app.

| Token | Value | Meaning |
| --- | --- | --- |
| `--bg-canvas` | `#0c0d0e` | page |
| `--bg-surface` | `#141618` | panels |
| `--bg-raised` | `#1a1d20` | popovers, selected rows |
| `--border` | `#24282c` | 1px hairlines, the only containment device |
| `--text` / `--text-2` / `--text-3` | `#e6edf3` / `#9aa4af` / `#6e7781` | hierarchy |
| `--key` | `#34d399` | key material exists, verified, safe to use |
| `--eve` | `#f59e0b` | an adversary, a failed check, tampering |
| `--basis-z` / `--basis-x` / `--basis-y` | `#60a5fa` / `#f472b6` / `#a78bfa` | measurement bases; also differ in glyph so colour is never the only cue |
| `--sim` | `#c4b5fd` outline | the "simulated" badge, always visible |

A light theme exists for `prefers-color-scheme: light` with the same semantic names. Contrast is checked at AA for text and for the basis colours on both canvases.

## Type

Two families, no more: **IBM Plex Sans** for text and headings, **JetBrains Mono** for data (bits, hex, key IDs, numbers). `font-variant-numeric: tabular-nums` on every number. Body line length at most 72ch. Sentence case everywhere; no tracked-out capitals, no eyebrow labels above headings that already say what they are.

Scale: 12 / 13 / 14 / 16 / 20 / 28 px; weights 400, 500, 600.

## Layout

One application shell: a slim left rail (Chat, Key lab, Experiments, Security model), a page header with the single global control bar for the page, and a scrollable main area at most 1280px wide. The 8-pt grid throughout; nested radii follow `inner = outer - padding`.

- **Chat**: two linked conversation panes (Alice, Bob) side by side, the relay's view between them as a narrow ledger of exactly what crossed the wire. Below 900px the panes stack.
- **Key lab**: left, the pipeline (stages with live counts); right, the knowledge ledger (what Alice, Bob, Eve and the public each know). The control bar holds channel, Eve and run settings.
- **Experiments**: one control bar (experiment, parameters), charts with theory overlays, tabular results underneath.
- **Security model**: a plain document with a threat-model table. No hero, no marketing.

Rules that apply everywhere:

- One primary action per section; at most three secondary. Everything used less than often goes in a menu.
- One source of truth per metric (the pool gauge is shown once, in the shell header).
- Page-level filters live in the control bar, never inside individual panels.
- Wrapping a single value in a bordered card is not allowed; whitespace groups.

## Banned

Purple or indigo blurred blobs, glow borders, identical three-card grids, emoji as icons, invented statistics, uppercase eyebrow labels, one word emphasised in a headline, giant decorative visuals with no data, placeholder images, and any security claim that the simulation cannot support. Icons are Lucide at one stroke weight.

## Interaction

Every interactive element has default, hover, focus-visible, active (`scale(0.97)`, 80ms), disabled, loading, error and success states. Transitions are 120–180ms `ease-out` (`cubic-bezier(0.23, 1, 0.32, 1)`); never `ease-in`. Anything a user does constantly (selecting a message, switching a tab) does not animate. Popovers grow from their trigger. `prefers-reduced-motion` removes the photon animation and replaces it with static, numbered states.

Motion is reserved for meaning: photons travelling in the pipeline, a key block being consumed, the QBER needle crossing the abort line. Nothing animates on page load.

## Words

Plain language in the user's terms: "key pool", "error rate", "someone may be listening". Errors say what happened and what to do. An action keeps one name from button to toast ("Start key exchange" produces "Key exchange started" and then "Key exchange finished"). The word **simulated** is always visible on any surface that shows a key, because it is true and because the rules of this project forbid implying otherwise.

## Quality gate (score 1-5, all axes at least 4 before merge)

1. **No slop**: none of the banned patterns above.
2. **Speed and hierarchy**: 1 primary and at most 3 secondary actions per section; no duplicated metrics or controls.
3. **Typography**: two families, tabular numerals, sentence case, line length at most 72ch.
4. **Geometry**: 4/8px grid, nested radii, card padding at least 16px.
5. **Motion**: under 200ms, no ease-in, active-state feedback, no load animation.
6. **Accessibility**: visible focus on everything, labels on icon buttons, semantic landmarks, basis shown by glyph as well as colour, keyboard-complete flows, reduced motion honoured.
7. **Responsive**: stacks cleanly, no horizontal page scroll, 44px touch targets, tables become lists on narrow screens.
