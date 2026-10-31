import type { ButtonHTMLAttributes } from 'react'

type Variant = 'default' | 'primary' | 'ghost' | 'eve'

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  small?: boolean
  loading?: boolean
  state?: 'error' | 'success'
}

/** All eight interaction states live in styles.css (.btn); this component only wires the props. */
export function Button({ variant = 'default', small, loading, state, className = '', ...rest }: Props) {
  const classes = ['btn', variant !== 'default' ? `btn-${variant}` : '', small ? 'btn-sm' : '', className]
    .filter(Boolean)
    .join(' ')
  return <button type="button" className={classes} aria-busy={loading || undefined} data-state={state} {...rest} />
}
