import { useId, type ReactNode } from 'react'

interface FieldProps {
  label: string
  hint?: string
  children: (id: string) => ReactNode
}

export function Field({ label, hint, children }: FieldProps) {
  const id = useId()
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children(id)}
      {hint ? <span className="meta">{hint}</span> : null}
    </div>
  )
}
