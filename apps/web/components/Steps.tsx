const STEPS = [
  { id: 'create', label: 'Create' },
  { id: 'author', label: 'Author' },
  { id: 'publish', label: 'Sign & publish' }
] as const

type StepId = (typeof STEPS)[number]['id']

/** Progress through the three screens. Steps before the current one render as done. */
export function Steps ({ current }: { current: StepId }) {
  const at = STEPS.findIndex((s) => s.id === current)
  return (
    <ol className="steps" aria-label="Progress">
      {STEPS.map((s, i) => {
        const state = i < at ? 'done' : i === at ? 'on' : ''
        return (
          <li key={s.id} className={`step ${state}`} aria-current={i === at ? 'step' : undefined}>
            <span className="step-index" aria-hidden="true"><span>{i + 1}</span></span>
            {s.label}
          </li>
        )
      })}
    </ol>
  )
}
