const STEPS = [
  { id: 'create', label: '1. Create' },
  { id: 'author', label: '2. Author' },
  { id: 'publish', label: '3. Sign & publish' }
] as const

export function Steps ({ current }: { current: (typeof STEPS)[number]['id'] }) {
  return (
    <nav className="steps" aria-label="Progress">
      {STEPS.map((s, i) => (
        <span key={s.id} className={s.id === current ? 'on' : ''}>
          {s.label}{i < STEPS.length - 1 ? '  ›' : ''}
        </span>
      ))}
    </nav>
  )
}
