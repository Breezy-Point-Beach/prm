import type { Rule } from '@prm/schema'
import { machineSummary } from '@prm/schema'
import type { Policy } from '@prm/schema'

/**
 * "What a machine will verify" — the rules matrix exactly as a verifier reads it.
 *
 * Deliberately plain. This is the authoritative view: if the prose and this table disagree, this
 * table is what an automated processor acts on, and the reader should be able to see that clearly.
 */
export function RulesTable ({ rules }: { rules: Rule[] }) {
  const rows = machineSummary({ rules } as Policy)
  return (
    <table>
      <thead>
        <tr><th>Category</th><th>Decision</th><th>Conditions</th></tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.category}>
            <td>
              {r.label}
              <div className="small muted mono">{r.category}</div>
            </td>
            <td><span className={`tag ${r.decision}`}>{r.decision}</span></td>
            <td className="small muted">{r.conditions || '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
