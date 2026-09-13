'use client'

import { useRouter } from 'next/navigation'
import { useEffect, useMemo, useState } from 'react'
import {
  alprRules, alprHumanReadable, TEMPLATES, composeHumanReadable, checkProseAlignment,
  stripRulesSummary, renderRulesSummary, normalizeIdentifier, type Rule
} from '@prm/schema'
import { hasAccount, getDraft, saveDraft, getPublished, type PolicyDraftState } from '../../lib/client/session'
import { Steps } from '../../components/Steps'
import { RulesTable } from '../../components/RulesTable'
import { Markdown } from '../../components/Markdown'

/**
 * Author — choose terms and write the explanation.
 *
 * Nothing here leaves the browser. The draft, including the plate, lives in localStorage on this
 * device only; it is used at signing time to compute a salted commitment, and the raw value is never
 * part of the published document.
 *
 * The prose/semantics guard has two layers, per @prm/schema/prose.ts: the generated summary is
 * appended at signing time and cannot be edited (structural), and the user's own narrative is
 * scanned for statements that contradict the rules (advisory).
 */
const DEFAULT_AGENCY = 'City of Whittier Police Department'

function defaultDraft (): PolicyDraftState {
  return {
    rules: alprRules({ state: 'CA' }),
    narrative: alprHumanReadable({ agency: DEFAULT_AGENCY, state: 'CA' }),
    jurisdictions: [...TEMPLATES.alpr.defaultJurisdictions('CA')],
    effectiveDate: new Date().toISOString().slice(0, 10)
  }
}

export default function AuthorPage () {
  const router = useRouter()
  const [ready, setReady] = useState(false)
  const [draft, setDraft] = useState<PolicyDraftState>(defaultDraft)
  const [tab, setTab] = useState<'human' | 'machine'>('human')
  const [plateError, setPlateError] = useState<string | null>(null)
  /** Version currently published from this device, if any: the draft is then an update to it. */
  const [publishedVersion, setPublishedVersion] = useState<number | null>(null)

  useEffect(() => {
    if (!hasAccount()) { router.replace('/create'); return }
    setDraft(getDraft() ?? defaultDraft())
    setPublishedVersion(getPublished()?.version ?? null)
    setReady(true)
  }, [router])

  useEffect(() => { if (ready) saveDraft(draft) }, [draft, ready])

  const divergences = useMemo(
    () => checkProseAlignment(draft.narrative, draft.rules),
    [draft.narrative, draft.rules]
  )
  const preview = useMemo(
    () => composeHumanReadable(draft.narrative, draft.rules),
    [draft.narrative, draft.rules]
  )

  function setRule (category: string, decision: Rule['decision']) {
    setDraft({
      ...draft,
      rules: draft.rules.map((r) => (r.category === category ? { ...r, decision } : r))
    })
  }

  function onPlate (value: string) {
    setDraft({ ...draft, plate: value })
    if (value.trim() === '') { setPlateError(null); return }
    try {
      normalizeIdentifier('us-license-plate', value)
      setPlateError(null)
    } catch (e) {
      setPlateError((e as Error).message)
    }
  }

  if (!ready) {
    return (
      <main>
        <Steps current="author" />
        <h1>Your policy</h1>
        <div className="skeleton" aria-hidden="true" />
      </main>
    )
  }

  return (
    <main>
      <Steps current="author" />
      <h1>Your policy</h1>
      <p className="lede">
        Starting from the California ALPR template. It authorizes the plate scan and the immediate
        hotlist check, and objects to what happens afterwards.
      </p>
      {publishedVersion !== null && (
        <div className="note info small">
          <b>Editing an update to version {publishedVersion}.</b>{' '}
          <span className="muted">
            Publishing will create version {publishedVersion + 1}. Version {publishedVersion} stays
            published and unchanged.
          </span>
        </div>
      )}

      <div className="panel">
        <h3>Vehicle</h3>
        <label htmlFor="plate">License plate (optional)</label>
        <input
          id="plate" type="text" placeholder="CA 7ABC123" autoComplete="off"
          value={draft.plate ?? ''} onChange={(e) => onPlate(e.target.value)}
        />
        {plateError
          ? <div className="note bad small">{plateError}</div>
          : (
            <p className="small muted">
              Stays on this device. The published policy contains only a salted commitment, so nobody
              can work out your plate from it — but you can prove to a specific agency that the policy
              covers your vehicle.
            </p>
            )}

        <label htmlFor="eff">Effective from</label>
        <input id="eff" type="text" value={draft.effectiveDate}
          onChange={(e) => setDraft({ ...draft, effectiveDate: e.target.value })} />
      </div>

      <h2>Terms</h2>
      <p className="small muted">
        These are what an automated system reads. Change them here, not in the text below.
      </p>
      <div className="panel tight">
        <table>
          <thead><tr><th>Category</th><th>Decision</th></tr></thead>
          <tbody>
            {draft.rules.map((r) => (
              <tr key={r.category}>
                <td>{r.category.replace('prm:', '').replace(/-/g, ' ')}</td>
                <td>
                  <select
                    aria-label={r.category}
                    value={r.decision}
                    onChange={(e) => setRule(r.category, e.target.value as Rule['decision'])}
                  >
                    <option value="allow">allow</option>
                    <option value="conditional">conditional</option>
                    <option value="deny">deny</option>
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2>Your explanation</h2>
      <p className="small muted">
        Written in your own words, and signed along with the terms. A generated summary of the terms
        above is appended automatically when you sign, so the two cannot drift apart.
      </p>
      <textarea
        aria-label="Policy explanation"
        value={draft.narrative}
        onChange={(e) => setDraft({ ...draft, narrative: stripRulesSummary(e.target.value) })}
      />

      {divergences.length > 0 && (
        <div className="note warn small">
          <b>Your words and your terms disagree.</b>
          <ul>
            {divergences.map((d) => (
              <li key={d.category}>
                {d.message}
                <div className="muted" style={{ marginTop: '.2rem' }}>“{d.quote}”</div>
              </li>
            ))}
          </ul>
          You can sign anyway — this is your document — but a reader and a machine would take away
          opposite meanings.
        </div>
      )}

      <h2>Preview</h2>
      <div className="tabs">
        <button className={tab === 'human' ? 'on' : ''} onClick={() => setTab('human')}>
          What a human will read
        </button>
        <button className={tab === 'machine' ? 'on' : ''} onClick={() => setTab('machine')}>
          What a machine will verify
        </button>
      </div>
      <div className="panel attached">
        {tab === 'human'
          ? <Markdown text={preview} />
          : <RulesTable rules={draft.rules} />}
      </div>

      <div className="row">
        <button onClick={() => router.push(publishedVersion !== null ? '/publish?update=1' : '/publish')}
          disabled={plateError !== null}>
          {publishedVersion !== null ? `Review and publish version ${publishedVersion + 1}` : 'Review and sign'}
        </button>
        <button className="secondary" onClick={() => setDraft(defaultDraft())}>
          Reset to template
        </button>
      </div>
      <p className="small muted" style={{ marginTop: '1.5rem' }}>
        Generated summary is {renderRulesSummary(draft.rules).length} characters and will be included
        in what you sign.
      </p>
    </main>
  )
}
