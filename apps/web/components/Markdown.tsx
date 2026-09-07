/**
 * Minimal markdown rendering for the policy prose.
 *
 * Deliberately not a markdown library. The text being rendered is authored by the user and then
 * SIGNED, so the rendering has to be predictable and the attack surface small. Headings, bold,
 * italics, list items and paragraphs are all the template uses; everything else is shown as plain
 * text rather than interpreted.
 *
 * No raw HTML is ever passed through, so there is no dangerouslySetInnerHTML anywhere in this file.
 */
function inline (text: string, keyPrefix: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  const pattern = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g
  let last = 0
  let match: RegExpExecArray | null
  let i = 0
  while ((match = pattern.exec(text)) !== null) {
    if (match.index > last) out.push(text.slice(last, match.index))
    const token = match[0]
    const key = `${keyPrefix}-${i++}`
    if (token.startsWith('**')) out.push(<strong key={key}>{token.slice(2, -2)}</strong>)
    else if (token.startsWith('`')) out.push(<code key={key}>{token.slice(1, -1)}</code>)
    else out.push(<em key={key}>{token.slice(1, -1)}</em>)
    last = match.index + token.length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

export function Markdown ({ text }: { text: string }) {
  const blocks: React.ReactNode[] = []
  const lines = text.split('\n')
  let list: string[] = []
  let paragraph: string[] = []

  const flushList = () => {
    if (list.length === 0) return
    blocks.push(
      <ul key={`ul${blocks.length}`}>
        {list.map((item, i) => <li key={i}>{inline(item, `li${blocks.length}-${i}`)}</li>)}
      </ul>
    )
    list = []
  }
  const flushParagraph = () => {
    if (paragraph.length === 0) return
    const joined = paragraph.join(' ')
    blocks.push(<p key={`p${blocks.length}`}>{inline(joined, `p${blocks.length}`)}</p>)
    paragraph = []
  }

  for (const raw of lines) {
    const line = raw.trimEnd()
    if (line.trim() === '') { flushList(); flushParagraph(); continue }
    if (line.startsWith('---')) {
      flushList(); flushParagraph()
      blocks.push(<hr key={`hr${blocks.length}`} />)
      continue
    }
    const heading = /^(#{1,4})\s+(.*)$/.exec(line)
    if (heading) {
      flushList(); flushParagraph()
      const level = heading[1]?.length ?? 1
      const content = inline(heading[2] ?? '', `h${blocks.length}`)
      const Tag = (['h1', 'h2', 'h3', 'h4'][level - 1] ?? 'h4') as 'h1' | 'h2' | 'h3' | 'h4'
      blocks.push(<Tag key={`h${blocks.length}`}>{content}</Tag>)
      continue
    }
    const item = /^[-*]\s+(.*)$/.exec(line)
    if (item) { flushParagraph(); list.push(item[1] ?? ''); continue }
    flushList()
    paragraph.push(line.trim())
  }
  flushList(); flushParagraph()

  return <div className="prose">{blocks}</div>
}
