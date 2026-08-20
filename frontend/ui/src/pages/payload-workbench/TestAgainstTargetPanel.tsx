import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Crosshair, RefreshCw, AlertTriangle, CheckCircle2 } from 'lucide-react'
import { api } from '../../api'
import { ActionButton } from '../../components/ui/ActionButton'
import { ErrorState } from '../../components/ui/ErrorState'

interface TestAgainstTargetPanelProps {
  output: string
}

export function TestAgainstTargetPanel({ output }: TestAgainstTargetPanelProps) {
  const [open, setOpen] = useState(false)
  const [targetUrl, setTargetUrl] = useState('')
  const [method, setMethod] = useState<'GET' | 'POST'>('GET')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<{
    potentialVulnerability: boolean
    responseSize: number
    recommendations: string[]
  } | null>(null)

  const lines = useMemo(() => output.split('\n').filter(l => l.trim().length > 0), [output])
  const [selectedLine, setSelectedLine] = useState(lines[0] ?? '')
  const [lastOutput, setLastOutput] = useState(output)

  if (output !== lastOutput) {
    setLastOutput(output)
    setSelectedLine(lines[0] ?? '')
  }

  const payload = lines.length > 1 ? selectedLine : (lines[0] ?? '')

  async function run() {
    if (!targetUrl.trim() || !payload) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await api.testPayloadAgainstTarget(payload, targetUrl.trim(), method)
      if (!res.success || !res.ai_analysis) {
        setError(res.error ?? 'Test failed.')
        return
      }
      setResult({
        potentialVulnerability: res.ai_analysis.potential_vulnerability,
        responseSize: res.ai_analysis.response_size,
        recommendations: res.ai_analysis.recommendations,
      })
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="payload-test-target">
      <button type="button" className="payload-test-target-toggle" onClick={() => setOpen(prev => !prev)}>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <Crosshair size={12} />
        Test against target
      </button>
      {open && (
        <>
          {lines.length > 1 && (
            <label className="workbench-field">
              <span className="workbench-field-label">Payload line to test</span>
              <select className="input input-full mono" value={selectedLine} onChange={e => setSelectedLine(e.target.value)}>
                {lines.map((line, i) => (
                  <option key={i} value={line}>
                    {line.length > 80 ? `${line.slice(0, 80)}…` : line}
                  </option>
                ))}
              </select>
              <span className="workbench-field-hint">Output has multiple lines — pick which one to send to the target.</span>
            </label>
          )}
          <label className="workbench-field">
            <span className="workbench-field-label">Target URL *</span>
            <input
              className="input input-full mono"
              placeholder="http://127.0.0.1:PORT/path?param=val"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
            />
            <span className="workbench-field-hint">A live target you're authorized to test — e.g. an OctoRig lab.</span>
          </label>
          <label className="workbench-field">
            <span className="workbench-field-label">Method</span>
            <select className="input input-full" value={method} onChange={e => setMethod(e.target.value as 'GET' | 'POST')}>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
          </label>

          <div className="workbench-actions">
            <ActionButton variant="primary" onClick={run} disabled={loading || !targetUrl.trim()}>
              {loading ? <><RefreshCw size={13} className="spin" /> Testing…</> : <><Crosshair size={13} /> Test</>}
            </ActionButton>
          </div>

          {error && <ErrorState message={error} />}

          {result && (
            <div className="workbench-note">
              {result.potentialVulnerability
                ? <><AlertTriangle size={12} color="var(--red)" style={{ verticalAlign: -2, marginRight: 4 }} />Payload was reflected in the response (response size: {result.responseSize} bytes).</>
                : <><CheckCircle2 size={12} color="var(--green)" style={{ verticalAlign: -2, marginRight: 4 }} />No naive reflection detected (response size: {result.responseSize} bytes).</>}
              {result.recommendations.length > 0 && (
                <ul>
                  {result.recommendations.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}
