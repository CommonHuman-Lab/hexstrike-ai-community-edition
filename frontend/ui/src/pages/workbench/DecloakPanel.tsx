import { useState } from 'react'
import { Wand2, Play, RefreshCw, Copy, Check, Download, Send } from 'lucide-react'
import { api } from '../../api'
import type { WorkbenchRecipeStepResult } from '../../api'
import { downloadWorkbenchOutput } from './fileIO'
import { SendToLootModal } from '../../components/modals/SendToLootModal'

export function DecloakPanel() {
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [output, setOutput] = useState<string | null>(null)
  const [steps, setSteps] = useState<WorkbenchRecipeStepResult[]>([])
  const [stoppedReason, setStoppedReason] = useState<string | undefined>(undefined)
  const [copied, setCopied] = useState(false)
  const [sendToLootOpen, setSendToLootOpen] = useState(false)

  async function run() {
    setLoading(true)
    setError(null)
    setOutput(null)
    setSteps([])
    setStoppedReason(undefined)
    try {
      const res = await api.workbenchDecloak(input)
      setSteps(res.steps ?? [])
      setStoppedReason(res.stopped_reason)
      if (!res.success) {
        setError(res.error ?? 'Decloak failed.')
        return
      }
      setOutput(res.output ?? '')
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  function copyOutput() {
    if (!output) return
    navigator.clipboard?.writeText(output).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }).catch(() => {})
  }

  return (
    <section className="workbench-panel">
      <div className="workbench-op-content">
        {steps.length === 0 && output === null && (
          <div className="workbench-panel-empty">
            <Wand2 size={28} color="var(--text-dim)" />
            <span className="workbench-panel-empty-title">Decloak</span>
            <span className="workbench-panel-empty-hint">
              Paste any encoded/nested value — Decloak auto-detects and peels back each layer
              (Base64, hex, gzip, URL-encoding, etc.) until it finds plaintext or a dead end.
            </span>
          </div>
        )}

        <label className="workbench-field">
          <span className="workbench-field-label">Input</span>
          <textarea
            className="input workbench-textarea mono"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && !loading) {
                e.preventDefault()
                void run()
              }
            }}
            rows={3}
          />
        </label>

        <div className="workbench-actions">
          <button className="workbench-run-btn" onClick={() => void run()} disabled={loading || !input.trim()}>
            {loading ? <><RefreshCw size={13} className="spin" /> Decloaking…</> : <><Play size={13} /> Decloak</>}
          </button>
        </div>

        {error && <div className="verify-error">{error}</div>}
        {stoppedReason === 'max_depth' && (
          <div className="workbench-note">Stopped at max depth — chain may be longer.</div>
        )}
        {stoppedReason === 'cycle' && (
          <div className="workbench-note">Stopped — decoding started repeating (cycle detected).</div>
        )}

        {steps.length > 0 && (
          <ol className="workbench-recipe-trace">
            {steps.map((s, i) => (
              <li key={i}>
                <span className="workbench-recipe-step-index">{i + 1}</span>
                <span className="workbench-field-label">{s.name ?? s.operation_id}</span>
                {s.input !== undefined && (
                  <span className="workbench-recipe-trace-input mono">
                    in: {s.input.length > 120 ? `${s.input.slice(0, 120)}…` : s.input}
                  </span>
                )}
                <span className="mono">{s.output}</span>
              </li>
            ))}
          </ol>
        )}

        {output !== null && (
          <div className="workbench-output-wrap">
            <div className="workbench-output-header">
              <span className="workbench-field-label">Final Output</span>
              <span className="workbench-output-actions">
                <button className="icon-btn" onClick={copyOutput} title="Copy output">
                  {copied ? <Check size={12} color="var(--green)" /> : <Copy size={12} />}
                </button>
                <button
                  className="icon-btn"
                  onClick={() => downloadWorkbenchOutput(output, undefined, 'decloak')}
                  title="Download output"
                >
                  <Download size={12} />
                </button>
                <button className="icon-btn" onClick={() => setSendToLootOpen(true)} title="Send output to Loot">
                  <Send size={12} />
                </button>
              </span>
            </div>
            <pre className="verify-result-output mono">{output}</pre>
          </div>
        )}
      </div>

      {output !== null && (
        <SendToLootModal
          isOpen={sendToLootOpen}
          onClose={() => setSendToLootOpen(false)}
          defaultTitle="Decloak output"
          content={output}
        />
      )}
    </section>
  )
}
