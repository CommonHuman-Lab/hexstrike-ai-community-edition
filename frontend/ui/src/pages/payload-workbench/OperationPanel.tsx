import { useState } from 'react'
import { Copy, Check, Play, RefreshCw, ListPlus, Download, Send } from 'lucide-react'
import { api } from '../../api'
import type { PayloadWorkbenchOperation } from '../../api'
import { downloadWorkbenchOutput } from '../workbench/fileIO'
import { SendToLootModal } from '../../components/modals/SendToLootModal'
import { ActionButton } from '../../components/ui/ActionButton'
import { Tooltip } from '../../components/ui/Tooltip'
import { ErrorState } from '../../components/ui/ErrorState'
import { useToast } from '../../components/feedback/ToastProvider'
import { TestAgainstTargetPanel } from './TestAgainstTargetPanel'

interface OperationPanelProps {
  operation: PayloadWorkbenchOperation
  onAddToRecipe: (operation: PayloadWorkbenchOperation, params: Record<string, string>, inputValue: string) => void
  initialInput?: string
}

export function OperationPanel({ operation, onAddToRecipe, initialInput }: OperationPanelProps) {
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(
      operation.params.map(p => [p.name, p.name === 'input' && initialInput ? initialInput : String(p.default ?? '')])
    )
  )
  const [sendToLootOpen, setSendToLootOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [output, setOutput] = useState<string | null>(null)
  const [outputMime, setOutputMime] = useState<string | undefined>(undefined)
  const [note, setNote] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [added, setAdded] = useState(false)
  const { pushToast } = useToast()

  function setValue(name: string, value: string) {
    setValues(prev => ({ ...prev, [name]: value }))
  }

  async function run() {
    setLoading(true)
    setError(null)
    setOutput(null)
    setOutputMime(undefined)
    setNote(null)
    try {
      const res = await api.payloadWorkbenchRun(operation.id, values)
      if (!res.success) {
        setError(res.error ?? 'Operation failed.')
        return
      }
      setOutput(res.output ?? '')
      setOutputMime(res.output_mime)
      setNote(res.note ?? null)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  function copyOutput() {
    if (!output) return
    if (!navigator.clipboard) {
      pushToast('error', 'Clipboard is unavailable in this context.')
      return
    }
    navigator.clipboard.writeText(output).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }).catch(() => pushToast('error', 'Failed to copy output.'))
  }

  function addToRecipe() {
    const { input: rawInput, ...rest } = values
    onAddToRecipe(operation, rest, rawInput ?? '')
    setAdded(true)
    setTimeout(() => setAdded(false), 1500)
  }

  const canRun = !loading && operation.params.every(p => !p.required || values[p.name]?.trim())

  function handleKeyDown(e: React.KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && canRun) {
      e.preventDefault()
      void run()
    }
  }

  return (
    <div className="workbench-op-body" onKeyDown={handleKeyDown}>
      <div className="section-header">
        <h3>{operation.name}</h3>
      </div>
      <div className="workbench-op-content">
        <p className="verify-tool-desc">{operation.description}</p>

        <div className="workbench-form">
          {operation.params.filter(p => !p.hidden).map(p => (
            <label key={p.name} className="workbench-field">
              <span className="workbench-field-label">{p.label}{p.required ? ' *' : ''}</span>
              {p.type === 'textarea' && (
                <textarea
                  className="input workbench-textarea mono"
                  value={values[p.name] ?? ''}
                  onChange={e => setValue(p.name, e.target.value)}
                  rows={4}
                />
              )}
              {p.type === 'select' && (
                <select
                  className="input input-full"
                  value={values[p.name] ?? ''}
                  onChange={e => setValue(p.name, e.target.value)}
                >
                  {(p.choices ?? []).map(choice => (
                    <option key={choice} value={choice}>{choice}</option>
                  ))}
                </select>
              )}
              {(p.type === 'text' || p.type === 'number') && (
                <input
                  className="input input-full mono"
                  type={p.type}
                  value={values[p.name] ?? ''}
                  onChange={e => setValue(p.name, e.target.value)}
                />
              )}
              {p.help_text && <span className="workbench-field-hint">{p.help_text}</span>}
            </label>
          ))}
        </div>

        <div className="workbench-actions">
          <ActionButton variant="primary" onClick={run} disabled={!canRun}>
            {loading ? <><RefreshCw size={13} className="spin" /> Running…</> : <><Play size={13} /> Run</>}
          </ActionButton>
          <Tooltip content="Add this operation (with its current settings) to the recipe">
            <ActionButton variant="secondary" onClick={addToRecipe}>
              {added ? <><Check size={13} color="var(--green)" /> Added</> : <><ListPlus size={13} /> Add to Recipe</>}
            </ActionButton>
          </Tooltip>
        </div>

        {error && <ErrorState message={error} />}

        {output !== null && (
          <div className="workbench-output-wrap">
            <div className="workbench-output-header">
              <span className="workbench-field-label">Output</span>
              <span className="workbench-output-actions">
                <Tooltip content="Copy output">
                  <ActionButton variant="icon" onClick={copyOutput} aria-label="Copy output">
                    {copied ? <Check size={12} color="var(--green)" /> : <Copy size={12} />}
                  </ActionButton>
                </Tooltip>
                <Tooltip content="Download output">
                  <ActionButton
                    variant="icon"
                    onClick={() => downloadWorkbenchOutput(output, outputMime, operation.id)}
                    aria-label="Download output"
                  >
                    <Download size={12} />
                  </ActionButton>
                </Tooltip>
                <Tooltip content="Send output to Loot" placement="left">
                  <ActionButton variant="icon" onClick={() => setSendToLootOpen(true)} aria-label="Send output to Loot">
                    <Send size={12} />
                  </ActionButton>
                </Tooltip>
              </span>
            </div>
            <pre className="verify-result-output mono">{output}</pre>
            {note && <div className="workbench-note">{note}</div>}
            <TestAgainstTargetPanel output={output} />
          </div>
        )}

        {output !== null && (
          <SendToLootModal
            isOpen={sendToLootOpen}
            onClose={() => setSendToLootOpen(false)}
            defaultTitle={`${operation.name} output`}
            content={output}
            sourceTool="payload-workbench"
          />
        )}
      </div>
    </div>
  )
}
