import { useEffect, useRef, useState } from 'react'
import type { Dispatch, SetStateAction } from 'react'
import {
  ArrowUp, ArrowDown, X, Play, RefreshCw, Copy, Check, Workflow, Pencil,
  Save, FolderOpen, FolderPlus, Trash2, GripVertical, SkipForward, Sparkles, Download,
  Link2, Upload, Eraser, Send,
} from 'lucide-react'
import { api } from '../../api'
import type { PayloadWorkbenchOperation, PayloadWorkbenchRecipeStepResult, PayloadWorkbenchSavedRecipe } from '../../api'
import { useDragReorder } from '../../hooks/useDragReorder'
import { usePersistentState } from '../../hooks/usePersistentState'
import { downloadWorkbenchOutput } from '../workbench/fileIO'
import { downloadRecipeAsFile, parseRecipeFile } from './recipeIO'
import { ConfirmActionModal } from '../../components/modals/ConfirmActionModal'
import { SendToLootModal } from '../../components/modals/SendToLootModal'
import { useToast } from '../../components/feedback/ToastProvider'
import { ActionButton } from '../../components/ui/ActionButton'
import { Tooltip } from '../../components/ui/Tooltip'
import { EmptyState } from '../../components/ui/EmptyState'
import { ErrorState } from '../../components/ui/ErrorState'
import { Badge } from '../../components/ui/Badge'
import { TestAgainstTargetPanel } from './TestAgainstTargetPanel'

export interface RecipeStep {
  stepId: string
  operationId: string
  operationName: string
  params: Record<string, string>
}

interface RecipePanelProps {
  recipe: RecipeStep[]
  setRecipe: Dispatch<SetStateAction<RecipeStep[]>>
  operations: PayloadWorkbenchOperation[]
  input: string
  setInput: Dispatch<SetStateAction<string>>
}

export function RecipePanel({ recipe, setRecipe, operations, input, setInput }: RecipePanelProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [output, setOutput] = useState<string | null>(null)
  const [outputMime, setOutputMime] = useState<string | undefined>(undefined)
  const [hasErrors, setHasErrors] = useState(false)
  const [steps, setSteps] = useState<PayloadWorkbenchRecipeStepResult[]>([])
  const [copied, setCopied] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editValues, setEditValues] = useState<Record<string, string>>({})
  const [continueOnError, setContinueOnError] = usePersistentState('nyxstrike_payload_workbench_continue_on_error', false)
  const [overrideEditingId, setOverrideEditingId] = useState<string | null>(null)
  const [overrideDraft, setOverrideDraft] = useState('')
  const [stepOverrides, setStepOverrides] = useState<Record<number, string>>({})

  const [savedRecipes, setSavedRecipes] = useState<PayloadWorkbenchSavedRecipe[]>([])
  const [savedLoading, setSavedLoading] = useState(false)
  const [savedError, setSavedError] = useState<string | null>(null)
  const [savingAs, setSavingAs] = useState(false)
  const [saveAsName, setSaveAsName] = useState('')
  const [renamingRecipeId, setRenamingRecipeId] = useState<string | null>(null)
  const [renameDraft, setRenameDraft] = useState('')
  const [loadedRecipeId, setLoadedRecipeId] = useState<string | null>(null)
  const [savingInPlace, setSavingInPlace] = useState(false)
  const [pendingDelete, setPendingDelete] = useState<PayloadWorkbenchSavedRecipe | null>(null)
  const [deletingRecipe, setDeletingRecipe] = useState(false)
  const [pendingClear, setPendingClear] = useState(false)
  const [sendToLootOpen, setSendToLootOpen] = useState(false)
  const importFileRef = useRef<HTMLInputElement>(null)
  const { pushToast } = useToast()

  function loadSavedRecipes() {
    setSavedLoading(true)
    setSavedError(null)
    api.payloadWorkbenchRecipes()
      .then(res => {
        if (!res.success) {
          setSavedError('Failed to load saved recipes.')
          return
        }
        setSavedRecipes(res.recipes)
      })
      .catch(e => setSavedError(String(e)))
      .finally(() => setSavedLoading(false))
  }

  useEffect(() => {
    loadSavedRecipes()
  }, [])

  function move(index: number, dir: -1 | 1) {
    setRecipe(prev => {
      const next = [...prev]
      const target = index + dir
      if (target < 0 || target >= next.length) return prev
      ;[next[index], next[target]] = [next[target], next[index]]
      return next
    })
    setStepOverrides({})
  }

  function reorderByStepId(draggedStepId: string, targetStepId: string) {
    setRecipe(prev => {
      const next = [...prev]
      const fromIndex = next.findIndex(s => s.stepId === draggedStepId)
      const toIndex = next.findIndex(s => s.stepId === targetStepId)
      if (fromIndex === -1 || toIndex === -1) return prev
      const [moved] = next.splice(fromIndex, 1)
      next.splice(toIndex, 0, moved)
      return next
    })
    setStepOverrides({})
  }

  const { dragHandlers, dragClassName } = useDragReorder(reorderByStepId)

  function remove(index: number) {
    setRecipe(prev => prev.filter((_, i) => i !== index))
    setEditingId(prev => (recipe[index]?.stepId === prev ? null : prev))
    setStepOverrides({})
  }

  function duplicate(index: number) {
    setRecipe(prev => {
      const step = prev[index]
      if (!step) return prev
      const copy: RecipeStep = { ...step, stepId: crypto.randomUUID(), params: { ...step.params } }
      const next = [...prev]
      next.splice(index + 1, 0, copy)
      return next
    })
    setStepOverrides({})
  }

  function clearRecipe() {
    setRecipe([])
    setLoadedRecipeId(null)
    setPendingClear(false)
    pushToast('info', 'Recipe cleared.')
  }

  function copyRecipeLink() {
    navigator.clipboard?.writeText(window.location.href)
      .then(() => pushToast('success', 'Recipe link copied.'))
      .catch(() => pushToast('error', 'Failed to copy link.'))
  }

  function exportRecipe() {
    downloadRecipeAsFile(recipe)
  }

  function triggerImport() {
    importFileRef.current?.click()
  }

  function handleImportFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      try {
        const { steps, skipped } = parseRecipeFile(String(reader.result ?? ''), operations)
        setRecipe(steps)
        setLoadedRecipeId(null)
        pushToast('success', skipped > 0 ? `Recipe imported — ${skipped} step(s) skipped (unknown operation).` : 'Recipe imported.')
      } catch (err) {
        pushToast('error', `Failed to import recipe: ${String(err)}`)
      }
    }
    reader.readAsText(file)
  }

  function startEdit(step: RecipeStep) {
    setEditingId(step.stepId)
    setEditValues({ ...step.params })
  }

  function cancelEdit() {
    setEditingId(null)
  }

  function saveEdit(stepId: string) {
    setRecipe(prev => prev.map(s => (s.stepId === stepId ? { ...s, params: editValues } : s)))
    setEditingId(null)
  }

  async function runRecipe(stopAfterStepIndex?: number) {
    setLoading(true)
    setError(null)
    setOutput(null)
    setOutputMime(undefined)
    setHasErrors(false)
    setSteps([])
    try {
      const res = await api.payloadWorkbenchRunRecipe(
        input,
        recipe.map(s => ({ operation_id: s.operationId, params: s.params })),
        { continueOnError, stopAfterStepIndex, stepInputOverrides: stepOverrides }
      )
      setSteps(res.steps ?? [])
      setHasErrors(!!res.has_errors)
      if (!res.success) {
        setError(res.error ?? 'Recipe failed.')
        return
      }
      setOutput(res.output ?? '')
      setOutputMime(res.output_mime)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  function run() {
    return runRecipe(undefined)
  }

  function runToStep(index: number) {
    return runRecipe(index)
  }

  function startOverride(index: number, current: string) {
    setOverrideEditingId(String(index))
    setOverrideDraft(stepOverrides[index] ?? current)
  }

  function cancelOverride() {
    setOverrideEditingId(null)
  }

  function saveOverride(index: number) {
    setStepOverrides(prev => ({ ...prev, [index]: overrideDraft }))
    setOverrideEditingId(null)
  }

  function clearOverride(index: number) {
    setStepOverrides(prev => {
      const next = { ...prev }
      delete next[index]
      return next
    })
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

  function startSaveAs() {
    setSaveAsName('')
    setSavingAs(true)
  }

  function cancelSaveAs() {
    setSavingAs(false)
  }

  async function confirmSaveAs() {
    const name = saveAsName.trim()
    if (!name) return
    const res = await api.createPayloadWorkbenchRecipe(
      name,
      recipe.map(s => ({ operation_id: s.operationId, params: s.params }))
    )
    if (res.success) {
      setSavingAs(false)
      setLoadedRecipeId(res.recipe?.recipe_id ?? null)
      loadSavedRecipes()
      pushToast('success', `Saved as "${name}".`)
    } else {
      pushToast('error', res.error ?? 'Failed to save recipe.')
    }
  }

  async function saveInPlace() {
    if (!loadedRecipeId) return
    setSavingInPlace(true)
    const res = await api.updatePayloadWorkbenchRecipe(loadedRecipeId, {
      steps: recipe.map(s => ({ operation_id: s.operationId, params: s.params })),
    })
    setSavingInPlace(false)
    if (res.success) {
      loadSavedRecipes()
      pushToast('success', 'Recipe saved.')
    } else {
      pushToast('error', res.error ?? 'Failed to save recipe.')
    }
  }

  function loadSavedRecipe(saved: PayloadWorkbenchSavedRecipe) {
    const loaded = saved.steps
      .map((s): RecipeStep | null => {
        const operation = operations.find(op => op.id === s.operation_id)
        if (!operation) return null
        return {
          stepId: crypto.randomUUID(),
          operationId: s.operation_id,
          operationName: operation.name,
          params: (s.params ?? {}) as Record<string, string>,
        }
      })
      .filter((s): s is RecipeStep => s !== null)
    setRecipe(loaded)
    setEditingId(null)
    setLoadedRecipeId(saved.recipe_id)
  }

  function startRenameRecipe(saved: PayloadWorkbenchSavedRecipe) {
    setRenamingRecipeId(saved.recipe_id)
    setRenameDraft(saved.name)
  }

  function cancelRenameRecipe() {
    setRenamingRecipeId(null)
  }

  async function confirmRenameRecipe(recipeId: string) {
    const name = renameDraft.trim()
    if (!name) return
    const res = await api.updatePayloadWorkbenchRecipe(recipeId, { name })
    if (res.success) {
      setRenamingRecipeId(null)
      loadSavedRecipes()
    } else {
      pushToast('error', res.error ?? 'Failed to rename recipe.')
    }
  }

  async function confirmDelete() {
    if (!pendingDelete) return
    setDeletingRecipe(true)
    const res = await api.deletePayloadWorkbenchRecipe(pendingDelete.recipe_id)
    setDeletingRecipe(false)
    if (res.success) {
      if (loadedRecipeId === pendingDelete.recipe_id) setLoadedRecipeId(null)
      setPendingDelete(null)
      loadSavedRecipes()
    } else {
      pushToast('error', res.error ?? 'Failed to delete recipe.')
    }
  }

  return (
    <section className={`workbench-recipe${recipe.length > 0 ? ' section' : ''}`}>
      {recipe.length > 0 && (
        <div className="section-header">
          <h3><Workflow size={14} style={{ marginRight: 6, verticalAlign: -2 }} />Recipe</h3>
          <span className="workbench-recipe-toolbar">
            <Tooltip content="Copy link to this recipe">
              <ActionButton variant="icon" onClick={copyRecipeLink} aria-label="Copy link to this recipe">
                <Link2 size={12} />
              </ActionButton>
            </Tooltip>
            <Tooltip content="Export recipe as a JSON file">
              <ActionButton variant="icon" onClick={exportRecipe} aria-label="Export recipe as a JSON file">
                <Download size={12} />
              </ActionButton>
            </Tooltip>
            <Tooltip content="Import recipe from a JSON file">
              <ActionButton variant="icon" onClick={triggerImport} aria-label="Import recipe from a JSON file">
                <Upload size={12} />
              </ActionButton>
            </Tooltip>
            <input
              ref={importFileRef}
              type="file"
              accept="application/json"
              className="workbench-hidden-file-input"
              onChange={handleImportFile}
            />
            <Tooltip content="Clear recipe">
              <ActionButton variant="icon" onClick={() => setPendingClear(true)} aria-label="Clear recipe">
                <Eraser size={12} />
              </ActionButton>
            </Tooltip>
          </span>
        </div>
      )}
      <div className="workbench-op-content">
        <div className="workbench-saved-recipes">
          <div className="workbench-saved-recipes-header">
            <span className="workbench-field-label"><FolderOpen size={12} style={{ marginRight: 4, verticalAlign: -2 }} />Saved Recipes</span>
            {recipe.length > 0 && !savingAs && (
              <span className="workbench-saved-recipe-actions">
                {loadedRecipeId && (
                  <Tooltip content="Save changes to the loaded recipe">
                    <ActionButton variant="icon" onClick={() => void saveInPlace()} disabled={savingInPlace} aria-label="Save changes to the loaded recipe">
                      <Save size={12} />
                    </ActionButton>
                  </Tooltip>
                )}
                <Tooltip content="Save as a new recipe">
                  <ActionButton variant="icon" onClick={startSaveAs} aria-label="Save as a new recipe">
                    <FolderPlus size={12} />
                  </ActionButton>
                </Tooltip>
              </span>
            )}
          </div>

          {savingAs && (
            <div className="workbench-saved-recipe-row workbench-saved-recipe-row--edit">
              <input
                className="input input-full mono"
                placeholder="Recipe name…"
                value={saveAsName}
                autoFocus
                onChange={e => setSaveAsName(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter') void confirmSaveAs()
                  if (e.key === 'Escape') cancelSaveAs()
                }}
              />
              <ActionButton variant="icon" onClick={() => void confirmSaveAs()} aria-label="Confirm"><Check size={12} /></ActionButton>
              <ActionButton variant="icon" onClick={cancelSaveAs} aria-label="Cancel"><X size={12} /></ActionButton>
            </div>
          )}

          {savedLoading && <div className="workbench-panel-empty-hint">Loading…</div>}
          {savedError && <ErrorState message={savedError} onRetry={loadSavedRecipes} />}

          {!savedLoading && savedRecipes.length === 0 && !savingAs && (
            <EmptyState title="No saved recipes yet." />
          )}

          {savedRecipes.map(saved => (
            <div key={saved.recipe_id} className="workbench-saved-recipe-row">
              {renamingRecipeId === saved.recipe_id ? (
                <>
                  <input
                    className="input input-full mono"
                    value={renameDraft}
                    autoFocus
                    onChange={e => setRenameDraft(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter') void confirmRenameRecipe(saved.recipe_id)
                      if (e.key === 'Escape') cancelRenameRecipe()
                    }}
                  />
                  <ActionButton variant="icon" onClick={() => void confirmRenameRecipe(saved.recipe_id)} aria-label="Confirm"><Check size={12} /></ActionButton>
                  <ActionButton variant="icon" onClick={cancelRenameRecipe} aria-label="Cancel"><X size={12} /></ActionButton>
                </>
              ) : (
                <>
                  <span className="workbench-saved-recipe-name mono" title={saved.name}>{saved.name}</span>
                  <span className="workbench-saved-recipe-actions">
                    <Tooltip content="Load into working recipe">
                      <ActionButton variant="icon" onClick={() => loadSavedRecipe(saved)} aria-label="Load into working recipe">
                        <FolderOpen size={12} />
                      </ActionButton>
                    </Tooltip>
                    <Tooltip content="Rename">
                      <ActionButton variant="icon" onClick={() => startRenameRecipe(saved)} aria-label="Rename">
                        <Pencil size={12} />
                      </ActionButton>
                    </Tooltip>
                    <Tooltip content="Delete">
                      <ActionButton variant="icon" onClick={() => setPendingDelete(saved)} aria-label="Delete">
                        <Trash2 size={12} />
                      </ActionButton>
                    </Tooltip>
                  </span>
                </>
              )}
            </div>
          ))}
        </div>

        {recipe.length === 0 ? (
          <EmptyState
            icon={<Workflow size={28} />}
            title="No recipe yet"
            description={'Use "Add to Recipe" on any operation to chain it here — each step\'s output feeds the next step\'s input.'}
          />
        ) : (
          <ol className="workbench-recipe-steps">
            {recipe.map((step, i) => {
              const operation = operations.find(op => op.id === step.operationId)
              const editableParams = operation?.params.filter(p => p.name !== 'input') ?? []
              const isEditing = editingId === step.stepId
              return (
                <li
                  key={step.stepId}
                  className={dragClassName(step.stepId, 'workbench-recipe-step-wrap')}
                  {...dragHandlers(step.stepId)}
                >
                  <div className="workbench-recipe-step">
                    <span className="workbench-recipe-step-drag" title="Drag to reorder">
                      <GripVertical size={12} />
                    </span>
                    <span className="workbench-recipe-step-index">{i + 1}</span>
                    <span className="workbench-recipe-step-name">{step.operationName}</span>
                    {Object.keys(step.params).length > 0 && (
                      <span className="workbench-recipe-step-params mono">
                        {Object.entries(step.params).map(([k, v]) => `${k}=${v}`).join(', ')}
                      </span>
                    )}
                    {stepOverrides[i] !== undefined && (
                      <span className="workbench-recipe-step-override-badge" title="This step's input is overridden for the next run">
                        input overridden
                      </span>
                    )}
                    <span className="workbench-recipe-step-actions">
                      <Tooltip content="Move up">
                        <ActionButton variant="icon" onClick={() => move(i, -1)} disabled={i === 0} aria-label="Move up">
                          <ArrowUp size={12} />
                        </ActionButton>
                      </Tooltip>
                      <Tooltip content="Move down">
                        <ActionButton variant="icon" onClick={() => move(i, 1)} disabled={i === recipe.length - 1} aria-label="Move down">
                          <ArrowDown size={12} />
                        </ActionButton>
                      </Tooltip>
                      {editableParams.length > 0 && (
                        <Tooltip content="Edit settings">
                          <ActionButton
                            variant="icon"
                            onClick={() => (isEditing ? cancelEdit() : startEdit(step))}
                            aria-label="Edit settings"
                          >
                            <Pencil size={12} />
                          </ActionButton>
                        </Tooltip>
                      )}
                      <Tooltip content="Override this step's input for debugging">
                        <ActionButton
                          variant="icon"
                          onClick={() => (overrideEditingId === String(i) ? cancelOverride() : startOverride(i, ''))}
                          aria-label="Override this step's input for debugging"
                        >
                          <Sparkles size={12} />
                        </ActionButton>
                      </Tooltip>
                      <Tooltip content="Run recipe up to this step">
                        <ActionButton variant="icon" onClick={() => void runToStep(i)} disabled={loading} aria-label="Run recipe up to this step">
                          <SkipForward size={12} />
                        </ActionButton>
                      </Tooltip>
                      <Tooltip content="Duplicate step">
                        <ActionButton variant="icon" onClick={() => duplicate(i)} aria-label="Duplicate step">
                          <Copy size={12} />
                        </ActionButton>
                      </Tooltip>
                      <Tooltip content="Remove">
                        <ActionButton variant="icon" onClick={() => remove(i)} aria-label="Remove">
                          <X size={12} />
                        </ActionButton>
                      </Tooltip>
                    </span>
                  </div>

                  {overrideEditingId === String(i) && (
                    <div className="workbench-recipe-step-edit">
                      <label className="workbench-field">
                        <span className="workbench-field-label">Override input for this step</span>
                        <textarea
                          className="input workbench-textarea mono"
                          value={overrideDraft}
                          onChange={e => setOverrideDraft(e.target.value)}
                          rows={2}
                        />
                      </label>
                      <div className="workbench-actions">
                        <ActionButton variant="secondary" onClick={() => saveOverride(i)}>
                          <Check size={13} /> Save Override
                        </ActionButton>
                        <ActionButton variant="secondary" onClick={cancelOverride}>
                          <X size={13} /> Cancel
                        </ActionButton>
                        {stepOverrides[i] !== undefined && (
                          <ActionButton variant="secondary" onClick={() => clearOverride(i)}>
                            <X size={13} /> Clear
                          </ActionButton>
                        )}
                      </div>
                    </div>
                  )}

                  {isEditing && (
                    <div className="workbench-recipe-step-edit">
                      {editableParams.map(p => (
                        <label key={p.name} className="workbench-field">
                          <span className="workbench-field-label">{p.label}</span>
                          {p.type === 'select' ? (
                            <select
                              className="input input-full"
                              value={editValues[p.name] ?? ''}
                              onChange={e => setEditValues(prev => ({ ...prev, [p.name]: e.target.value }))}
                            >
                              {(p.choices ?? []).map(choice => (
                                <option key={choice} value={choice}>{choice}</option>
                              ))}
                            </select>
                          ) : p.type === 'textarea' ? (
                            <textarea
                              className="input workbench-textarea mono"
                              value={editValues[p.name] ?? ''}
                              onChange={e => setEditValues(prev => ({ ...prev, [p.name]: e.target.value }))}
                              rows={2}
                            />
                          ) : (
                            <input
                              className="input input-full mono"
                              type={p.type === 'number' ? 'number' : 'text'}
                              value={editValues[p.name] ?? ''}
                              onChange={e => setEditValues(prev => ({ ...prev, [p.name]: e.target.value }))}
                            />
                          )}
                          {p.help_text && <span className="workbench-field-hint">{p.help_text}</span>}
                        </label>
                      ))}
                      <div className="workbench-actions">
                        <ActionButton variant="secondary" onClick={() => saveEdit(step.stepId)}>
                          <Check size={13} /> Save
                        </ActionButton>
                        <ActionButton variant="secondary" onClick={cancelEdit}>
                          <X size={13} /> Cancel
                        </ActionButton>
                      </div>
                    </div>
                  )}
                </li>
              )
            })}
          </ol>
        )}

        {recipe.length > 0 && (
          <>
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

            <label className="workbench-continue-toggle">
              <input
                type="checkbox"
                checked={continueOnError}
                onChange={e => setContinueOnError(e.target.checked)}
              />
              Continue on error
            </label>

            <div className="workbench-actions">
              <ActionButton variant="primary" onClick={run} disabled={loading}>
                {loading ? <><RefreshCw size={13} className="spin" /> Running…</> : <><Play size={13} /> Run Recipe</>}
              </ActionButton>
            </div>

            {error && <ErrorState message={error} />}
            {hasErrors && !error && (
              <div className="workbench-note">Some steps failed and were skipped (continue-on-error was on) — see the trace below.</div>
            )}

            {steps.length > 0 && (
              <ol className="workbench-recipe-trace">
                {steps.map((s, i) => {
                  const traceClass = s.error
                    ? (continueOnError ? 'workbench-recipe-trace-error-continued' : 'workbench-recipe-trace-error')
                    : ''
                  return (
                    <li key={i} className={traceClass}>
                      <span className="workbench-recipe-step-index">{i + 1}</span>
                      <span className="workbench-field-label">{s.name ?? s.operation_id}</span>
                      {s.input !== undefined && (
                        <span className="workbench-recipe-trace-input mono">in: {s.input.length > 120 ? `${s.input.slice(0, 120)}…` : s.input}</span>
                      )}
                      {s.error ? (
                        <span className="mono">
                          {continueOnError && <Badge tone="warning">skipped</Badge>}
                          {' '}{continueOnError ? 'Skipped (chain continued): ' : 'Error: '}{s.error}
                        </span>
                      ) : (
                        <span className="mono">{s.output}</span>
                      )}
                    </li>
                  )
                })}
              </ol>
            )}

            {output !== null && (
              <div className="workbench-output-wrap">
                <div className="workbench-output-header">
                  <span className="workbench-field-label">Final Output</span>
                  <span className="workbench-output-actions">
                    <Tooltip content="Copy output">
                      <ActionButton variant="icon" onClick={copyOutput} aria-label="Copy output">
                        {copied ? <Check size={12} color="var(--green)" /> : <Copy size={12} />}
                      </ActionButton>
                    </Tooltip>
                    <Tooltip content="Download output">
                      <ActionButton
                        variant="icon"
                        onClick={() => downloadWorkbenchOutput(output, outputMime, 'payload-recipe')}
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
                <TestAgainstTargetPanel output={output} />
              </div>
            )}
          </>
        )}
      </div>

      <ConfirmActionModal
        isOpen={!!pendingDelete}
        title="Delete saved recipe?"
        description={`This will permanently delete "${pendingDelete?.name}". This can't be undone.`}
        confirmLabel="Delete"
        isConfirming={deletingRecipe}
        onConfirm={confirmDelete}
        onClose={() => setPendingDelete(null)}
      />

      <ConfirmActionModal
        isOpen={pendingClear}
        title="Clear recipe?"
        description="This will discard the working recipe and its input. Saved recipes are not affected."
        confirmLabel="Clear"
        onConfirm={clearRecipe}
        onClose={() => setPendingClear(false)}
      />

      {output !== null && (
        <SendToLootModal
          isOpen={sendToLootOpen}
          onClose={() => setSendToLootOpen(false)}
          defaultTitle="Payload recipe output"
          content={output}
          sourceTool="payload-workbench"
        />
      )}
    </section>
  )
}
