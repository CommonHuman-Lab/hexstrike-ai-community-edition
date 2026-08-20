import { useEffect, useMemo, useRef, useState } from 'react'
import { Syringe, Layers } from 'lucide-react'
import { api } from '../../api'
import type { PayloadWorkbenchOperation } from '../../api'
import { usePersistentState } from '../../hooks/usePersistentState'
import { BrowserPage } from '../../components/layout/BrowserPage'
import { KpiStrip } from '../../components/data-display/KpiStrip'
import { LoadingState } from '../../components/ui/LoadingState'
import { ErrorState } from '../../components/ui/ErrorState'
import { EmptyState } from '../../components/ui/EmptyState'
import { SearchInput } from '../../components/ui/SearchInput'
import { OperationPanel } from './OperationPanel'
import { RecipePanel, type RecipeStep } from './RecipePanel'
import '../workbench/WorkbenchPage.css'
import './PayloadWorkbenchPage.css'

interface PayloadWorkbenchPageProps {
  urlOperationId?: string | null
  onOperationSelected?: (operationId: string | null) => void
}

export default function PayloadWorkbenchPage({ urlOperationId, onOperationSelected }: PayloadWorkbenchPageProps) {
  const [operations, setOperations] = useState<PayloadWorkbenchOperation[]>([])
  const [categories, setCategories] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [recipe, setRecipe] = usePersistentState<RecipeStep[]>('nyxstrike_payload_workbench_recipe', [])
  const [recipeInput, setRecipeInput] = usePersistentState<string>('nyxstrike_payload_workbench_recipe_input', '')
  const [pendingInitialInput, setPendingInitialInput] = useState<string | null>(null)
  const searchInputRef = useRef<HTMLInputElement>(null)
  const operationRefs = useRef<Record<string, HTMLButtonElement | null>>({})

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    api.payloadWorkbenchOperations()
      .then(res => {
        if (cancelled) return
        if (!res.success) {
          setError('Failed to load operations.')
          return
        }
        setOperations(res.operations)
        setCategories(res.categories)
        setSelectedId(prev => prev ?? res.operations[0]?.id ?? null)
      })
      .catch(e => !cancelled && setError(String(e)))
      .finally(() => !cancelled && setLoading(false))
    return () => { cancelled = true }
  }, [reloadToken])

  useEffect(() => {
    if (!urlOperationId || selectedId === urlOperationId) return
    if (operations.some(op => op.id === urlOperationId)) {
      setSelectedId(urlOperationId)
    }
  }, [urlOperationId, operations, selectedId])

  const byCategory = useMemo((): [string, PayloadWorkbenchOperation[]][] => {
    const q = search.trim().toLowerCase()
    return categories
      .map((category): [string, PayloadWorkbenchOperation[]] => [
        category,
        operations.filter(op => op.category === category && (
          !q || op.name.toLowerCase().includes(q) || op.description.toLowerCase().includes(q)
        )),
      ])
      .filter(([, ops]) => ops.length > 0)
  }, [operations, categories, search])

  const selected = operations.find(op => op.id === selectedId) ?? null

  useEffect(() => {
    if (!selectedId) return
    operationRefs.current[selectedId]?.scrollIntoView({ block: 'nearest' })
  }, [selectedId])

  function selectOperation(operationId: string) {
    setSelectedId(operationId)
    setPendingInitialInput(null)
    onOperationSelected?.(operationId)
  }

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null
      const isTyping = !!target && (
        target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT' || target.isContentEditable
      )
      if (!isTyping && e.key === '/') {
        e.preventDefault()
        searchInputRef.current?.focus()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  function addToRecipe(operation: PayloadWorkbenchOperation, params: Record<string, string>, inputValue: string) {
    const step: RecipeStep = {
      stepId: crypto.randomUUID(),
      operationId: operation.id,
      operationName: operation.name,
      params,
    }
    setRecipe(prev => [...prev, step])
    if (inputValue.trim()) {
      setRecipeInput(prev => (prev.trim() ? prev : inputValue))
    }
  }

  return (
    <>
      {loading && (
        <div className="payload-page-state">
          <LoadingState label="Loading operations…" />
        </div>
      )}

      {!loading && error && (
        <div className="payload-page-state">
          <ErrorState message={error} onRetry={() => setReloadToken(t => t + 1)} />
        </div>
      )}

      {!loading && !error && (
        <BrowserPage
          className="workbench-page"
          asideExpanded={recipe.length > 0}
          top={(
            <KpiStrip
              items={[
                { icon: <Syringe size={16} />, label: 'Operations', value: operations.length, accent: 'var(--blue)' },
                {
                  icon: <Layers size={16} />,
                  label: 'Recipe Steps',
                  value: recipe.length,
                  accent: recipe.length > 0 ? 'var(--green)' : 'var(--text-dim)',
                },
              ]}
            />
          )}
          nav={(
            <nav className="workbench-sidebar browser-nav">
              <div className="workbench-sidebar-title browser-nav-title">
                <span className="workbench-sidebar-title-text">
                  <Syringe size={14} /> Payload Workbench
                </span>
              </div>
              <SearchInput
                inputRef={searchInputRef}
                value={search}
                onChange={setSearch}
                placeholder="Find an operation… (/)"
                className="payload-search-wrap"
              />

              {byCategory.map(([category, ops]) => (
                <div key={category} className="workbench-category">
                  <div className="payload-category-label-static">
                    <span className="workbench-category-label">{category.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="workbench-category-ops">
                    {ops.map(op => (
                      <div key={op.id} className="workbench-op-row-wrap">
                        <button
                          ref={el => { operationRefs.current[op.id] = el }}
                          className={`workbench-op-btn${op.id === selectedId ? ' workbench-op-btn--active' : ''}`}
                          onClick={() => selectOperation(op.id)}
                        >
                          {op.name}
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
              {byCategory.length === 0 && (
                <EmptyState
                  title={search ? `No operations match "${search}".` : 'No operations available.'}
                />
              )}
            </nav>
          )}
          main={(
            <div className="workbench-main">
              <section className="workbench-panel">
                {selected
                  ? (
                    <OperationPanel
                      key={selected.id}
                      operation={selected}
                      onAddToRecipe={addToRecipe}
                      initialInput={pendingInitialInput ?? undefined}
                    />
                  )
                  : (
                    <div className="workbench-panel-empty">
                      <Syringe size={28} color="var(--text-dim)" />
                      <span className="workbench-panel-empty-title">Select an operation</span>
                      <span className="workbench-panel-empty-hint">Pick something from the sidebar to get started.</span>
                    </div>
                  )}
              </section>
            </div>
          )}
          aside={(
            <aside className="workbench-recipe-col browser-aside">
              <RecipePanel
                recipe={recipe}
                setRecipe={setRecipe}
                operations={operations}
                input={recipeInput}
                setInput={setRecipeInput}
              />
            </aside>
          )}
        />
      )}
    </>
  )
}
