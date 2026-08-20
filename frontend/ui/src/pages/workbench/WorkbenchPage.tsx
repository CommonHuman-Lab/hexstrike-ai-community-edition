import { useEffect, useMemo, useRef, useState } from 'react'
import { FlaskConical, RefreshCw, Search, ChevronDown, ChevronRight, ChevronsDownUp, X, Settings2, RotateCcw, Star, Database, Layers, Wand2 } from 'lucide-react'
import { api } from '../../api'
import type { WorkbenchOperation } from '../../api'
import { usePersistentState } from '../../hooks/usePersistentState'
import { useWorkbenchLayout } from '../../hooks/useWorkbenchLayout'
import { useWorkbenchFavorites } from '../../hooks/useWorkbenchFavorites'
import { ActionButton } from '../../components/ui/ActionButton'
import { ConfirmActionModal } from '../../components/modals/ConfirmActionModal'
import { BrowserPage } from '../../components/layout/BrowserPage'
import { KpiStrip } from '../../components/data-display/KpiStrip'
import { OperationPanel } from './OperationPanel'
import { RecipePanel, type RecipeStep } from './RecipePanel'
import { DecloakPanel } from './DecloakPanel'
import { WorkbenchSidebarCustomize } from './WorkbenchSidebarCustomize'
import './WorkbenchPage.css'

const FAVORITES_CATEGORY = 'Favorites'

function encodeRecipe(steps: RecipeStep[]): string {
  return JSON.stringify(steps.map(s => [s.operationId, s.params]))
}

function decodeRecipe(json: string, operations: WorkbenchOperation[]): RecipeStep[] {
  const pairs = JSON.parse(json) as [string, Record<string, string>][]
  return pairs
    .map((pair): RecipeStep | null => {
      const [operationId, params] = pair
      const operation = operations.find(op => op.id === operationId)
      return operation ? { stepId: crypto.randomUUID(), operationId, operationName: operation.name, params } : null
    })
    .filter((s): s is RecipeStep => s !== null)
}

interface WorkbenchPageProps {
  urlOperationId?: string | null
  onOperationSelected?: (operationId: string | null) => void
  urlRecipe?: string | null
  onRecipeChanged?: (encodedRecipe: string | null) => void
  urlInput?: string | null
}

export default function WorkbenchPage({
  urlOperationId,
  onOperationSelected,
  urlRecipe,
  onRecipeChanged,
  urlInput,
}: WorkbenchPageProps) {
  const [operations, setOperations] = useState<WorkbenchOperation[]>([])
  const [categories, setCategories] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [mode, setMode] = useState<'operations' | 'decloak'>('operations')
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = usePersistentState<string[]>('nyxstrike_workbench_expanded_categories', [])
  const [recipe, setRecipe] = usePersistentState<RecipeStep[]>('nyxstrike_workbench_recipe', [])
  const [recipeInput, setRecipeInput] = usePersistentState<string>('nyxstrike_workbench_recipe_input', '')
  const [hydrated, setHydrated] = useState(!urlRecipe)
  const [recipePast, setRecipePast] = useState<RecipeStep[][]>([])
  const [recipeFuture, setRecipeFuture] = useState<RecipeStep[][]>([])
  const [pendingInitialInput, setPendingInitialInput] = useState<string | null>(null)
  const [isCustomizing, setIsCustomizing] = useState(false)
  const [pendingReset, setPendingReset] = useState(false)
  const searchInputRef = useRef<HTMLInputElement>(null)
  const operationRefs = useRef<Record<string, HTMLButtonElement | null>>({})

  const {
    allByCategory,
    visibleByCategory,
    isCategoryHidden,
    isOperationHidden,
    hideCategory,
    showCategory,
    hideOperation,
    showOperation,
    reorderCategory,
    reorderOperation,
    resetLayout,
  } = useWorkbenchLayout(categories, operations)
  const { favorites, isFavorite, toggleFavorite } = useWorkbenchFavorites()

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api.workbenchOperations()
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
  }, [])

  useEffect(() => {
    if (!urlOperationId || selectedId === urlOperationId) return
    if (operations.some(op => op.id === urlOperationId)) {
      setSelectedId(urlOperationId)
    }
  }, [urlOperationId, operations, selectedId])

  useEffect(() => {
    if (hydrated || operations.length === 0) return
    if (urlRecipe) {
      try {
        setRecipe(decodeRecipe(urlRecipe, operations))
      } catch {
        setRecipe([])
      }
      if (urlInput) setRecipeInput(prev => (prev.trim() ? prev : urlInput))
    } else if (urlInput) {
      setPendingInitialInput(urlInput)
    }
    setHydrated(true)
  }, [operations, hydrated, urlRecipe, urlInput])

  useEffect(() => {
    if (!hydrated) return
    onRecipeChanged?.(recipe.length > 0 ? encodeRecipe(recipe) : null)
  }, [recipe, hydrated])

  const byCategory = useMemo(() => {
    const q = search.trim().toLowerCase()
    const filteredVisible = q
      ? visibleByCategory.map((entry): [string, WorkbenchOperation[]] => [
          entry[0],
          entry[1].filter(op => op.name.toLowerCase().includes(q) || op.description.toLowerCase().includes(q)),
        ])
      : visibleByCategory
    if (q) return filteredVisible.filter(([, ops]) => ops.length > 0)
    const favoriteOps = visibleByCategory.flatMap(([, ops]) => ops).filter(op => isFavorite(op.id))
    const base = filteredVisible
      .map((entry): [string, WorkbenchOperation[]] => [entry[0], entry[1].filter(op => !isFavorite(op.id))])
      .filter(([, ops]) => ops.length > 0)
    return favoriteOps.length > 0 ? [[FAVORITES_CATEGORY, favoriteOps] as [string, WorkbenchOperation[]], ...base] : base
  }, [visibleByCategory, search, isFavorite])

  const selected = operations.find(op => op.id === selectedId) ?? null

  useEffect(() => {
    if (!selectedId) return
    const op = operations.find(o => o.id === selectedId)
    if (!op) return
    const category = favorites.includes(selectedId) ? FAVORITES_CATEGORY : op.category
    setExpanded(prev => (prev.length === 1 && prev[0] === category ? prev : [category]))
  }, [selectedId, operations, favorites])

  useEffect(() => {
    if (!selectedId) return
    operationRefs.current[selectedId]?.scrollIntoView({ block: 'nearest' })
  }, [selectedId, expanded])

  function selectOperation(operationId: string) {
    setSelectedId(operationId)
    setPendingInitialInput(null)
    setMode('operations')
    onOperationSelected?.(operationId)
  }

  function toggleCategory(category: string) {
    setExpanded(prev => (prev.length === 1 && prev[0] === category ? [] : [category]))
  }

  function collapseAll() {
    setExpanded([])
  }

  function setRecipeTracked(action: RecipeStep[] | ((prev: RecipeStep[]) => RecipeStep[])) {
    setRecipePast(prevPast => [...prevPast.slice(-49), recipe])
    setRecipeFuture([])
    setRecipe(action)
  }

  function undoRecipe() {
    if (recipePast.length === 0) return
    const previous = recipePast[recipePast.length - 1]
    setRecipePast(recipePast.slice(0, -1))
    setRecipeFuture([recipe, ...recipeFuture].slice(0, 50))
    setRecipe(previous)
  }

  function redoRecipe() {
    if (recipeFuture.length === 0) return
    const [next, ...rest] = recipeFuture
    setRecipePast([...recipePast.slice(-49), recipe])
    setRecipeFuture(rest)
    setRecipe(next)
  }

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      const target = e.target as HTMLElement | null
      const isTyping = !!target && (
        target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT' || target.isContentEditable
      )
      if (!isTyping && e.key === '/' && !isCustomizing) {
        e.preventDefault()
        searchInputRef.current?.focus()
        return
      }
      if (!isTyping && (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'z') {
        e.preventDefault()
        if (e.shiftKey) redoRecipe()
        else undoRecipe()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [recipe, recipePast, recipeFuture, isCustomizing])

  function addToRecipe(operation: WorkbenchOperation, params: Record<string, string>, inputValue: string) {
    const step: RecipeStep = {
      stepId: crypto.randomUUID(),
      operationId: operation.id,
      operationName: operation.name,
      params,
    }
    setRecipeTracked(prev => [...prev, step])
    if (inputValue.trim()) {
      setRecipeInput(prev => (prev.trim() ? prev : inputValue))
    }
  }

  return (
    <>
      {loading && (
        <div className="workbench-page-loading">
          <RefreshCw size={20} className="spin" color="var(--green)" />
        </div>
      )}

      {error && <div className="workbench-page-error">{error}</div>}

      {!loading && !error && (
        <>
          <ConfirmActionModal
            isOpen={pendingReset}
            title="Reset Workbench layout?"
            description="This will un-hide all categories and tools and restore the default order. Starred favorites are not affected."
            confirmLabel="Reset"
            confirmVariant="default"
            onConfirm={() => { resetLayout(); setPendingReset(false) }}
            onClose={() => setPendingReset(false)}
          />

          <BrowserPage
            className="workbench-page"
            asideExpanded={recipe.length > 0}
            top={(
              <KpiStrip
                items={[
                  { icon: <FlaskConical size={16} />, label: 'Operations', value: operations.length, accent: 'var(--blue)' },
                  { icon: <Database size={16} />, label: 'Categories', value: categories.length, accent: 'var(--purple)' },
                  { icon: <Star size={16} />, label: 'Favorites', value: favorites.length, accent: 'var(--amber)' },
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
                    <FlaskConical size={14} /> Workbench
                  </span>
                  <div className="workbench-sidebar-title-actions">
                    {!isCustomizing && expanded.length > 0 && (
                      <button
                        type="button"
                        className="workbench-reset-link-btn"
                        onClick={collapseAll}
                        title="Collapse all categories"
                      >
                        <ChevronsDownUp size={12} />
                      </button>
                    )}
                    {isCustomizing && (
                      <button
                        type="button"
                        className="workbench-reset-link-btn"
                        onClick={() => setPendingReset(true)}
                        title="Reset layout"
                      >
                        <RotateCcw size={12} />
                      </button>
                    )}
                    <ActionButton
                      variant={isCustomizing ? 'success' : 'default'}
                      className="workbench-customize-btn"
                      onClick={() => setIsCustomizing(prev => !prev)}
                    >
                      <Settings2 size={13} /> {isCustomizing ? 'Done' : 'Customize'}
                    </ActionButton>
                  </div>
                </div>
                <div className="workbench-mode-tabs">
                  <button
                    type="button"
                    className={`workbench-mode-tab${mode === 'operations' ? ' workbench-mode-tab--active' : ''}`}
                    onClick={() => setMode('operations')}
                  >
                    Operations
                  </button>
                  <button
                    type="button"
                    className={`workbench-mode-tab${mode === 'decloak' ? ' workbench-mode-tab--active' : ''}`}
                    onClick={() => setMode('decloak')}
                  >
                    <Wand2 size={12} /> Decloak
                  </button>
                </div>
                <div className={`workbench-search${isCustomizing ? ' workbench-search--disabled' : ''}`}>
                  <Search size={13} className="workbench-search-icon" />
                  <input
                    ref={searchInputRef}
                    className="workbench-search-input"
                    placeholder={isCustomizing ? 'Search disabled while customizing' : 'Find an operation… (/)'}
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    disabled={isCustomizing}
                  />
                  {search && !isCustomizing && (
                    <button className="workbench-search-clear" onClick={() => setSearch('')} title="Clear search">
                      <X size={12} />
                    </button>
                  )}
                </div>

                {isCustomizing ? (
                  <WorkbenchSidebarCustomize
                    allByCategory={allByCategory}
                    isCategoryHidden={isCategoryHidden}
                    isOperationHidden={isOperationHidden}
                    hideCategory={hideCategory}
                    showCategory={showCategory}
                    hideOperation={hideOperation}
                    showOperation={showOperation}
                    isFavorite={isFavorite}
                    toggleFavorite={toggleFavorite}
                    reorderCategory={reorderCategory}
                    reorderOperation={reorderOperation}
                  />
                ) : (
                  <>
                    {byCategory.map(([category, ops]) => {
                      const isCollapsed = search.trim() ? false : !expanded.includes(category)
                      return (
                        <div key={category} className="workbench-category">
                          <button className="workbench-category-header" onClick={() => toggleCategory(category)}>
                            {isCollapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
                            <span className="workbench-category-label">{category.replace(/_/g, ' ')}</span>
                          </button>
                          {!isCollapsed && (
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
                                  <button
                                    type="button"
                                    className={`workbench-star-btn${isFavorite(op.id) ? ' workbench-star-btn--active' : ''}`}
                                    onClick={e => { e.stopPropagation(); toggleFavorite(op.id) }}
                                    title={isFavorite(op.id) ? `Unstar ${op.name}` : `Star ${op.name}`}
                                  >
                                    <Star size={12} fill={isFavorite(op.id) ? 'currentColor' : 'none'} />
                                  </button>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )
                    })}
                    {byCategory.length === 0 && (
                      <div className="workbench-empty">
                        {search
                          ? <>No operations match "{search}".</>
                          : (
                            <>
                              All categories are hidden.{' '}
                              <button type="button" className="workbench-empty-reset-link" onClick={resetLayout}>
                                Reset layout
                              </button>
                            </>
                          )}
                      </div>
                    )}
                  </>
                )}
              </nav>
            )}
            main={(
              <div className="workbench-main">
                {mode === 'decloak' ? (
                  <DecloakPanel />
                ) : (
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
                          <FlaskConical size={28} color="var(--text-dim)" />
                          <span className="workbench-panel-empty-title">Select an operation</span>
                          <span className="workbench-panel-empty-hint">Pick something from the sidebar to get started.</span>
                        </div>
                      )}
                  </section>
                )}
              </div>
            )}
            aside={(
              <aside className="workbench-recipe-col browser-aside">
                <RecipePanel
                  recipe={recipe}
                  setRecipe={setRecipeTracked}
                  operations={operations}
                  input={recipeInput}
                  setInput={setRecipeInput}
                />
              </aside>
            )}
          />
        </>
      )}
    </>
  )
}
