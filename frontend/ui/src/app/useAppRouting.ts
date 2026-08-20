import { useEffect, useState } from 'react'
import { buildPayloadWorkbenchHash, buildWorkbenchHash, routeFromHash, type Page } from './routing'

export function useAppRouting(isPageEnabled: (page: Page) => boolean) {
  const initialRoute = routeFromHash()
  const [page, setPageState] = useState<Page>(initialRoute.page)
  const [activeSessionId, setActiveSessionId] = useState<string | null>(initialRoute.sessionId)
  const [activeToolName, setActiveToolNameState] = useState<string | null>(initialRoute.toolName)
  const [activeWorkbenchOperationId, setActiveWorkbenchOperationIdState] = useState<string | null>(
    initialRoute.workbenchOperationId
  )
  const [activeWorkbenchRecipe, setActiveWorkbenchRecipeState] = useState<string | null>(initialRoute.workbenchRecipe)
  const [activeWorkbenchInput, setActiveWorkbenchInputState] = useState<string | null>(initialRoute.workbenchInput)
  const [activePayloadWorkbenchOperationId, setActivePayloadWorkbenchOperationIdState] = useState<string | null>(
    initialRoute.payloadWorkbenchOperationId
  )
  const [sidebarMobileOpen, setSidebarMobileOpen] = useState(false)

  function setPage(p: Page) {
    if (p === 'session-detail') return
    window.location.hash = `/${p === 'dashboard' ? '' : p}`
    setPageState(p)
    setActiveSessionId(null)
    setActiveToolNameState(null)
    setActiveWorkbenchOperationIdState(null)
    setActiveWorkbenchRecipeState(null)
    setActiveWorkbenchInputState(null)
    setActivePayloadWorkbenchOperationIdState(null)
    setSidebarMobileOpen(false)
  }

  function openSessionDetail(sessionId: string) {
    window.location.hash = `/sessions/${sessionId}`
    setPageState('session-detail')
    setActiveSessionId(sessionId)
    setActiveToolNameState(null)
    setActiveWorkbenchOperationIdState(null)
    setActiveWorkbenchRecipeState(null)
    setActiveWorkbenchInputState(null)
    setActivePayloadWorkbenchOperationIdState(null)
    setSidebarMobileOpen(false)
  }

  function openWorkbench(input: string, operationId: string | null = null) {
    window.location.hash = buildWorkbenchHash(operationId, null, input)
    setPageState('workbench')
    setActiveSessionId(null)
    setActiveToolNameState(null)
    setActiveWorkbenchOperationIdState(operationId)
    setActiveWorkbenchRecipeState(null)
    setActiveWorkbenchInputState(input)
    setActivePayloadWorkbenchOperationIdState(null)
    setSidebarMobileOpen(false)
  }

  // Reflects the currently selected Run-page tool into the URL, so it's bookmarkable/shareable.
  // Does not carry any tool params/inputs — just which tool the Run page should open with.
  function setActiveToolName(toolName: string | null) {
    window.location.hash = toolName ? `/run/${encodeURIComponent(toolName)}` : '/run'
    setActiveToolNameState(toolName)
  }

  function setActiveWorkbenchOperationId(operationId: string | null) {
    window.location.hash = buildWorkbenchHash(operationId, activeWorkbenchRecipe)
    setActiveWorkbenchOperationIdState(operationId)
  }

  function setActiveWorkbenchRecipe(recipeJson: string | null) {
    window.location.hash = buildWorkbenchHash(activeWorkbenchOperationId, recipeJson)
    setActiveWorkbenchRecipeState(recipeJson)
  }

  function setActivePayloadWorkbenchOperationId(operationId: string | null) {
    window.location.hash = buildPayloadWorkbenchHash(operationId)
    setActivePayloadWorkbenchOperationIdState(operationId)
  }

  // Keep state in sync if the user presses Back/Forward
  useEffect(() => {
    function onHashChange() {
      const route = routeFromHash()
      setPageState(route.page)
      setActiveSessionId(route.sessionId)
      setActiveToolNameState(route.toolName)
      setActiveWorkbenchOperationIdState(route.workbenchOperationId)
      setActiveWorkbenchRecipeState(route.workbenchRecipe)
      setActiveWorkbenchInputState(route.workbenchInput)
      setActivePayloadWorkbenchOperationIdState(route.payloadWorkbenchOperationId)
      setSidebarMobileOpen(false)
    }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  // If the active page gets disabled, fall back to dashboard
  useEffect(() => {
    if (!isPageEnabled(page)) {
      setPage('dashboard')
    }
  }, [page, isPageEnabled])

  return {
    page,
    activeSessionId,
    activeToolName,
    activeWorkbenchOperationId,
    activeWorkbenchRecipe,
    activeWorkbenchInput,
    activePayloadWorkbenchOperationId,
    sidebarMobileOpen,
    setSidebarMobileOpen,
    setPage,
    openSessionDetail,
    setActiveToolName,
    setActiveWorkbenchOperationId,
    setActiveWorkbenchRecipe,
    setActivePayloadWorkbenchOperationId,
    openWorkbench,
  }
}
