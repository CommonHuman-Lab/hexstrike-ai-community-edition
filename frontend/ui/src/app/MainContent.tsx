import { lazy, Suspense } from 'react'
import { RefreshCw } from 'lucide-react'
import type { Dispatch, RefObject, SetStateAction } from 'react'
import type {
  Tool,
  ToolExecResponse,
  WebDashboardResponse,
} from '../api'
import type { RunHistoryEntry } from '../shared/types'
import type { ThemeId } from './themes'
import type { Page } from './routing'
import type { PageConfig } from '../hooks/usePageVisibility'
import { AppFooter } from './AppFooter'

// Eagerly loaded — always visible on any page
import { DashboardPage } from '../pages/dashboard/DashboardPage'

// Lazy-loaded page chunks — each becomes its own JS chunk
const RunPage           = lazy(() => import('../pages/run/RunPage').then(m => ({ default: m.RunPage })))
const LogsPage          = lazy(() => import('../pages/logview/LogsPage'))
const SettingsPage      = lazy(() => import('../pages/settings/SettingsPage'))
const HelpPage          = lazy(() => import('../pages/help/HelpPage'))
const TasksPage         = lazy(() => import('../pages/tasks/TasksPage'))
const ToolsPage         = lazy(() => import('../pages/tools/ToolsPage'))
const PluginsPage       = lazy(() => import('../pages/plugins/PluginsPage'))
const ReportsPage       = lazy(() => import('../pages/reports/ReportsPage'))
const VerifyPage        = lazy(() => import('../pages/verify/VerifyPage').then(m => ({ default: m.VerifyPage })))
const SessionsPage      = lazy(() => import('../pages/sessions/SessionsPage'))
const SessionDetailPage = lazy(() => import('../pages/sessions/SessionDetailPage'))
const LootPage          = lazy(() => import('../pages/loot/LootPage'))
const WorkbenchPage     = lazy(() => import('../pages/workbench/WorkbenchPage'))
const PayloadWorkbenchPage = lazy(() => import('../pages/payload-workbench/PayloadWorkbenchPage'))

/** Minimal spinner shown while a lazy chunk is loading */
function PageLoader() {
  return (
    <div className="loading-state">
      <RefreshCw size={24} className="spin" color="var(--green)" />
    </div>
  )
}

interface MainContentProps {
  page: Page
  demo: boolean
  tools: Tool[]
  health: WebDashboardResponse | null
  toolsStatusWithParents: Record<string, boolean>
  runHistory: RunHistoryEntry[]
  setRunHistory: Dispatch<SetStateAction<RunHistoryEntry[]>>
  fetchServerRunHistory: () => Promise<void>
  clearServerRunHistory: () => Promise<void>
  commandToolRequest?: { toolName: string; requestId: number } | null
  onCommandToolHandled?: () => void
  openSessionDetail: (sessionId: string) => void
  activeSessionId: string | null
  setPage: (page: Page) => void
  addBrowserRunEntry: (tool: string, params: Record<string, unknown>, result: ToolExecResponse) => void
  logLines: string[]
  logAutoScroll: boolean
  setLogAutoScroll: Dispatch<SetStateAction<boolean>>
  logLimit: number
  setLogLimit: Dispatch<SetStateAction<number>>
  logEndRef: RefObject<HTMLDivElement | null>
  loading: boolean
  error: string | null
  toolCategories: Record<string, string[]>
  themeId: ThemeId
  setThemeId: (theme: ThemeId) => void
  reduceTextureEffects: boolean
  setReduceTextureEffects: (value: boolean) => void
  demoProcesses?: unknown
  demoSessions?: unknown
  demoCpuHistory?: unknown
  isPageEnabled: (page: Page) => boolean
  togglePage: (page: Page) => void
  orderedPageConfigs: PageConfig[]
  reorderPage: (draggedId: string, targetId: string) => void
}

interface MainContentProps {
  page: Page
  demo: boolean
  tools: Tool[]
  health: WebDashboardResponse | null
  toolsStatusWithParents: Record<string, boolean>
  runHistory: RunHistoryEntry[]
  setRunHistory: Dispatch<SetStateAction<RunHistoryEntry[]>>
  fetchServerRunHistory: () => Promise<void>
  clearServerRunHistory: () => Promise<void>
  commandToolRequest?: { toolName: string; requestId: number } | null
  onCommandToolHandled?: () => void
  urlToolName?: string | null
  onToolSelected?: (toolName: string | null) => void
  urlWorkbenchOperationId?: string | null
  onWorkbenchOperationSelected?: (operationId: string | null) => void
  urlWorkbenchRecipe?: string | null
  onWorkbenchRecipeChanged?: (encodedRecipe: string | null) => void
  urlWorkbenchInput?: string | null
  onOpenInWorkbench?: (input: string, operationId?: string | null) => void
  urlPayloadWorkbenchOperationId?: string | null
  onPayloadWorkbenchOperationSelected?: (operationId: string | null) => void
  openSessionDetail: (sessionId: string) => void
  activeSessionId: string | null
  setPage: (page: Page) => void
  addBrowserRunEntry: (tool: string, params: Record<string, unknown>, result: ToolExecResponse) => void
  logLines: string[]
  logAutoScroll: boolean
  setLogAutoScroll: Dispatch<SetStateAction<boolean>>
  logLimit: number
  setLogLimit: Dispatch<SetStateAction<number>>
  logEndRef: RefObject<HTMLDivElement | null>
  loading: boolean
  error: string | null
  toolCategories: Record<string, string[]>
  themeId: ThemeId
  setThemeId: (theme: ThemeId) => void
  reduceTextureEffects: boolean
  setReduceTextureEffects: (value: boolean) => void
  /** Demo data injected from App (avoids importing demo.ts here) */
  demoProcesses?: unknown
  demoSessions?: unknown
  demoCpuHistory?: unknown
}

export function MainContent({
  page,
  demo,
  tools,
  health,
  toolsStatusWithParents,
  runHistory,
  setRunHistory,
  fetchServerRunHistory,
  clearServerRunHistory,
  commandToolRequest,
  onCommandToolHandled,
  urlToolName,
  onToolSelected,
  urlWorkbenchOperationId,
  onWorkbenchOperationSelected,
  urlWorkbenchRecipe,
  onWorkbenchRecipeChanged,
  urlWorkbenchInput,
  onOpenInWorkbench,
  urlPayloadWorkbenchOperationId,
  onPayloadWorkbenchOperationSelected,
  openSessionDetail,
  activeSessionId,
  setPage,
  addBrowserRunEntry,
  logLines,
  logAutoScroll,
  setLogAutoScroll,
  logLimit,
  setLogLimit,
  logEndRef,
  loading,
  error,
  toolCategories,
  themeId,
  setThemeId,
  reduceTextureEffects,
  setReduceTextureEffects,
  demoProcesses,
  demoSessions,
  demoCpuHistory,
  isPageEnabled,
  togglePage,
  orderedPageConfigs,
  reorderPage,
}: MainContentProps) {
  // Flush pages render their own footer inside their main content column
  // (BrowserPage / RunPage) so it lines up with a single column, not the full row.
  const isFlush = page === 'run' || page === 'workbench' || page === 'payload-workbench' || page === 'tools' || page === 'sessions' || page === 'plugins' || page === 'loot' || page === 'reports' || page === 'tasks' || page === 'help' || page === 'settings' || page === 'verify' || page === 'logs'
  return (
    <main className={`main${isFlush ? ' main--flush' : ''}`}>
      <div className="page-slot">
      <Suspense fallback={<PageLoader />}>
        {page === 'settings' && (
          <SettingsPage
            themeId={themeId}
            setThemeId={setThemeId}
            reduceTextureEffects={reduceTextureEffects}
            setReduceTextureEffects={setReduceTextureEffects}
            isPageEnabled={isPageEnabled}
            togglePage={togglePage}
            orderedPageConfigs={orderedPageConfigs}
            reorderPage={reorderPage}
          />
        )}
        {page === 'help' && <HelpPage />}
        {page === 'run' && (
          <RunPage
            tools={tools}
            toolsStatus={toolsStatusWithParents}
            runHistory={runHistory}
            setRunHistory={setRunHistory}
            commandToolRequest={commandToolRequest}
            onCommandToolHandled={onCommandToolHandled}
            urlToolName={urlToolName}
            onToolSelected={onToolSelected}
            onRefresh={fetchServerRunHistory}
            onClearHistory={clearServerRunHistory}
            onOpenSession={openSessionDetail}
          />
        )}
        {page === 'tasks' && (
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          <TasksPage demoData={demo && demoProcesses ? { processes: demoProcesses as any } : undefined} />
        )}
        {page === 'tools' && health && (
          <ToolsPage health={health} tools={tools} toolsStatus={toolsStatusWithParents} />
        )}
        {page === 'plugins' && <PluginsPage />}
        {page === 'reports' && <ReportsPage runHistory={runHistory} />}
        {page === 'verify' && <VerifyPage />}
        {page === 'sessions' && (
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          <SessionsPage demoData={demo && demoSessions ? { sessions: demoSessions as any } : undefined} onOpenSession={openSessionDetail} />
        )}
        {page === 'session-detail' && activeSessionId && (
          <SessionDetailPage
            sessionId={activeSessionId}
            tools={tools}
            onBack={() => setPage('sessions')}
            onToolRun={addBrowserRunEntry}
            llmAvailable={health?.llm_status?.available ?? false}
          />
        )}
        {page === 'loot' && <LootPage onOpenInWorkbench={onOpenInWorkbench} />}
        {page === 'workbench' && (
          <WorkbenchPage
            urlOperationId={urlWorkbenchOperationId}
            onOperationSelected={onWorkbenchOperationSelected}
            urlRecipe={urlWorkbenchRecipe}
            onRecipeChanged={onWorkbenchRecipeChanged}
            urlInput={urlWorkbenchInput}
          />
        )}
        {page === 'payload-workbench' && (
          <PayloadWorkbenchPage
            urlOperationId={urlPayloadWorkbenchOperationId}
            onOperationSelected={onPayloadWorkbenchOperationSelected}
          />
        )}
        {page === 'logs' && (
          <LogsPage
            logLines={logLines}
            logAutoScroll={logAutoScroll}
            setLogAutoScroll={setLogAutoScroll}
            logLimit={logLimit}
            setLogLimit={setLogLimit}
            logEndRef={logEndRef}
          />
        )}
        {page === 'dashboard' && (
          <>
            {loading && !health && (
              <div className="loading-state">
                <RefreshCw size={24} className="spin" color="var(--green)" />
                <p>Connecting to server…</p>
              </div>
            )}
            {error && !health && (
              <div className="error-banner">
                {error} — is the server running on port 8888?
              </div>
            )}
            {health && (
              <DashboardPage
                health={health}
                tools={tools}
                runHistory={runHistory}
                loading={loading}
                error={error}
                toolCategories={toolCategories}
                demo={demo}
                demoCpuHistory={demoCpuHistory}
              />
            )}
          </>
        )}
      </Suspense>
      </div>
      {!isFlush && <AppFooter />}
    </main>
  )
}
