import type { AttackChainStep, SessionSummary, Tool } from '../../api'
import type { ToolExecResponse } from '../../api'

export function normalizeStepsFromSession(session: SessionSummary): AttackChainStep[] {
  if (Array.isArray(session.workflow_steps) && session.workflow_steps.length > 0) return session.workflow_steps
  return session.tools_executed.map(tool => ({ tool, parameters: {} }))
}

function normalizeToken(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '')
}

export function resolveToolForStep(stepTool: string, tools: Tool[]): Tool | null {
  const step = stepTool.trim()
  if (!step) return null

  const directByName = tools.find(t => t.name === step)
  if (directByName) return directByName

  const directByEndpoint = tools.find(t => t.endpoint === step)
  if (directByEndpoint) return directByEndpoint

  const directByParent = tools.find(t => t.parent_tool === step)
  if (directByParent) return directByParent

  const normalizedStep = normalizeToken(step)
  let best: { tool: Tool; score: number } | null = null

  for (const tool of tools) {
    const name = normalizeToken(tool.name)
    const parent = normalizeToken(tool.parent_tool ?? '')
    const endpoint = normalizeToken(tool.endpoint)
    let score = 0

    if (name === normalizedStep) score = Math.max(score, 80)
    if (parent === normalizedStep) score = Math.max(score, 75)
    if (endpoint === normalizedStep) score = Math.max(score, 70)
    if (name.includes(normalizedStep)) score = Math.max(score, 62)
    if (endpoint.includes(normalizedStep)) score = Math.max(score, 58)
    if (parent && parent.includes(normalizedStep)) score = Math.max(score, 56)
    if (normalizedStep.includes(name)) score = Math.max(score, 52)
    if (score === 0) continue

    if (!best || score > best.score) best = { tool, score }
  }

  return best?.tool ?? null
}

export type StepState = 'idle' | 'running' | 'success' | 'failed'

export type PersistedStepResult = {
  success: boolean
  return_code: number
  execution_time: number
  timestamp?: string
  stdout?: string
  stderr?: string
}

export type ChainSuggestion = {
  sourceTool: string
  updates: Record<string, string>
  summary: string
}

const URL_RE = /https?:\/\/[^\s"'<>]+/gi
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi

function isLikelyIp(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 4) return false
  return parts.every(p => {
    if (!/^\d+$/.test(p)) return false
    const n = Number(p)
    return n >= 0 && n <= 255
  })
}

function toRootDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split('.').filter(Boolean)
  if (parts.length <= 2) return hostname.toLowerCase()
  const joinedTail = parts.slice(-3).join('.')
  if (joinedTail.endsWith('.co.uk') || joinedTail.endsWith('.com.au')) {
    return parts.slice(-3).join('.')
  }
  return parts.slice(-2).join('.')
}

function hostFromUrl(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase()
  } catch {
    return null
  }
}

function collectStrings(node: unknown, out: string[], depth = 0): void {
  if (depth > 4) return
  if (typeof node === 'string') {
    out.push(node)
    return
  }
  if (Array.isArray(node)) {
    for (const value of node.slice(0, 400)) collectStrings(value, out, depth + 1)
    return
  }
  if (node && typeof node === 'object') {
    for (const value of Object.values(node as Record<string, unknown>)) collectStrings(value, out, depth + 1)
  }
}

function extractCandidates(stdout: string): { urls: string[]; domains: string[]; ips: string[] } {
  const urls: string[] = []
  const domains: string[] = []
  const ips: string[] = []

  function addUrl(value: string) {
    const clean = value.trim()
    if (!clean) return
    if (!urls.includes(clean)) urls.push(clean)
    const host = hostFromUrl(clean)
    if (host && !domains.includes(host)) domains.push(host)
  }

  function addDomain(value: string) {
    const clean = value.trim().toLowerCase()
    if (!clean || isLikelyIp(clean)) return
    if (!domains.includes(clean)) domains.push(clean)
  }

  function addIp(value: string) {
    const clean = value.trim()
    if (!isLikelyIp(clean)) return
    if (!ips.includes(clean)) ips.push(clean)
  }

  const text = stdout || ''
  const parsedStrings: string[] = []
  try {
    const parsed = JSON.parse(text)
    collectStrings(parsed, parsedStrings)
  } catch {
    // output may be non-JSON
  }

  const corpus = [text, ...parsedStrings].join('\n')

  for (const m of corpus.match(URL_RE) ?? []) addUrl(m)
  for (const m of corpus.match(DOMAIN_RE) ?? []) addDomain(m)
  for (const m of corpus.match(IPV4_RE) ?? []) addIp(m)

  return { urls, domains, ips }
}

function firstParam(params: Record<string, unknown>, keys: string[]): string | undefined {
  for (const key of keys) {
    const v = params[key]
    if (typeof v === 'string' && v.trim()) return v.trim()
  }
  return undefined
}

function normalizeInputTarget(value: string): string {
  const trimmed = value.trim()
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) return trimmed
  return `https://${trimmed}`
}

export function buildStepChainSuggestion({
  steps,
  selectedStepIndex,
  selectedTool,
  sessionId,
  target,
  stepResults,
  currentValues,
}: {
  steps: AttackChainStep[]
  selectedStepIndex: number
  selectedTool: Tool
  sessionId: string
  target: string
  stepResults: Record<string, { result?: ToolExecResponse; error?: string }>
  currentValues: Record<string, string>
}): ChainSuggestion | null {
  const paramNames = [...Object.keys(selectedTool.params), ...Object.keys(selectedTool.optional)]
  if (paramNames.length === 0) return null

  for (let i = selectedStepIndex - 1; i >= 0; i -= 1) {
    const prevStep = steps[i]
    const prevStepKey = `${sessionId}:${i}`
    const prevResult = stepResults[prevStepKey]?.result
    if (!prevResult?.success) continue

    const prevParams = (prevStep.parameters ?? {}) as Record<string, unknown>
    const extracted = extractCandidates(prevResult.stdout ?? '')

    const fallbackDomain = firstParam(prevParams, ['domain'])
      ?? extracted.domains[0]
      ?? hostFromUrl(extracted.urls[0] ?? '')
    const fallbackTarget = firstParam(prevParams, ['target', 'host', 'query'])
      ?? extracted.urls[0]
      ?? extracted.domains[0]
      ?? extracted.ips[0]
      ?? target
    const fallbackUrl = firstParam(prevParams, ['url', 'endpoint'])
      ?? extracted.urls[0]
      ?? (fallbackDomain ? normalizeInputTarget(fallbackDomain) : '')

    const updates: Record<string, string> = {}

    for (const name of paramNames) {
      if (currentValues[name]?.trim()) continue
      const key = name.toLowerCase()
      if (['target', 'host', 'query', 'hostname'].includes(key) && fallbackTarget) {
        updates[name] = fallbackTarget
      } else if (['url', 'endpoint'].includes(key) && fallbackUrl) {
        updates[name] = fallbackUrl
      } else if (key === 'domain' && fallbackDomain) {
        updates[name] = toRootDomain(fallbackDomain)
      }
    }

    if (Object.keys(updates).length > 0) {
      const summaryParts = []
      if (extracted.urls.length > 0) summaryParts.push(`${extracted.urls.length} URL${extracted.urls.length === 1 ? '' : 's'}`)
      if (extracted.domains.length > 0) summaryParts.push(`${extracted.domains.length} domain${extracted.domains.length === 1 ? '' : 's'}`)
      if (extracted.ips.length > 0) summaryParts.push(`${extracted.ips.length} IP${extracted.ips.length === 1 ? '' : 's'}`)
      const summary = summaryParts.length > 0
        ? `Found ${summaryParts.join(', ')} in ${prevStep.tool} output.`
        : `Using values from ${prevStep.tool} for next step.`
      return {
        sourceTool: prevStep.tool,
        updates,
        summary,
      }
    }
  }

  return null
}
