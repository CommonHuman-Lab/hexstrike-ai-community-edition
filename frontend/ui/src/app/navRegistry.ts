import type { LucideIcon } from 'lucide-react'
import {
  LayoutDashboard, Play, Terminal, Settings as SettingsIcon, HelpCircle,
  ListTodo, Wrench, Puzzle, FileText, Layers, KeyRound, ShieldCheck, FlaskConical, Syringe,
} from 'lucide-react'
import type { Page } from './routing'

export interface NavEntry {
  id: Exclude<Page, 'session-detail'>
  label: string
  icon: LucideIcon
  description: string
  mandatory: boolean
  paletteLabel: string
}

export const NAV_ENTRIES: NavEntry[] = [
  { id: 'dashboard', label: 'Home', icon: LayoutDashboard, description: 'Overview dashboard with KPIs and live status', mandatory: true, paletteLabel: 'Open Home' },
  { id: 'run', label: 'Run', icon: Play, description: 'Execute security tools interactively', mandatory: false, paletteLabel: 'Open Run' },
  { id: 'tasks', label: 'Tasks', icon: ListTodo, description: 'Background task queue and progress', mandatory: false, paletteLabel: 'Open Tasks' },
  { id: 'logs', label: 'Logs', icon: Terminal, description: 'Live server log stream', mandatory: false, paletteLabel: 'Open Logs' },
  { id: 'reports', label: 'Reports', icon: FileText, description: 'Generated scan reports', mandatory: false, paletteLabel: 'Open Reports' },
  { id: 'sessions', label: 'Sessions', icon: Layers, description: 'Saved recon/engagement sessions', mandatory: false, paletteLabel: 'Open Sessions' },
  { id: 'loot', label: 'Loot', icon: KeyRound, description: 'Captured credentials and artefacts', mandatory: false, paletteLabel: 'Open Loot' },
  { id: 'verify', label: 'Verify', icon: ShieldCheck, description: 'Evidence chain-of-custody — look up runs by hash, check session integrity', mandatory: false, paletteLabel: 'Open Verify' },
  { id: 'tools', label: 'Tools', icon: Wrench, description: 'Browse and inspect available tools', mandatory: false, paletteLabel: 'Open Tools' },
  { id: 'workbench', label: 'Workbench', icon: FlaskConical, description: 'Quick data transforms — encoding, hashing, ciphers, and more', mandatory: false, paletteLabel: 'Open Workbench' },
  { id: 'payload-workbench', label: 'Payload', icon: Syringe, description: 'Generate, evade, and test attack payloads — XSS, SQLi, LFI, and more', mandatory: false, paletteLabel: 'Open Payload Workbench' },
  { id: 'plugins', label: 'Plugins', icon: Puzzle, description: 'Manage skill and plugin extensions', mandatory: false, paletteLabel: 'Open Plugins' },
  { id: 'help', label: 'Help', icon: HelpCircle, description: 'Documentation and keyboard shortcuts', mandatory: false, paletteLabel: 'Open Help' },
  { id: 'settings', label: 'Settings', icon: SettingsIcon, description: 'Application settings (always visible)', mandatory: true, paletteLabel: 'Open Settings' },
]

export const MANDATORY_PAGE_IDS: ReadonlySet<Page> = new Set(
  NAV_ENTRIES.filter(e => e.mandatory).map(e => e.id)
)
