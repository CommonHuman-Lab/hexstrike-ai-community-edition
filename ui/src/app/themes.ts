export type ThemeId = 'dark' | 'unicorn' | 'minimal-light'

export interface ThemeOption {
  id: ThemeId
  label: string
  hint: string
}

export const THEME_STORAGE_KEY = 'hexstrike_theme'

export const THEME_OPTIONS: ThemeOption[] = [
  { id: 'dark', label: 'Dark Ops', hint: 'Default tactical dark' },
  { id: 'unicorn', label: 'Unicorn', hint: 'Candy neon fantasy' },
  { id: 'minimal-light', label: 'White Minimalist', hint: 'Clean and bright' },
]

export function isThemeId(value: string): value is ThemeId {
  return THEME_OPTIONS.some(theme => theme.id === value)
}
