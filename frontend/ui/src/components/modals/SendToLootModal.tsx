import { useState } from 'react'
import { Send } from 'lucide-react'
import { ActionButton } from '../ui/ActionButton'
import { api } from '../../api'
import type { LootType } from '../../api'
import { useToast } from '../feedback/ToastProvider'
import { Sheet } from './Sheet'

const LOOT_TYPES: LootType[] = [
  'flag', 'file', 'config', 'hash', 'key', 'secret', 'screenshot', 'other',
]

interface SendToLootModalProps {
  isOpen: boolean
  onClose: () => void
  defaultTitle: string
  content: string
  sourceTool?: string
}

export function SendToLootModal({ isOpen, onClose, defaultTitle, content, sourceTool = 'workbench' }: SendToLootModalProps) {
  const { pushToast } = useToast()
  const [title, setTitle] = useState(defaultTitle)
  const [lootType, setLootType] = useState<LootType>('other')
  const [body, setBody] = useState(content)
  const [tagsInput, setTagsInput] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSave() {
    if (!title.trim()) {
      setError('Title is required.')
      return
    }
    setSaving(true)
    setError(null)
    const res = await api.createLoot({
      loot_type: lootType,
      title: title.trim(),
      content: body,
      source_tool: sourceTool,
      tags: tagsInput.split(',').map(t => t.trim()).filter(Boolean),
    })
    setSaving(false)
    if (!res.success) {
      setError(res.error ?? 'Failed to save to Loot.')
      return
    }
    pushToast('success', 'Saved to Loot.')
    onClose()
  }

  return (
    <Sheet
      isOpen={isOpen}
      onClose={onClose}
      disableClose={saving}
      title={
        <>
          <span className="modal-icon modal-icon--accent" aria-hidden="true">
            <Send size={14} />
          </span>
          <span className="modal-name">Send to Loot</span>
        </>
      }
    >
      <label className="workbench-field">
        <span className="workbench-field-label">Title</span>
        <input className="input input-full" value={title} onChange={e => setTitle(e.target.value)} autoFocus />
      </label>

      <label className="workbench-field">
        <span className="workbench-field-label">Type</span>
        <select className="input input-full" value={lootType} onChange={e => setLootType(e.target.value as LootType)}>
          {LOOT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
      </label>

      <label className="workbench-field">
        <span className="workbench-field-label">Content</span>
        <textarea
          className="input workbench-textarea mono"
          value={body}
          onChange={e => setBody(e.target.value)}
          rows={6}
        />
      </label>

      <label className="workbench-field">
        <span className="workbench-field-label">Tags (comma separated)</span>
        <input className="input input-full" value={tagsInput} onChange={e => setTagsInput(e.target.value)} />
      </label>

      {error && <div className="verify-error">{error}</div>}

      <div className="confirm-action-buttons">
        <ActionButton variant="default" onClick={onClose} disabled={saving}>Cancel</ActionButton>
        <ActionButton variant="success" onClick={() => { void handleSave() }} disabled={saving}>
          {saving ? 'Saving…' : 'Save to Loot'}
        </ActionButton>
      </div>
    </Sheet>
  )
}
