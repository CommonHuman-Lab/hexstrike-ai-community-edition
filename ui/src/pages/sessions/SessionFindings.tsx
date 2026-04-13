import { useState } from 'react'
import { createPortal } from 'react-dom'
import { Plus, Trash2, Edit2, Check, X, Shield } from 'lucide-react'
import { api } from '../../api'
import type { SessionSummary, SessionFinding, CreateFindingPayload } from '../../api'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
type Severity = typeof SEVERITIES[number]

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

const FINDING_STATUSES = ['open', 'confirmed', 'false_positive', 'resolved'] as const

const emptyForm = (): CreateFindingPayload => ({
  title: '',
  severity: 'info',
  description: '',
  tool: '',
  evidence: '',
  recommendation: '',
  cve: '',
  tags: [],
})

export function SessionFindings({
  session,
  onUpdate,
}: {
  session: SessionSummary
  onUpdate?: () => void
}) {
  const findings: SessionFinding[] = session.findings ?? []
  const [filterSev, setFilterSev] = useState<Severity | 'all'>('all')
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState<CreateFindingPayload>(emptyForm())
  const [tagsInput, setTagsInput] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editForm, setEditForm] = useState<Partial<SessionFinding>>({})
  const [deletingId, setDeletingId] = useState<string | null>(null)

  const visible = filterSev === 'all'
    ? findings
    : findings.filter(f => f.severity === filterSev)

  const bySeverity = SEVERITIES.reduce((acc, sev) => {
    acc[sev] = visible.filter(f => f.severity === sev)
    return acc
  }, {} as Record<Severity, SessionFinding[]>)

  function updateForm(key: keyof CreateFindingPayload, value: string) {
    setForm(prev => ({ ...prev, [key]: value }))
  }

  async function saveFinding() {
    if (!form.title.trim()) { setError('Title is required'); return }
    setSaving(true)
    setError(null)
    try {
      const payload: CreateFindingPayload = {
        ...form,
        tags: tagsInput ? tagsInput.split(',').map(t => t.trim()).filter(Boolean) : [],
      }
      await api.addSessionFinding(session.session_id, payload)
      setForm(emptyForm())
      setTagsInput('')
      setShowForm(false)
      onUpdate?.()
    } catch (e) {
      setError(String(e))
    } finally {
      setSaving(false)
    }
  }

  async function saveFindingEdit(findingId: string) {
    setSaving(true)
    setError(null)
    try {
      await api.updateSessionFinding(session.session_id, findingId, editForm)
      setEditingId(null)
      setEditForm({})
      onUpdate?.()
    } catch (e) {
      setError(String(e))
    } finally {
      setSaving(false)
    }
  }

  async function deleteFinding(findingId: string) {
    setDeletingId(findingId)
    try {
      await api.deleteSessionFinding(session.session_id, findingId)
      onUpdate?.()
    } catch (e) {
      setError(String(e))
    } finally {
      setDeletingId(null)
    }
  }

  function startEdit(f: SessionFinding) {
    setEditingId(f.finding_id)
    setEditForm({
      title: f.title,
      severity: f.severity,
      description: f.description ?? '',
      tool: f.tool ?? '',
      evidence: f.evidence ?? '',
      recommendation: f.recommendation ?? '',
      cve: f.cve ?? '',
      tags: f.tags ?? [],
      status: f.status ?? 'open',
    })
  }

  return (
    <div className="session-findings">
      <div className="session-findings-header">
        <div className="session-findings-filters">
          <button
            className={`findings-filter-btn${filterSev === 'all' ? ' findings-filter-btn--active' : ''}`}
            onClick={() => setFilterSev('all')}
          >
            All ({findings.length})
          </button>
          {SEVERITIES.map(sev => {
            const count = findings.filter(f => f.severity === sev).length
            if (count === 0) return null
            return (
              <button
                key={sev}
                className={`findings-filter-btn findings-filter-btn--${sev}${filterSev === sev ? ' findings-filter-btn--active' : ''}`}
                onClick={() => setFilterSev(sev)}
              >
                {SEVERITY_LABEL[sev]} ({count})
              </button>
            )
          })}
        </div>
        <button className="session-action-btn" onClick={() => { setShowForm(true); setError(null) }}>
          <Plus size={12} /> Add Finding
        </button>
      </div>

      {showForm && createPortal(
        <div
          className="modal-backdrop finding-modal-backdrop"
          onClick={e => { if (e.target === e.currentTarget) { setShowForm(false); setError(null) } }}
        >
          <div className="modal finding-modal" role="dialog" aria-modal="true" aria-label="Add Finding">
            <div className="modal-header finding-modal-header">
              <div className="modal-title-row">
                <Shield size={13} />
                <span className="modal-name">Add Finding</span>
              </div>
              <button className="modal-close" onClick={() => { setShowForm(false); setError(null) }}>×</button>
            </div>
            <div className="finding-modal-body">
              <div className="findings-form-row">
                <input
                  className="findings-form-input"
                  placeholder="Title *"
                  value={form.title}
                  onChange={e => updateForm('title', e.target.value)}
                  autoFocus
                />
                <select
                  className="findings-form-select"
                  value={form.severity}
                  onChange={e => updateForm('severity', e.target.value as Severity)}
                >
                  {SEVERITIES.map(s => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
                </select>
              </div>
              <textarea
                className="findings-form-textarea"
                placeholder="Description"
                rows={3}
                value={form.description ?? ''}
                onChange={e => updateForm('description', e.target.value)}
              />
              <div className="findings-form-row">
                <input
                  className="findings-form-input"
                  placeholder="Tool (e.g. nmap)"
                  value={form.tool ?? ''}
                  onChange={e => updateForm('tool', e.target.value)}
                />
                <input
                  className="findings-form-input"
                  placeholder="CVE (e.g. CVE-2021-44228)"
                  value={form.cve ?? ''}
                  onChange={e => updateForm('cve', e.target.value)}
                />
              </div>
              <textarea
                className="findings-form-textarea"
                placeholder="Evidence / PoC"
                rows={3}
                value={form.evidence ?? ''}
                onChange={e => updateForm('evidence', e.target.value)}
              />
              <textarea
                className="findings-form-textarea"
                placeholder="Recommendation"
                rows={2}
                value={form.recommendation ?? ''}
                onChange={e => updateForm('recommendation', e.target.value)}
              />
              <input
                className="findings-form-input"
                placeholder="Tags (comma separated)"
                value={tagsInput}
                onChange={e => setTagsInput(e.target.value)}
              />
              {error && <div className="findings-error">{error}</div>}
              <div className="findings-form-actions">
                <button className="session-action-btn session-action-btn--primary" onClick={saveFinding} disabled={saving}>
                  {saving ? 'Saving…' : 'Save Finding'}
                </button>
                <button className="session-action-btn" onClick={() => { setShowForm(false); setError(null) }}>
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}

      {visible.length === 0 && (
        <div className="findings-empty">
          <p className="section-meta">No findings recorded yet.</p>
        </div>
      )}

      {SEVERITIES.map(sev => {
        const group = bySeverity[sev]
        if (!group.length) return null
        return (
          <div key={sev} className={`findings-group findings-group--${sev}`}>
            <div className="findings-group-header">
              <span className={`findings-severity-badge findings-severity-badge--${sev}`}>
                {SEVERITY_LABEL[sev]}
              </span>
              <span className="section-meta">{group.length} finding{group.length !== 1 ? 's' : ''}</span>
            </div>
            {group.map(f => (
              <div key={f.finding_id} className="finding-card">
                {editingId === f.finding_id ? (
                  <div className="finding-edit-form">
                    <div className="findings-form-row">
                      <input
                        className="findings-form-input"
                        value={editForm.title ?? ''}
                        onChange={e => setEditForm(p => ({ ...p, title: e.target.value }))}
                        placeholder="Title"
                      />
                      <select
                        className="findings-form-select"
                        value={editForm.severity ?? 'info'}
                        onChange={e => setEditForm(p => ({ ...p, severity: e.target.value as Severity }))}
                      >
                        {SEVERITIES.map(s => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
                      </select>
                      <select
                        className="findings-form-select"
                        value={editForm.status ?? 'open'}
                        onChange={e => setEditForm(p => ({ ...p, status: e.target.value as 'open' | 'confirmed' | 'false_positive' | 'resolved' }))}
                      >
                        {FINDING_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </div>
                    <textarea
                      className="findings-form-textarea"
                      placeholder="Description"
                      rows={2}
                      value={editForm.description ?? ''}
                      onChange={e => setEditForm(p => ({ ...p, description: e.target.value }))}
                    />
                    <textarea
                      className="findings-form-textarea"
                      placeholder="Evidence"
                      rows={2}
                      value={editForm.evidence ?? ''}
                      onChange={e => setEditForm(p => ({ ...p, evidence: e.target.value }))}
                    />
                    <input
                      className="findings-form-input"
                      placeholder="Recommendation"
                      value={editForm.recommendation ?? ''}
                      onChange={e => setEditForm(p => ({ ...p, recommendation: e.target.value }))}
                    />
                    {error && editingId === f.finding_id && <div className="findings-error">{error}</div>}
                    <div className="findings-form-actions">
                      <button className="session-action-btn" onClick={() => saveFindingEdit(f.finding_id)} disabled={saving}>
                        <Check size={12} /> Save
                      </button>
                      <button className="session-action-btn" onClick={() => { setEditingId(null); setEditForm({}) }}>
                        <X size={12} /> Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="finding-card-header">
                      <span className="finding-title">{f.title}</span>
                      <span className={`finding-status finding-status--${f.status ?? 'open'}`}>{f.status ?? 'open'}</span>
                      <div className="finding-card-actions">
                        <button className="finding-icon-btn" title="Edit" onClick={() => startEdit(f)}>
                          <Edit2 size={12} />
                        </button>
                        <button
                          className="finding-icon-btn finding-icon-btn--danger"
                          title="Delete"
                          disabled={deletingId === f.finding_id}
                          onClick={() => deleteFinding(f.finding_id)}
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </div>
                    {f.description && <p className="finding-description">{f.description}</p>}
                    <div className="finding-meta">
                      {f.tool && <span className="mono finding-meta-item">tool: {f.tool}</span>}
                      {f.cve && <span className="finding-meta-item finding-cve">{f.cve}</span>}
                      {f.tags && f.tags.length > 0 && (
                        <span className="finding-meta-item">{f.tags.join(', ')}</span>
                      )}
                    </div>
                    {f.evidence && (
                      <details className="finding-evidence-details">
                        <summary className="finding-evidence-summary">Evidence</summary>
                        <pre className="finding-evidence-pre">{f.evidence}</pre>
                      </details>
                    )}
                    {f.recommendation && (
                      <div className="finding-recommendation">
                        <strong>Recommendation:</strong> {f.recommendation}
                      </div>
                    )}
                  </>
                )}
              </div>
            ))}
          </div>
        )
      })}
    </div>
  )
}
