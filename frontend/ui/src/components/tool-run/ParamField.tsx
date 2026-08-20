import type { ChangeEvent } from 'react'

export function ParamField({
  name,
  value,
  onChange,
  required,
  disabled,
  isBoolean,
}: {
  name: string
  value: string
  onChange: (v: string) => void
  required?: boolean
  disabled?: boolean
  isBoolean?: boolean
}) {
  function handleChange(e: ChangeEvent<HTMLInputElement>) {
    onChange(e.target.value)
  }

  function handleToggle(e: ChangeEvent<HTMLInputElement>) {
    onChange(e.target.checked ? 'true' : 'false')
  }

  if (isBoolean) {
    return (
      <div className="run-field run-field--bool">
        <label className="run-field-label mono">{name}</label>
        <label className="run-field-toggle">
          <input
            type="checkbox"
            name={name}
            checked={value === 'true'}
            onChange={handleToggle}
            disabled={disabled}
          />
          <span className="run-field-toggle-track">
            <span className="run-field-toggle-thumb" />
          </span>
        </label>
      </div>
    )
  }

  return (
    <div className="run-field">
      <label className="run-field-label mono">
        {name}
        {required && <span className="run-required">*</span>}
      </label>
      <input
        className="run-field-input mono"
        name={name}
        value={value}
        onChange={handleChange}
        placeholder={required ? 'required' : 'optional'}
        disabled={disabled}
      />
    </div>
  )
}
