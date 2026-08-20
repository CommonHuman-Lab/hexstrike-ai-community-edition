import { Search, X } from 'lucide-react'
import type { RefObject } from 'react'
import './SearchInput.css'

interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  className?: string
  inputRef?: RefObject<HTMLInputElement | null>
}

export function SearchInput({ value, onChange, placeholder = 'Search…', className = '', inputRef }: SearchInputProps) {
  return (
    <div className={`ui-search-wrap${className ? ` ${className}` : ''}`}>
      <Search size={13} className="ui-search-icon" />
      <input
        ref={inputRef}
        type="text"
        className="input ui-search-input"
        placeholder={placeholder}
        value={value}
        onChange={e => onChange(e.target.value)}
      />
      {value && (
        <button
          type="button"
          className="ui-search-clear"
          onClick={() => onChange('')}
          aria-label="Clear search"
        >
          <X size={13} />
        </button>
      )}
    </div>
  )
}
