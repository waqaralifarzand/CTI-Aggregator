import React from 'react'

const inputStyle = {
  background: 'var(--bg-card)',
  border: '1px solid var(--border)',
  color: 'var(--text-primary)',
  borderRadius: '6px',
  padding: '7px 10px',
  fontSize: '13px',
  height: '34px',
  outline: 'none',
  fontFamily: 'inherit',
}

export default function FilterBar({ filters, onFilterChange, onClear }) {
  return (
    <div style={{
      display: 'flex',
      flexWrap: 'wrap',
      gap: '8px',
      alignItems: 'center',
      padding: '12px 16px',
      background: 'var(--bg-card)',
      borderBottom: '1px solid var(--border)',
    }}>
      <select
        value={filters.severity}
        onChange={(e) => onFilterChange('severity', e.target.value)}
        style={inputStyle}
      >
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="clean">Clean</option>
      </select>

      <select
        value={filters.ioc_type}
        onChange={(e) => onFilterChange('ioc_type', e.target.value)}
        style={inputStyle}
      >
        <option value="">All IoC Types</option>
        <option value="ip">IP Address</option>
        <option value="domain">Domain</option>
        <option value="hash_md5">MD5 Hash</option>
        <option value="hash_sha256">SHA256 Hash</option>
      </select>

      <input
        type="date"
        value={filters.date_from}
        onChange={(e) => onFilterChange('date_from', e.target.value)}
        style={{ ...inputStyle, width: '140px' }}
        title="Date from"
      />

      <input
        type="date"
        value={filters.date_to}
        onChange={(e) => onFilterChange('date_to', e.target.value)}
        style={{ ...inputStyle, width: '140px' }}
        title="Date to"
      />

      <input
        type="text"
        value={filters.search}
        onChange={(e) => onFilterChange('search', e.target.value)}
        placeholder="Search IoC value..."
        style={{ ...inputStyle, width: '200px' }}
      />

      <button
        onClick={onClear}
        style={{
          background: 'transparent',
          border: '1px solid var(--border)',
          color: 'var(--text-secondary)',
          borderRadius: '6px',
          padding: '7px 14px',
          fontSize: '13px',
          height: '34px',
          cursor: 'pointer',
          fontFamily: 'inherit',
          transition: 'all 0.15s',
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.borderColor = 'var(--text-muted)'
          e.currentTarget.style.color = 'var(--text-primary)'
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.borderColor = 'var(--border)'
          e.currentTarget.style.color = 'var(--text-secondary)'
        }}
      >
        Clear
      </button>
    </div>
  )
}
