import React, { useState } from 'react'
import { trainModel } from '../../api/client'

export default function RetrainButton({ onRetrain }) {
  const [training, setTraining] = useState(false)
  const [message, setMessage] = useState(null)
  const [isError, setIsError] = useState(false)

  const handleRetrain = async () => {
    setTraining(true)
    setMessage(null)
    try {
      const res = await trainModel()
      if (res.data.success) {
        setIsError(false)
        setMessage(res.data.data?.message || 'Training started.')
        if (onRetrain) onRetrain()
      } else {
        setIsError(true)
        setMessage(res.data.error || 'Training failed')
      }
    } catch (err) {
      setIsError(true)
      setMessage(err.response?.data?.error || 'Training failed')
    } finally {
      setTraining(false)
      setTimeout(() => setMessage(null), 5000)
    }
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
      <button
        onClick={handleRetrain}
        disabled={training}
        style={{
          background: 'var(--accent)', border: 'none', color: '#0a0e1a',
          borderRadius: '6px', padding: '10px 20px', cursor: training ? 'not-allowed' : 'pointer',
          fontSize: '13px', fontWeight: '700', fontFamily: 'inherit',
          opacity: training ? 0.7 : 1, display: 'flex', alignItems: 'center', gap: '6px',
        }}
      >
        {training ? (
          <>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
              style={{ animation: 'spin 1s linear infinite' }}>
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            Training...
          </>
        ) : (
          <>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/>
            </svg>
            Retrain Model
          </>
        )}
      </button>
      {message && (
        <span style={{ fontSize: '13px', color: isError ? 'var(--critical)' : 'var(--clean)' }}>
          {message}
        </span>
      )}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
