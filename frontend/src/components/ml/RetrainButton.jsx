import React, { useState } from 'react'
import { trainModel } from '../../api/client'

export default function RetrainButton({ onRetrain }) {
  const [training, setTraining] = useState(false)
  const [toast, setToast] = useState(null) // { message, isError }

  const showToast = (message, isError = false) => {
    setToast({ message, isError })
    setTimeout(() => setToast(null), 4000)
  }

  const handleRetrain = async () => {
    setTraining(true)
    setToast(null)
    try {
      const res = await trainModel()
      if (res.data.success) {
        const samples = res.data.data?.training_samples
        const msg = samples
          ? `Model training started. Refresh metrics in ~30 seconds. (${samples} samples)`
          : 'Model training started. Refresh metrics in ~30 seconds.'
        showToast(msg, false)
        if (onRetrain) onRetrain()
      } else {
        showToast(res.data.error || 'Training failed', true)
      }
    } catch (err) {
      showToast(err.response?.data?.error || 'Training failed', true)
    } finally {
      setTraining(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '8px' }}>
      <button
        onClick={handleRetrain}
        disabled={training}
        style={{
          background: 'transparent',
          border: '1px solid var(--accent)',
          color: 'var(--accent)',
          borderRadius: '6px',
          padding: '8px 16px',
          cursor: training ? 'not-allowed' : 'pointer',
          fontSize: '13px',
          fontWeight: '600',
          fontFamily: 'inherit',
          opacity: training ? 0.6 : 1,
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          transition: 'all 0.15s',
        }}
        onMouseEnter={(e) => { if (!training) { e.currentTarget.style.background = 'rgba(6,182,212,0.1)' } }}
        onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent' }}
      >
        {training ? (
          <>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
              style={{ animation: 'spin 1s linear infinite' }}>
              <path d="M21 12a9 9 0 1 1-6.219-8.56" />
            </svg>
            Training...
          </>
        ) : (
          <>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <polyline points="1 4 1 10 7 10" />
              <path d="M3.51 15a9 9 0 1 0 .49-4" />
            </svg>
            Retrain Model
          </>
        )}
      </button>

      {toast && (
        <div style={{
          fontSize: '12px',
          color: toast.isError ? 'var(--critical)' : 'var(--clean)',
          background: toast.isError ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)',
          border: `1px solid ${toast.isError ? 'rgba(239,68,68,0.3)' : 'rgba(16,185,129,0.3)'}`,
          borderRadius: '6px',
          padding: '6px 12px',
          maxWidth: '380px',
          textAlign: 'right',
        }}>
          {toast.message}
        </div>
      )}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
