import React, { useCallback } from 'react'
import { useDropzone } from 'react-dropzone'

export default function CsvUploader({ onUpload }) {
  const onDrop = useCallback((accepted) => {
    if (accepted[0]) onUpload(accepted[0])
  }, [onUpload])

  const { getRootProps, getInputProps, isDragActive, acceptedFiles, fileRejections } = useDropzone({
    onDrop,
    accept: { 'text/csv': ['.csv'], 'text/plain': ['.txt'] },
    maxFiles: 1,
  })

  return (
    <div>
      <div
        {...getRootProps()}
        style={{
          border: `2px dashed ${isDragActive ? 'var(--accent)' : 'var(--border)'}`,
          borderRadius: '10px',
          padding: '48px 24px',
          textAlign: 'center',
          cursor: 'pointer',
          background: isDragActive ? 'rgba(6,182,212,0.04)' : 'var(--bg-card)',
          transition: 'all 0.15s',
        }}
      >
        <input {...getInputProps()} />
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="1.5"
          style={{ margin: '0 auto 14px', display: 'block' }}>
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
          <polyline points="17 8 12 3 7 8"/>
          <line x1="12" y1="3" x2="12" y2="15"/>
        </svg>
        <p style={{ fontSize: '14px', color: 'var(--text-secondary)', margin: '0 0 6px', fontWeight: '500' }}>
          {isDragActive ? 'Drop your CSV here' : 'Drop CSV file here or click to browse'}
        </p>
        <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: 0 }}>
          One IoC per line — IP addresses, domains, or file hashes
        </p>
        {acceptedFiles[0] && (
          <div style={{ marginTop: '12px', fontSize: '13px', color: 'var(--accent)', fontWeight: '600' }}>
            ✓ {acceptedFiles[0].name}
          </div>
        )}
        {fileRejections.length > 0 && (
          <div style={{ marginTop: '12px', fontSize: '13px', color: 'var(--critical)' }}>
            Invalid file type — please upload a .csv file
          </div>
        )}
      </div>
    </div>
  )
}
