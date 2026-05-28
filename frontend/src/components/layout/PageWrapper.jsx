import React from 'react'

export default function PageWrapper({ children, style = {} }) {
  return (
    <div
      style={{
        padding: '32px',
        minHeight: '100vh',
        ...style,
      }}
    >
      {children}
    </div>
  )
}
