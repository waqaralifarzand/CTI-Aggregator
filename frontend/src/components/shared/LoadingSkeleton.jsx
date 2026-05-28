import React from 'react'

export default function LoadingSkeleton({ height = '20px', width = '100%', className = '', borderRadius = '6px' }) {
  return (
    <div
      className={`shimmer ${className}`}
      style={{ height, width, borderRadius, display: 'block' }}
    />
  )
}
