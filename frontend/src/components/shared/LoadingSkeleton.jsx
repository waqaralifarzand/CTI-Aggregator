export default function LoadingSkeleton({ height = 20, width = '100%', borderRadius = 4, style = {} }) {
  return (
    <div
      className="skeleton"
      style={{ height, width, borderRadius, ...style }}
    />
  )
}

export function SkeletonPanel() {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      padding: '20px',
    }}>
      <LoadingSkeleton height={16} width="30%" style={{ marginBottom: 16 }} />
      <LoadingSkeleton height={12} width="100%" style={{ marginBottom: 8 }} />
      <LoadingSkeleton height={12} width="80%" style={{ marginBottom: 8 }} />
      <LoadingSkeleton height={12} width="60%" />
    </div>
  )
}
