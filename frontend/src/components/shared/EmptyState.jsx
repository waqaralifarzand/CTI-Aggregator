export default function EmptyState({ icon, title, description }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '48px 24px',
      textAlign: 'center',
      gap: '12px',
    }}>
      {icon && (
        <div style={{ color: 'var(--text-muted)', marginBottom: 4 }}>
          {icon}
        </div>
      )}
      <p style={{ color: 'var(--text-secondary)', fontSize: '15px', fontWeight: 600, margin: 0 }}>
        {title}
      </p>
      {description && (
        <p style={{ color: 'var(--text-muted)', fontSize: '13px', margin: 0 }}>
          {description}
        </p>
      )}
    </div>
  )
}
