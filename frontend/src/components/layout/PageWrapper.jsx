export default function PageWrapper({ children }) {
  return (
    <div style={{
      marginLeft: '240px',
      padding: '32px',
      minHeight: '100vh',
      backgroundColor: 'var(--bg-primary)',
    }}>
      {children}
    </div>
  )
}
