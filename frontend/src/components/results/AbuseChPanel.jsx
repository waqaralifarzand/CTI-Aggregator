function SubSection({ title, data, type }) {
  const applicable = data?.applicable !== false
  const found = data?.found

  return (
    <div style={{ padding: '14px 0', borderBottom: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: found ? '12px' : 0 }}>
        <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '13px' }}>{title}</span>
        {!applicable ? (
          <span style={{ color: 'var(--text-muted)', fontSize: '12px', fontStyle: 'italic' }}>Not applicable for this IoC type</span>
        ) : found ? (
          <span style={{ color: 'var(--critical)', fontSize: '12px', fontWeight: 600 }}>⚠ Flagged</span>
        ) : (
          <span style={{ color: 'var(--clean)', fontSize: '12px' }}>✓ Clean</span>
        )}
      </div>

      {applicable && found && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '13px' }}>
          {type === 'urlhaus' && (
            <>
              {data.url_count > 0 && (
                <Row label="Malicious URLs" value={data.url_count} />
              )}
              {data.tags?.length > 0 && (
                <Row label="Tags" value={data.tags.join(', ')} />
              )}
            </>
          )}
          {type === 'malwarebazaar' && (
            <>
              {data.file_type && <Row label="File Type" value={data.file_type} />}
              {data.signature && <Row label="Signature" value={data.signature} />}
              {data.tags?.length > 0 && <Row label="Tags" value={data.tags.join(', ')} />}
            </>
          )}
        </div>
      )}
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div style={{ display: 'flex', gap: '12px' }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 110 }}>{label}</span>
      <span style={{ color: 'var(--text-primary)' }}>{value ?? '—'}</span>
    </div>
  )
}

export default function AbuseChPanel({ urlhaus, malwarebazaar, animStyle }) {
  const anyFound = urlhaus?.found || malwarebazaar?.found

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: `1px solid ${anyFound ? 'rgba(239,68,68,0.3)' : 'var(--border)'}`,
      borderRadius: '8px',
      padding: '16px 20px',
      opacity: anyFound ? 1 : 0.8,
      ...animStyle,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
        <span style={{
          fontSize: '10px', fontWeight: 700, letterSpacing: '0.08em',
          padding: '2px 6px', borderRadius: '3px',
          background: 'rgba(249,115,22,0.15)', color: 'var(--high)',
        }}>ABUSE.CH</span>
        <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '14px' }}>
          Abuse.ch Feeds
        </span>
      </div>
      <SubSection title="URLhaus" data={urlhaus} type="urlhaus" />
      <div style={{ paddingTop: '4px' }}>
        <SubSection title="MalwareBazaar" data={malwarebazaar} type="malwarebazaar" />
      </div>
    </div>
  )
}
