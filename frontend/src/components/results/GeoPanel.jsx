const COUNTRY_FLAGS = {
  US: '🇺🇸', GB: '🇬🇧', DE: '🇩🇪', FR: '🇫🇷', CN: '🇨🇳', RU: '🇷🇺',
  JP: '🇯🇵', KR: '🇰🇷', IN: '🇮🇳', BR: '🇧🇷', AU: '🇦🇺', CA: '🇨🇦',
  NL: '🇳🇱', SE: '🇸🇪', SG: '🇸🇬', PK: '🇵🇰', TR: '🇹🇷', IR: '🇮🇷',
}

function GeoRow({ label, value }) {
  if (!value) return null
  return (
    <div style={{ display: 'flex', gap: '12px', padding: '8px 0', borderBottom: '1px solid var(--border)', fontSize: '13px' }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 90, flexShrink: 0 }}>{label}</span>
      <span style={{ color: 'var(--text-primary)' }}>{value}</span>
    </div>
  )
}

export default function GeoPanel({ geo, animStyle }) {
  if (!geo) return null

  const flag = COUNTRY_FLAGS[geo.country_code] || '🌐'

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      padding: '20px',
      ...animStyle,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
        <span style={{ fontSize: '22px' }}>{flag}</span>
        <div>
          <span style={{ color: 'var(--text-muted)', fontSize: '11px', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', display: 'block' }}>
            Geolocation
          </span>
          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
            {geo.country || 'Unknown'}
          </span>
        </div>
      </div>
      <GeoRow label="City" value={geo.city} />
      <GeoRow label="Region" value={geo.region} />
      <GeoRow label="Country" value={geo.country} />
      <GeoRow label="ISP" value={geo.isp} />
      <GeoRow label="ASN" value={geo.asn} />
    </div>
  )
}
