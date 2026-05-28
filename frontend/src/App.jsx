import React from 'react'
import { Routes, Route } from 'react-router-dom'
import Sidebar from './components/layout/Sidebar'
import Home from './pages/Home'
import Results from './pages/Results'
import Dashboard from './pages/Dashboard'
import Reports from './pages/Reports'
import Feeds from './pages/Feeds'
import MLInsights from './pages/MLInsights'
import Bulk from './pages/Bulk'

export default function App() {
  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--bg-primary)' }}>
      <Sidebar />
      <main style={{ marginLeft: '240px', flex: 1, minHeight: '100vh', overflow: 'auto' }}>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/results/:scanId" element={<Results />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/feeds" element={<Feeds />} />
          <Route path="/ml" element={<MLInsights />} />
          <Route path="/bulk" element={<Bulk />} />
        </Routes>
      </main>
    </div>
  )
}
