import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/layout/Sidebar'
import Home       from './pages/Home'
import Results    from './pages/Results'
import Dashboard  from './pages/Dashboard'
import Reports    from './pages/Reports'
import Feeds      from './pages/Feeds'
import MLInsights from './pages/MLInsights'
import Bulk       from './pages/Bulk'

export default function App() {
  return (
    <BrowserRouter>
      <Sidebar />
      <Routes>
        <Route path="/"                element={<Home />} />
        <Route path="/results/:scanId" element={<Results />} />
        <Route path="/dashboard"       element={<Dashboard />} />
        <Route path="/reports"         element={<Reports />} />
        <Route path="/feeds"           element={<Feeds />} />
        <Route path="/ml"              element={<MLInsights />} />
        <Route path="/bulk"            element={<Bulk />} />
      </Routes>
    </BrowserRouter>
  )
}
