import { Routes, Route } from "react-router-dom";
import Layout from "./components/Layout";
import Dashboard from "./pages/Dashboard";
import Indicators from "./pages/Indicators";
import Anomalies from "./pages/Anomalies";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="indicators" element={<Indicators />} />
        <Route path="anomalies" element={<Anomalies />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}
