import axios from "axios";

const api = axios.create({
  baseURL: "/api/v1",
  headers: { "Content-Type": "application/json" },
});

// --- Feed endpoints ---
export const fetchFeeds = (feed = "all") =>
  api.post("/feeds/fetch", { feed });

export const getFeedStatus = () =>
  api.get("/feeds/status").then((r) => r.data);

export const getFeedHistory = (limit = 20) =>
  api.get("/feeds/history", { params: { limit } }).then((r) => r.data);

// --- Indicator endpoints ---
export const getIndicators = (params = {}) =>
  api.get("/indicators", { params }).then((r) => r.data);

export const searchIndicator = (value) =>
  api.get("/indicators/search", { params: { value } }).then((r) => r.data);

export const getIndicator = (id) =>
  api.get(`/indicators/${id}`).then((r) => r.data);

// --- Dashboard endpoints ---
export const getDashboardSummary = () =>
  api.get("/dashboard/summary").then((r) => r.data);

export const getDashboardTimeline = (days = 30) =>
  api.get("/dashboard/timeline", { params: { days } }).then((r) => r.data);

export const getTopIoCs = (limit = 10) =>
  api.get("/dashboard/top-iocs", { params: { limit } }).then((r) => r.data);

export const getFeedHealth = () =>
  api.get("/dashboard/feed-health").then((r) => r.data);

export const getRecentActivity = (limit = 20) =>
  api.get("/dashboard/recent-activity", { params: { limit } }).then((r) => r.data);

// --- Anomaly endpoints ---
export const runDetection = () =>
  api.post("/anomalies/run").then((r) => r.data);

export const getAnomalies = (params = {}) =>
  api.get("/anomalies", { params }).then((r) => r.data);

export const getAnomalySummary = () =>
  api.get("/anomalies/summary").then((r) => r.data);

// --- Prediction endpoints ---
export const classifyIndicator = (data) =>
  api.post("/predictions/classify", data).then((r) => r.data);

export const trainModel = (version = "v1") =>
  api.post("/predictions/train", { version }).then((r) => r.data);

export const getModelInfo = () =>
  api.get("/predictions/model-info").then((r) => r.data);

export default api;
