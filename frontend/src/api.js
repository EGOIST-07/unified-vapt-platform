/**
 * API communication layer for the VAPT Dashboard backend.
 */
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// ─── Auth token interceptor ──────────────────────────────────────────────────
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 || error.response?.status === 403) {
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      window.dispatchEvent(new Event('auth-logout'));
    }
    return Promise.reject(error);
  },
);

// ─── Auth ─────────────────────────────────────────────────────────────────────
export const login = (username, password) =>
  api.post('/auth/login', { username, password }).then(r => {
    localStorage.setItem('token', r.data.access_token);
    localStorage.setItem('username', r.data.username);
    return r.data;
  });

export const logout = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('username');
};

export const getStoredToken = () => localStorage.getItem('token');
export const getStoredUsername = () => localStorage.getItem('username');

// ─── Dashboard ────────────────────────────────────────────────────────────────
export const fetchDashboardStats  = () => api.get('/dashboard/stats').then(r => r.data);
export const fetchSeverityCounts  = () => api.get('/dashboard/severity').then(r => r.data);
export const fetchVulnTrends      = (days = 30) => api.get(`/dashboard/trends?days=${days}`).then(r => r.data);
export const fetchTopAssets       = (limit = 10) => api.get(`/dashboard/top-assets?limit=${limit}`).then(r => r.data);
export const fetchAssetCounts     = () => api.get('/dashboard/asset-counts').then(r => r.data);

// ─── Assets ───────────────────────────────────────────────────────────────────
export const fetchAssets     = (params = {}) => api.get('/assets', { params }).then(r => r.data);
export const fetchAsset      = (id) => api.get(`/assets/${id}`).then(r => r.data);
export const createAsset     = (data) => api.post('/assets', data).then(r => r.data);
export const deleteAsset     = (id) => api.delete(`/assets/${id}`);
export const fetchServices   = (assetId) => api.get(`/assets/${assetId}/services`).then(r => r.data);

// ─── Scans ────────────────────────────────────────────────────────────────────
export const fetchScans  = (params = {}) => api.get('/scans', { params }).then(r => r.data);
export const fetchScan   = (id) => api.get(`/scans/${id}`).then(r => r.data);
export const startScan   = (data) => api.post('/scans', data).then(r => r.data);
export const cancelScan  = (scanId) => api.post(`/scans/${scanId}/cancel`).then(r => r.data);

// ─── Vulnerabilities ─────────────────────────────────────────────────────────
export const fetchVulnerabilities  = (params = {}) => api.get('/vulnerabilities', { params }).then(r => r.data);
export const fetchScanRecommendations = (scanId) => api.get(`/scans/${scanId}/recommendations`).then(r => r.data);

// ─── Discovery ────────────────────────────────────────────────────────────────
export const discoverAssets = (domain) => api.post('/discover-subdomains', { domain }).then(r => r.data);
export const fetchDiscoveryStatus = (taskId) => api.get(`/discover-subdomains/${taskId}`).then(r => r.data);

// ─── Reports ──────────────────────────────────────────────────────────────────
export const downloadReport = (assetId) => {
  const token = localStorage.getItem('token');
  const link = document.createElement('a');
  link.href = `/api/report/${assetId}?token=${encodeURIComponent(token)}`;
  link.download = '';
  document.body.appendChild(link);
  link.click();
  link.remove();
};

export const downloadScanReport = (scanId) => {
  const token = localStorage.getItem('token');
  const link = document.createElement('a');
  link.href = `/api/report/scan/${scanId}?token=${encodeURIComponent(token)}`;
  link.download = '';
  document.body.appendChild(link);
  link.click();
  link.remove();
};

// ─── Health ───────────────────────────────────────────────────────────────────
export const fetchHealth = () => api.get('/health').then(r => r.data);

export default api;
