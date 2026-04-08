/**
 * Main dashboard — sidebar layout, login, header, and page orchestration.
 */
import React, { useState, useEffect, useCallback } from 'react';
import {
  fetchDashboardStats, fetchSeverityCounts, fetchVulnTrends,
  fetchTopAssets, fetchAssetCounts, fetchAssets, fetchScans,
  fetchVulnerabilities, startScan, createAsset, discoverAssets,
  login as apiLogin, logout as apiLogout, getStoredToken, getStoredUsername,
  cancelScan, downloadScanReport, downloadReport,
  fetchScanRecommendations, fetchDiscoveryStatus,
} from './api';
import {
  StatsCards, SeverityChart, TrendsChart, TopAssetsChart,
  AssetTypeChart, AttackSurfaceMap, VulnTable, ScanPanel,
  AddAssetForm, ScanHistory, AssetList, C, cardStyle, inputBase, btnPrimary,
} from './components';

const REFRESH_INTERVAL = 5000;
const DISCOVERY_POLL_INTERVAL_MS = 2000;
const DISCOVERY_MAX_WAIT_MS = 7 * 60 * 1000;

/* ─── SVG Icons ───────────────────────────────────────────────────────────── */

const Icon = ({ children, size = 20 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    {children}
  </svg>
);

const Icons = {
  overview: (
    <Icon>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </Icon>
  ),
  assets: (
    <Icon>
      <rect x="2" y="2" width="20" height="8" rx="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" />
      <circle cx="6" cy="6" r="1" fill="currentColor" stroke="none" />
      <circle cx="6" cy="18" r="1" fill="currentColor" stroke="none" />
    </Icon>
  ),
  vulns: (
    <Icon>
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </Icon>
  ),
  map: (
    <Icon>
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
    </Icon>
  ),
  logout: (
    <Icon>
      <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4" />
      <polyline points="16 17 21 12 16 7" />
      <line x1="21" y1="12" x2="9" y2="12" />
    </Icon>
  ),
  search: (
    <Icon size={18}>
      <circle cx="11" cy="11" r="8" />
      <path d="M21 21l-4.35-4.35" />
    </Icon>
  ),
  user: (
    <Icon>
      <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </Icon>
  ),
  chevron: (
    <Icon size={16}>
      <polyline points="6 9 12 15 18 9" />
    </Icon>
  ),
  shield: (
    <Icon size={40}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </Icon>
  ),
};

/* ─── Login Page ──────────────────────────────────────────────────────────── */

function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await apiLogin(username, password);
      onLogin();
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh', background: '#F8FAFC',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 16,
      backgroundImage: 'radial-gradient(ellipse at 50% 0%, rgba(79,70,229,0.06) 0%, transparent 60%)',
      backgroundSize: '100% 100%, 40px 40px, 40px 40px',
      backgroundColor: '#F8FAFC',
    }}>
      <form onSubmit={handleSubmit} style={{
        background: '#FFFFFF', borderRadius: 16, padding: '40px 28px', width: '100%', maxWidth: 400,
        border: `1px solid ${C.border}`,
        boxShadow: '0 10px 40px -12px rgba(0,0,0,.12), 0 4px 12px rgba(0,0,0,0.06)',
      }}>
        {/* Shield Icon */}
        <div style={{ textAlign: 'center', marginBottom: 8, color: C.accent }}>
          {Icons.shield}
        </div>

        <h1 style={{
          color: C.text, fontSize: 24, fontWeight: 700, textAlign: 'center',
          letterSpacing: '-0.02em', marginBottom: 4,
        }}>
          VAPT Dashboard
        </h1>
        <p style={{ color: '#64748B', fontSize: 14, textAlign: 'center', marginBottom: 32 }}>
          Sign in to continue
        </p>

        {error && (
          <div style={{
            background: '#EF44441A', border: '1px solid #EF444466', borderRadius: 8,
            padding: '8px 12px', color: C.critical, fontSize: 13, marginBottom: 16,
          }}>
            {error}
          </div>
        )}

        <label style={{ display: 'block', color: C.muted, fontSize: 13, fontWeight: 500, marginBottom: 6 }}>
          Username
        </label>
        <input
          type="text"
          value={username}
          onChange={e => setUsername(e.target.value)}
          required
          autoFocus
          style={{ ...inputBase, width: '100%', marginBottom: 18 }}
        />

        <label style={{ display: 'block', color: C.muted, fontSize: 13, fontWeight: 500, marginBottom: 6 }}>
          Password
        </label>
        <input
          type="password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          required
          style={{ ...inputBase, width: '100%', marginBottom: 20 }}
        />

        {/* Remember me */}
        <label style={{
          display: 'flex', alignItems: 'center', gap: 8, marginBottom: 24,
          cursor: 'pointer', fontSize: 13, color: C.muted, userSelect: 'none',
        }}>
          <input
            type="checkbox"
            checked={remember}
            onChange={e => setRemember(e.target.checked)}
            style={{ accentColor: C.accent, width: 16, height: 16, cursor: 'pointer' }}
          />
          Remember me
        </label>

        <button type="submit" disabled={loading} style={{
          ...btnPrimary, width: '100%', padding: '12px 0', fontSize: 15,
          cursor: loading ? 'wait' : 'pointer',
          opacity: loading ? 0.7 : 1,
        }}>
          {loading ? 'Signing in...' : 'Login'}
        </button>
      </form>
    </div>
  );
}

/* ─── Sidebar ─────────────────────────────────────────────────────────────── */

function Sidebar({ activeTab, onTabChange, isMobile }) {
  const navItems = [
    { key: 'overview', label: 'Overview',        icon: Icons.overview },
    { key: 'assets',   label: 'Assets & Scans',  icon: Icons.assets },
    { key: 'vulns',    label: 'Vulnerabilities',  icon: Icons.vulns },
    { key: 'map',      label: 'Attack Surface',   icon: Icons.map },
  ];

  const itemStyle = (active) => ({
    display: 'flex', alignItems: 'center', gap: 12,
    padding: '12px 16px', borderRadius: 8, marginBottom: 4,
    cursor: 'pointer', fontSize: 14, fontWeight: 500,
    transition: 'background .2s, color .2s',
    background: active ? '#EEF2FF' : 'transparent',
    color: active ? C.accent : C.muted,
    border: active ? '1px solid #E0E7FF' : '1px solid transparent',
    boxShadow: 'none',
    width: '100%', textAlign: 'left',
  });

  if (isMobile) {
    return (
      <nav style={{
        position: 'sticky', top: 0, zIndex: 9,
        display: 'flex', gap: 8, overflowX: 'auto',
        padding: '10px 12px', background: '#FFFFFF',
        borderBottom: `1px solid ${C.border}`,
      }}>
        {navItems.map(item => (
          <button
            key={item.key}
            onClick={() => onTabChange(item.key)}
            style={{
              ...itemStyle(activeTab === item.key),
              marginBottom: 0,
              minWidth: 120,
              justifyContent: 'center',
              padding: '10px 12px',
            }}
          >
            {item.icon}
            {item.label}
          </button>
        ))}
      </nav>
    );
  }

  return (
    <aside style={{
      width: 260, flexShrink: 0, background: '#FFFFFF',
      borderRight: `1px solid ${C.border}`,
      borderLeft: '2px solid #4F46E5',
      display: 'flex', flexDirection: 'column',
      height: '100vh', position: 'sticky', top: 0,
    }}>
      {/* Logo */}
      <div style={{
        padding: '24px 20px 20px', display: 'flex', alignItems: 'center', gap: 10,
        borderBottom: `1px solid ${C.border}`,
      }}>
        <div style={{ color: C.accent }}>{Icons.shield}</div>
        <div>
          <div style={{ fontSize: 16, fontWeight: 700, color: C.text, letterSpacing: '-0.02em' }}>VAPT</div>
          <div style={{ fontSize: 11, color: C.muted, fontWeight: 500 }}>Dashboard</div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '16px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
        {navItems.map(item => (
          <button
            key={item.key}
            onClick={() => onTabChange(item.key)}
            style={itemStyle(activeTab === item.key)}
            onMouseEnter={e => { if (activeTab !== item.key) e.currentTarget.style.background = '#F1F5F9'; }}
            onMouseLeave={e => { if (activeTab !== item.key) e.currentTarget.style.background = 'transparent'; }}
          >
            {item.icon}
            {item.label}
          </button>
        ))}
      </nav>
    </aside>
  );
}

/* ─── Top Header Bar ──────────────────────────────────────────────────────── */

function TopHeader({ title, username, onLogout, isMobile }) {
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  const pageTitles = {
    overview: 'Overview',
    assets: 'Assets & Scans',
    vulns: 'Vulnerabilities',
    map: 'Attack Surface',
  };

  return (
    <header style={{
      height: 64, padding: isMobile ? '0 12px' : '0 28px',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.85)',
      position: 'sticky', top: 0, zIndex: 10,
      backdropFilter: 'blur(12px)',
    }}>
      {/* Page Title */}
      <h1 style={{ fontSize: isMobile ? 18 : 24, fontWeight: 700, color: C.text, letterSpacing: '-0.02em' }}>
        {pageTitles[title] || title}
      </h1>

      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        {!isMobile && (
          <div style={{ position: 'relative' }}>
            <input
              placeholder="Search..."
              style={{
                ...inputBase, width: 240, paddingLeft: 36,
                background: '#F8FAFC', border: `1px solid ${C.border}`,
              }}
            />
            <span style={{
              position: 'absolute', left: 12, top: '50%',
              transform: 'translateY(-50%)', color: C.muted, pointerEvents: 'none',
            }}>
              {Icons.search}
            </span>
          </div>
        )}

        {/* User Menu */}
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setUserMenuOpen(!userMenuOpen)}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: isMobile ? '6px 8px' : '6px 12px', borderRadius: 8,
              background: C.card, border: `1px solid ${C.border}`,
              color: C.text, cursor: 'pointer', fontSize: 13, fontWeight: 500,
            }}
          >
            <div style={{
              width: 28, height: 28, borderRadius: '50%',
              background: C.accent + '15', color: C.accent,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              {Icons.user}
            </div>
            {!isMobile && (username || 'User')}
            {!isMobile && Icons.chevron}
          </button>

          {userMenuOpen && (
            <>
              <div
                style={{ position: 'fixed', inset: 0, zIndex: 15 }}
                onClick={() => setUserMenuOpen(false)}
              />
              <div style={{
                position: 'absolute', right: 0, top: 'calc(100% + 6px)',
                background: '#FFFFFF', border: `1px solid ${C.border}`, borderRadius: 10,
                padding: 6, minWidth: 160, zIndex: 20,
                boxShadow: '0 4px 16px rgba(0,0,0,.1), 0 1px 3px rgba(0,0,0,0.06)',
              }}>
                <button
                  onClick={() => setUserMenuOpen(false)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                    padding: '8px 12px', borderRadius: 6, border: 'none',
                    background: 'transparent', color: C.text, cursor: 'pointer',
                    fontSize: 13, textAlign: 'left',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = '#F1F5F9'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  {Icons.user}
                  Profile
                </button>
                <div style={{ height: 1, background: C.border, margin: '4px 0' }} />
                <button
                  onClick={() => { setUserMenuOpen(false); onLogout(); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8, width: '100%',
                    padding: '8px 12px', borderRadius: 6, border: 'none',
                    background: 'transparent', color: C.critical, cursor: 'pointer',
                    fontSize: 13, textAlign: 'left',
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = '#F1F5F9'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  {Icons.logout}
                  Logout
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  );
}

/* ─── Dashboard ──────────────────────────────────────────────────────────── */

export default function Dashboard() {
  const [isAuthenticated, setIsAuthenticated] = useState(!!getStoredToken());
  const [stats, setStats] = useState({});
  const [severity, setSeverity] = useState({});
  const [trends, setTrends] = useState([]);
  const [topAssets, setTopAssets] = useState([]);
  const [assetCounts, setAssetCounts] = useState({});
  const [assets, setAssets] = useState([]);
  const [scans, setScans] = useState([]);
  const [vulns, setVulns] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [scanRecommendations, setScanRecommendations] = useState([]);
  const [discoveryResults, setDiscoveryResults] = useState([]);
  const [discoveryDomain, setDiscoveryDomain] = useState('');
  const [discoveryTaskId, setDiscoveryTaskId] = useState('');
  const [discoveryStatus, setDiscoveryStatus] = useState('idle');
  const [discoveryStatusMessage, setDiscoveryStatusMessage] = useState('');
  const [discoveryElapsedSeconds, setDiscoveryElapsedSeconds] = useState(0);
  const [discoveryLoading, setDiscoveryLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState('overview');
  const [isMobile, setIsMobile] = useState(
    typeof window !== 'undefined' ? window.innerWidth < 980 : false,
  );

  useEffect(() => {
    const handleLogout = () => setIsAuthenticated(false);
    window.addEventListener('auth-logout', handleLogout);
    return () => window.removeEventListener('auth-logout', handleLogout);
  }, []);

  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth < 980);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  const loadData = useCallback(async () => {
    try {
      const vulnPromise = selectedScanId
        ? fetchVulnerabilities({ scan_id: selectedScanId }).catch(() => [])
        : fetchVulnerabilities().catch(() => []);
      const recPromise = selectedScanId
        ? fetchScanRecommendations(selectedScanId).catch(() => ({ recommendations: [] }))
        : Promise.resolve({ recommendations: [] });

      const [s, sev, tr, top, ac, a, sc, v, rec] = await Promise.all([
        fetchDashboardStats().catch(() => ({})),
        fetchSeverityCounts().catch(() => ({})),
        fetchVulnTrends().catch(() => []),
        fetchTopAssets().catch(() => []),
        fetchAssetCounts().catch(() => ({})),
        fetchAssets().catch(() => []),
        fetchScans().catch(() => []),
        vulnPromise,
        recPromise,
      ]);
      setStats(s); setSeverity(sev); setTrends(tr); setTopAssets(top);
      setAssetCounts(ac); setAssets(a); setScans(sc); setVulns(v);
      setScanRecommendations(rec.recommendations || []);
      setError(null);
    } catch {
      setError('Failed to connect to backend');
    } finally {
      setLoading(false);
    }
  }, [selectedScanId]);

  useEffect(() => {
    if (!isAuthenticated) return;
    loadData();
    const interval = setInterval(loadData, REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, [loadData, isAuthenticated]);

  const handleLogin = () => { setIsAuthenticated(true); setLoading(true); };
  const handleLogout = () => { apiLogout(); setIsAuthenticated(false); };

  const handleAddAsset = async (name, type) => {
    try {
      await createAsset({ asset_name: name, asset_type: type });
      loadData();
    } catch (err) {
      alert('Failed to add asset: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleScan = async (assetId, scanType) => {
    try {
      await startScan({ asset_id: assetId, scan_type: scanType || 'quick' });
      loadData();
    } catch (err) {
      alert('Failed to start scan: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleDiscover = async (domain) => {
    try {
      setDiscoveryDomain(domain);
      setDiscoveryResults([]);
      setDiscoveryTaskId('');
      setDiscoveryElapsedSeconds(0);
      setDiscoveryStatus('queued');
      setDiscoveryStatusMessage('Submitting discovery task...');
      setDiscoveryLoading(true);
      const started = await discoverAssets(domain);
      const taskId = started?.task_id;
      if (!taskId) {
        setDiscoveryStatus('failed');
        setDiscoveryStatusMessage('Discovery task could not be started.');
        setDiscoveryLoading(false);
        return;
      }
      setDiscoveryTaskId(taskId);
      setDiscoveryStatus('pending');
      setDiscoveryStatusMessage('Task queued. Waiting for worker...');

      const deadline = Date.now() + DISCOVERY_MAX_WAIT_MS;
      const startedAt = Date.now();
      let finalStatus = null;
      while (Date.now() < deadline) {
        const status = await fetchDiscoveryStatus(taskId);
        const elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
        setDiscoveryElapsedSeconds(elapsedSeconds);

        if (status.status === 'pending') {
          const phase = elapsedSeconds < 8 ? 'pending' : 'running';
          setDiscoveryStatus(phase);
          setDiscoveryStatusMessage(
            phase === 'pending'
              ? 'Task queued. Waiting for worker...'
              : 'Enumerating subdomains and verifying DNS records...'
          );
        }

        if (status.status === 'completed' || status.status === 'failed') {
          finalStatus = status;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, DISCOVERY_POLL_INTERVAL_MS));
      }

      if (!finalStatus) {
        setDiscoveryStatus('timeout');
        setDiscoveryStatusMessage('Discovery is still running. Please check again in a moment.');
        throw new Error('Subdomain discovery is still running. Please wait and try again in a moment.');
      }

      if (finalStatus?.status === 'failed') {
        setDiscoveryStatus('failed');
        setDiscoveryStatusMessage(finalStatus.reason || 'Subdomain discovery failed.');
        throw new Error(finalStatus.reason || 'Subdomain discovery failed');
      }
      setDiscoveryStatus('completed');
      setDiscoveryStatusMessage(
        `Completed. Found ${(finalStatus?.subdomains || []).length} verified subdomains.`
      );
      setDiscoveryResults(finalStatus?.subdomains || []);
    } catch (err) {
      if (discoveryStatus !== 'timeout') {
        setDiscoveryStatus('failed');
        setDiscoveryStatusMessage(err.response?.data?.detail || err.message || 'Discovery failed.');
      }
      alert('Discovery failed: ' + (err.response?.data?.detail || err.message));
    } finally {
      setDiscoveryLoading(false);
    }
  };

  const handleAddDiscoveredAsset = async (subdomain) => {
    try {
      await createAsset({ asset_name: subdomain, asset_type: 'subdomain' });
      await loadData();
    } catch (err) {
      alert('Failed to add discovered subdomain: ' + (err.response?.data?.detail || err.message));
      throw err;
    }
  };

  const handleCancelScan = async (scanId) => {
    try {
      await cancelScan(scanId);
      loadData();
    } catch (err) {
      alert('Failed to cancel scan: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleScanReport = (scanId) => downloadScanReport(scanId);
  const handleAssetReport = (assetId) => downloadReport(assetId);
  const handleViewVulns = () => {
    setSelectedScanId(null);
    setScanRecommendations([]);
    setTab('vulns');
  };
  const handleMapNodeClick = () => {
    setSelectedScanId(null);
    setScanRecommendations([]);
    setTab('vulns');
  };

  const handleViewScanResults = async (scanId) => {
    try {
      const [scanVulns, rec] = await Promise.all([
        fetchVulnerabilities({ scan_id: scanId }),
        fetchScanRecommendations(scanId),
      ]);
      setSelectedScanId(scanId);
      setVulns(scanVulns);
      setScanRecommendations(rec.recommendations || []);
      setTab('vulns');
    } catch (err) {
      alert('Failed to load scan results: ' + (err.response?.data?.detail || err.message));
    }
  };

  const handleTabChange = (nextTab) => {
    if (nextTab === 'vulns' && tab !== 'vulns') {
      setSelectedScanId(null);
      setScanRecommendations([]);
    }
    setTab(nextTab);
  };

  if (!isAuthenticated) return <LoginPage onLogin={handleLogin} />;

  if (loading) {
    return (
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        height: '100vh', background: C.bg, color: C.muted,
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{
            width: 44, height: 44,
            border: `3px solid ${C.border}`, borderTop: `3px solid ${C.accent}`,
            borderRadius: '50%', animation: 'spin .8s linear infinite',
            margin: '0 auto 16px',
          }} />
          <div style={{ fontSize: 16, fontWeight: 500 }}>Loading VAPT Dashboard...</div>
          <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: C.bg, flexDirection: isMobile ? 'column' : 'row' }}>
      {/* Sidebar */}
      <Sidebar activeTab={tab} onTabChange={handleTabChange} isMobile={isMobile} />

      {/* Main Content */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Top Header */}
        <TopHeader
          title={tab}
          username={getStoredUsername()}
          onLogout={handleLogout}
          isMobile={isMobile}
        />

        {/* Error Banner */}
        {error && (
          <div style={{
            margin: isMobile ? '10px 12px 0' : '16px 28px 0', padding: '10px 16px',
            background: '#EF44441A', border: '1px solid #EF444466',
            borderRadius: 8, color: C.critical, fontSize: 14,
          }}>
            {error}
          </div>
        )}

        {/* Page Content */}
        <main className="cyber-grid" style={{ flex: 1, padding: isMobile ? 12 : 28, overflow: 'auto' }}>

          {/* ─── Overview ───────────────────────────────────────────── */}
          {tab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              <StatsCards stats={stats} isMobile={isMobile} />
              <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '2fr 1fr', gap: 24, alignItems: 'stretch' }}>
                <TrendsChart trends={trends} />
                <SeverityChart severity={severity} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '2fr 1fr', gap: 24, alignItems: 'stretch' }}>
                <TopAssetsChart assets={topAssets} />
                <AssetTypeChart counts={assetCounts} />
              </div>
            </div>
          )}

          {/* ─── Assets & Scans ─────────────────────────────────────── */}
          {tab === 'assets' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              {/* Two-column: Scan Controls | Assets */}
              <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '340px 1fr', gap: 24, alignItems: 'start' }}>
                {/* Left: Scan Controls */}
                <ScanPanel
                  assets={assets}
                  onScan={handleScan}
                  onDiscover={handleDiscover}
                  discoveryResults={discoveryResults}
                  discoveryDomain={discoveryDomain}
                  discoveryTaskId={discoveryTaskId}
                  discoveryStatus={discoveryStatus}
                  discoveryStatusMessage={discoveryStatusMessage}
                  discoveryElapsedSeconds={discoveryElapsedSeconds}
                  discoveryLoading={discoveryLoading}
                  onAddDiscoveredAsset={handleAddDiscoveredAsset}
                />

                {/* Right: Add Asset + Assets Table */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
                  <AddAssetForm onAdd={handleAddAsset} />
                  <AssetList
                    assets={assets}
                    onScan={(id) => handleScan(id, 'quick')}
                    onViewVulns={handleViewVulns}
                    onReport={handleAssetReport}
                  />
                </div>
              </div>

              {/* Full width: Scan History */}
              <ScanHistory
                scans={scans}
                onCancel={handleCancelScan}
                onReport={handleScanReport}
                onViewResults={handleViewScanResults}
              />
            </div>
          )}

          {/* ─── Vulnerabilities ─────────────────────────────────────── */}
          {tab === 'vulns' && (
            <VulnTable
              vulnerabilities={vulns}
              assets={assets}
              selectedScanId={selectedScanId}
              recommendations={scanRecommendations}
            />
          )}

          {/* ─── Attack Surface ──────────────────────────────────────── */}
          {tab === 'map' && (
            <AttackSurfaceMap
              assets={assets}
              vulnerabilities={vulns}
              onNodeClick={handleMapNodeClick}
            />
          )}
        </main>
      </div>
    </div>
  );
}
