/**
 * Reusable chart and visualization components for VAPT Dashboard.
 * Uses Chart.js for statistics and D3.js for attack surface / network maps.
 */
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Doughnut, Bar, Line } from 'react-chartjs-2';
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
  CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler,
} from 'chart.js';
import * as d3 from 'd3';

ChartJS.register(
  ArcElement, Tooltip, Legend,
  CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler,
);

/* ─── Design Tokens ───────────────────────────────────────────────────────── */

export const C = {
  critical: '#DC2626',
  high:     '#EA580C',
  medium:   '#D97706',
  low:      '#2563EB',
  info:     '#64748B',
  bg:       '#F1F5F9',
  sidebar:  '#FFFFFF',
  card:     '#FFFFFF',
  hover:    '#F1F5F9',
  border:   '#E2E8F0',
  grid:     '#E2E8F0',
  text:     '#0F172A',
  muted:    '#64748B',
  accent:   '#4F46E5',
  accentHover: '#4338CA',
  success:  '#16A34A',
};

export const cardStyle = {
  background: C.card,
  borderRadius: 14,
  padding: 24,
  boxShadow: '0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06)',
  border: `1px solid ${C.border}`,
  transition: 'box-shadow .2s, transform .2s',
};

export const inputBase = {
  background: '#F8FAFC',
  color: C.text,
  border: `1px solid ${C.border}`,
  borderRadius: 8,
  padding: '10px 14px',
  fontSize: 14,
  outline: 'none',
  transition: 'border-color .2s, box-shadow .2s',
  boxSizing: 'border-box',
};

export const btnPrimary = {
  padding: '10px 16px',
  borderRadius: 8,
  border: 'none',
  fontWeight: 600,
  cursor: 'pointer',
  background: C.accent,
  color: '#fff',
  fontSize: 14,
  transition: 'all 0.2s ease',
  boxShadow: '0 1px 2px rgba(0,0,0,0.1)',
};

const sectionTitle = { fontSize: 18, fontWeight: 600, color: C.text, marginBottom: 16 };

const thStyle = {
  padding: '12px 16px',
  textAlign: 'left',
  color: C.muted,
  fontWeight: 600,
  fontSize: 11,
  textTransform: 'uppercase',
  letterSpacing: '.06em',
};

const tdStyle = { padding: '14px 16px', fontSize: 13, color: C.text };

function useDebouncedValue(value, delayMs = 180) {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}

/* ─── Helpers ─────────────────────────────────────────────────────────────── */

const sevBadge = (sev) => ({
  display: 'inline-block',
  padding: '4px 12px',
  borderRadius: 9999,
  fontSize: 11,
  fontWeight: 600,
  lineHeight: '18px',
  letterSpacing: '.02em',
  textTransform: 'capitalize',
  background: (C[sev] || C.info) + '20',
  color: C[sev] || C.info,
  border: `1px solid ${(C[sev] || C.info)}30`,
});

const riskLevel = (score) => {
  if (score >= 81) return { label: 'Critical', color: C.critical };
  if (score >= 51) return { label: 'High',     color: C.high };
  if (score >= 21) return { label: 'Medium',   color: C.medium };
  return                   { label: 'Low',      color: C.low };
};

const riskIndicator = (score) => {
  if (score >= 81) return '🔴';
  if (score >= 51) return '🟠';
  if (score >= 21) return '🟡';
  return '🔵';
};

const typePillColors = {
  domain:    { bg: '#EEF2FF', fg: '#4F46E5' },
  subdomain: { bg: '#F3E8FF', fg: '#7C3AED' },
  ip:        { bg: '#ECFEFF', fg: '#0891B2' },
  cidr:      { bg: '#F0FDFA', fg: '#0D9488' },
};

/* ─── Stats Cards (4 top + 2 bottom) ──────────────────────────────────────── */

export function StatsCards({ stats, isMobile = false }) {
  const topItems = [
    { label: 'Total Assets',              value: stats.total_assets ?? 0,                color: '#818CF8' },
    { label: 'Open Vulnerabilities',      value: stats.open_vulnerabilities ?? 0,        color: C.critical },
    { label: 'Critical Vulnerabilities',  value: stats.critical_vulns ?? 0,              color: '#DC2626' },
    { label: 'Active Scans',             value: stats.active_scans ?? 0,                color: '#22C55E' },
  ];

  const bottomItems = [
    { label: 'Open Ports',        value: stats.open_ports ?? 0,                          color: '#F59E0B' },
    { label: 'Average Risk Score', value: (stats.avg_risk_score ?? 0).toFixed(1),         color: '#A78BFA' },
  ];

  const MetricCard = ({ item }) => (
    <div
      style={{ ...cardStyle, display: 'flex', alignItems: 'center', gap: 16, padding: 24, cursor: 'default' }}
      onMouseEnter={e => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.1), 0 1px 3px rgba(0,0,0,0.08)'; }}
      onMouseLeave={e => { e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.06)'; }}
    >
      <div style={{
        width: 48, height: 48, borderRadius: 12,
        background: item.color + '12',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        border: `1px solid ${item.color}20`,
      }}>
        <div style={{
          width: 18, height: 18, borderRadius: '50%',
          background: item.color + '30',
          border: `2px solid ${item.color}`,
          boxShadow: 'none',
        }} />
      </div>
      <div>
        <div style={{ fontSize: 28, fontWeight: 700, color: item.color, lineHeight: 1 }}>{item.value}</div>
        <div style={{ color: C.muted, fontSize: 13, marginTop: 6, fontWeight: 500 }}>{item.label}</div>
      </div>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: isMobile ? 'repeat(2, 1fr)' : 'repeat(4, 1fr)', gap: 16 }}>
        {topItems.map(item => <MetricCard key={item.label} item={item} />)}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : 'repeat(2, 1fr)', gap: 16 }}>
        {bottomItems.map(item => <MetricCard key={item.label} item={item} />)}
      </div>
    </div>
  );
}

/* ─── Severity Doughnut ───────────────────────────────────────────────────── */

export function SeverityChart({ severity }) {
  const labels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const colors = [C.critical, C.high, C.medium, C.low, C.info];
  const values = labels.map(l => severity[l.toLowerCase()] ?? 0);

  const data = {
    labels,
    datasets: [{ data: values, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }],
  };
  const options = {
    responsive: true,
    plugins: {
      legend: { position: 'bottom', labels: { color: C.text, padding: 14, font: { size: 12 } } },
    },
    cutout: '65%',
  };

  return (
    <div style={{ ...cardStyle, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <h3 style={sectionTitle}>Severity Distribution</h3>
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ maxWidth: 260 }}>
          <Doughnut data={data} options={options} />
        </div>
      </div>
    </div>
  );
}

/* ─── Vulnerability Trends Line Chart ─────────────────────────────────────── */

export function TrendsChart({ trends }) {
  if (!trends || trends.length === 0) {
    return (
      <div style={{ ...cardStyle, height: '100%' }}>
        <h3 style={sectionTitle}>Vulnerability Trends</h3>
        <p style={{ color: C.muted }}>No trend data available yet.</p>
      </div>
    );
  }

  const dates = [...new Set(trends.map(t => t.date))].sort();
  const severities = ['critical', 'high', 'medium', 'low'];
  const colorMap = { critical: C.critical, high: C.high, medium: C.medium, low: C.low };

  const datasets = severities.map(sev => ({
    label: sev.charAt(0).toUpperCase() + sev.slice(1),
    data: dates.map(d => {
      const entry = trends.find(t => t.date === d && t.severity === sev);
      return entry ? entry.cnt : 0;
    }),
    borderColor: colorMap[sev],
    backgroundColor: colorMap[sev] + '18',
    fill: true,
    tension: 0.35,
    pointRadius: 3,
    borderWidth: 2.5,
    pointHoverRadius: 6,
  }));

  const data = { labels: dates, datasets };
  const options = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: 'index', intersect: false },
    scales: {
      x: { ticks: { color: C.muted, font: { size: 11 } }, grid: { color: '#E2E8F0' } },
      y: { ticks: { color: C.muted, font: { size: 11 } }, grid: { color: '#E2E8F0' }, beginAtZero: true },
    },
    plugins: { legend: { labels: { color: C.text, font: { size: 12 } } } },
  };

  return (
    <div style={{ ...cardStyle, height: '100%' }}>
      <h3 style={sectionTitle}>Vulnerability Trends (30 days)</h3>
      <div style={{ height: 260 }}>
        <Line data={data} options={options} />
      </div>
    </div>
  );
}

/* ─── Top Vulnerable Assets Bar Chart ─────────────────────────────────────── */

export function TopAssetsChart({ assets }) {
  if (!assets || assets.length === 0) {
    return (
      <div style={{ ...cardStyle, height: '100%' }}>
        <h3 style={sectionTitle}>Top Vulnerable Assets</h3>
        <p style={{ color: C.muted }}>No data yet.</p>
      </div>
    );
  }

  const data = {
    labels: assets.map(a => a.asset_name.length > 25 ? a.asset_name.slice(0, 22) + '...' : a.asset_name),
    datasets: [
      { label: 'Critical', data: assets.map(a => a.critical_count ?? 0), backgroundColor: C.critical },
      { label: 'High',     data: assets.map(a => a.high_count ?? 0),     backgroundColor: C.high },
      { label: 'Total',    data: assets.map(a => a.vuln_count ?? 0),     backgroundColor: C.accent + '66' },
    ],
  };
  const options = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: 'y',
    scales: {
      x: { stacked: false, ticks: { color: C.muted, font: { size: 11 } }, grid: { color: '#E2E8F0' } },
      y: { ticks: { color: C.text, font: { size: 11 } }, grid: { display: false } },
    },
    plugins: { legend: { labels: { color: C.text, font: { size: 12 } } } },
  };

  return (
    <div style={{ ...cardStyle, height: '100%' }}>
      <h3 style={sectionTitle}>Top Vulnerable Assets</h3>
      <div style={{ height: 260 }}>
        <Bar data={data} options={options} />
      </div>
    </div>
  );
}

/* ─── Asset Type Distribution ─────────────────────────────────────────────── */

export function AssetTypeChart({ counts }) {
  const labels = ['Domain', 'Subdomain', 'IP', 'CIDR'];
  const keys = ['domain', 'subdomain', 'ip', 'cidr'];
  const values = keys.map(k => counts[k] ?? 0);
  const colors = ['#818CF8', '#A78BFA', '#22D3EE', '#2DD4BF'];

  const data = {
    labels,
    datasets: [{ data: values, backgroundColor: colors, borderWidth: 0, hoverOffset: 6 }],
  };
  const options = {
    responsive: true,
    plugins: { legend: { position: 'bottom', labels: { color: C.text, font: { size: 12 } } } },
    cutout: '60%',
  };

  return (
    <div style={{ ...cardStyle, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <h3 style={sectionTitle}>Asset Types</h3>
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ maxWidth: 220 }}>
          <Doughnut data={data} options={options} />
        </div>
      </div>
    </div>
  );
}

/* ─── D3 Attack Surface Network Map ───────────────────────────────────────── */

export function AttackSurfaceMap({ assets, vulnerabilities, onNodeClick }) {
  const containerRef = useRef(null);
  const svgRef = useRef(null);
  const tooltipRef = useRef(null);

  useEffect(() => {
    if (!assets || assets.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = svgRef.current.clientWidth || 700;
    const height = 500;

    svg.attr('viewBox', `0 0 ${width} ${height}`);

    const tooltip = d3.select(tooltipRef.current);

    const nodes = assets.map(a => ({
      id: a.id,
      name: a.asset_name,
      type: a.asset_type,
      risk: a.risk_score ?? 0,
      vulns: (vulnerabilities || []).filter(v => v.asset_id === a.id).length,
    }));

    const links = [];

    const riskColor = (r) => {
      if (r >= 81) return C.critical;
      if (r >= 51) return C.high;
      if (r >= 21) return C.medium;
      return C.low;
    };

    const g = svg.append('g');
    const zoom = d3.zoom()
      .scaleExtent([0.3, 5])
      .on('zoom', (e) => g.attr('transform', e.transform));
    svg.call(zoom);

    const simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-250))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => 14 + Math.min(d.risk / 4, 20)));

    const link = g.append('g')
      .selectAll('line')
      .data(links)
      .enter().append('line')
      .attr('stroke', C.border)
      .attr('stroke-width', 1.5);

    const node = g.append('g')
      .selectAll('circle')
      .data(nodes)
      .enter().append('circle')
      .attr('r', d => 10 + Math.min(d.risk / 4, 18))
      .attr('fill', d => riskColor(d.risk) + 'CC')
      .attr('stroke', d => {
        if (d.risk >= 81) return '#EF4444';
        if (d.risk >= 51) return '#F97316';
        if (d.risk >= 21) return '#F59E0B';
        return '#3B82F6';
      })
      .attr('stroke-width', 2.5)
      .style('cursor', 'pointer')
      .style('filter', d => {
        if (d.risk >= 81) return 'drop-shadow(0 0 8px rgba(220,38,38,0.35))';
        if (d.risk >= 51) return 'drop-shadow(0 0 6px rgba(234,88,12,0.3))';
        if (d.risk >= 21) return 'drop-shadow(0 0 5px rgba(217,119,6,0.25))';
        return 'drop-shadow(0 0 4px rgba(37,99,235,0.2))';
      })
      .on('mouseover', (e, d) => {
        const rect = containerRef.current.getBoundingClientRect();
        tooltip
          .style('opacity', 1)
          .style('left', (e.clientX - rect.left + 14) + 'px')
          .style('top', (e.clientY - rect.top - 10) + 'px')
          .html(
            `<strong>${d.name}</strong><br/>` +
            `Type: ${d.type}<br/>` +
            `Risk: <span style="color:${riskColor(d.risk)};font-weight:700">${d.risk}</span><br/>` +
            `Vulns: ${d.vulns}`
          );
      })
      .on('mousemove', (e) => {
        const rect = containerRef.current.getBoundingClientRect();
        tooltip
          .style('left', (e.clientX - rect.left + 14) + 'px')
          .style('top', (e.clientY - rect.top - 10) + 'px');
      })
      .on('mouseout', () => tooltip.style('opacity', 0))
      .on('click', (e, d) => {
        e.stopPropagation();
        if (onNodeClick) onNodeClick(d);
      })
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    g.append('g')
      .selectAll('text')
      .data(nodes)
      .enter().append('text')
      .text(d => d.name.length > 22 ? d.name.slice(0, 19) + '...' : d.name)
      .attr('font-size', 11)
      .attr('font-family', 'Inter, system-ui, sans-serif')
      .attr('fill', C.muted)
      .attr('text-anchor', 'middle')
      .attr('dy', d => -(14 + Math.min(d.risk / 4, 18)));

    simulation.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      node.attr('cx', d => d.x).attr('cy', d => d.y);
      g.selectAll('text').attr('x', d => d.x).attr('y', d => d.y);
    });

    return () => simulation.stop();
  }, [assets, vulnerabilities, onNodeClick]);

  const legendItems = [
    { label: 'Low (0-20)', color: C.low },
    { label: 'Medium (21-50)', color: C.medium },
    { label: 'High (51-80)', color: C.high },
    { label: 'Critical (81+)', color: C.critical },
  ];

  return (
    <div ref={containerRef} style={{ ...cardStyle, padding: 24, position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, gap: 10, flexWrap: 'wrap' }}>
        <h3 style={{ ...sectionTitle, marginBottom: 0 }}>Attack Surface Map</h3>
        <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
          {legendItems.map(l => (
            <span key={l.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11, color: C.muted }}>
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: l.color, display: 'inline-block' }} />
              {l.label}
            </span>
          ))}
        </div>
      </div>
      {(!assets || assets.length === 0) ? (
        <p style={{ color: C.muted }}>Add assets to visualize your attack surface.</p>
      ) : (
        <>
          <svg ref={svgRef} style={{ width: '100%', height: 500, display: 'block' }} />
          <div ref={tooltipRef} style={{
            position: 'absolute', pointerEvents: 'none', opacity: 0,
            background: '#FFFFFF', border: `1px solid ${C.border}`, borderRadius: 10,
            padding: '10px 14px', fontSize: 12, color: C.text, lineHeight: 1.7,
            transition: 'opacity .15s', zIndex: 20, whiteSpace: 'nowrap',
            boxShadow: '0 4px 16px rgba(0,0,0,0.12)',
            backdropFilter: 'blur(8px)',
          }} />
          <p style={{ color: C.muted, fontSize: 11, marginTop: 8 }}>
            Scroll to zoom &middot; Drag canvas to pan &middot; Drag nodes to reposition &middot; Click node to view vulnerabilities
          </p>
        </>
      )}
    </div>
  );
}

/* ─── Vulnerability Table with Filters ────────────────────────────────────── */

export function VulnTable({ vulnerabilities, assets, selectedScanId, recommendations = [] }) {
  const [sevFilter, setSevFilter] = useState('all');
  const [assetFilter, setAssetFilter] = useState('all');
  const [searchInput, setSearchInput] = useState('');
  const debouncedSearch = useDebouncedValue(searchInput);

  const assetNameById = useMemo(() => {
    const m = new Map();
    for (const a of (assets || [])) {
      m.set(a.id, a.asset_name);
    }
    return m;
  }, [assets]);

  const filtered = useMemo(() => {
    const q = debouncedSearch.trim().toLowerCase();
    return (vulnerabilities || []).filter(v => {
      if (sevFilter !== 'all' && v.severity !== sevFilter) return false;
      if (assetFilter !== 'all' && String(v.asset_id) !== assetFilter) return false;
      if (!q) return true;
      return (
        (v.vulnerability_name || '').toLowerCase().includes(q) ||
        (v.cve_id || '').toLowerCase().includes(q) ||
        (v.description || '').toLowerCase().includes(q)
      );
    });
  }, [vulnerabilities, sevFilter, assetFilter, debouncedSearch]);

  const assetName = (assetId) => assetNameById.get(assetId) || `Asset #${assetId}`;

  return (
    <div style={{ ...cardStyle, overflowX: 'auto' }}>
      <h3 style={sectionTitle}>
        {selectedScanId ? `Scan Results #${selectedScanId}` : 'Vulnerabilities'}
      </h3>

      {selectedScanId && (
        <div style={{
          marginBottom: 16,
          padding: '10px 12px',
          border: `1px solid ${C.border}`,
          borderRadius: 8,
          color: C.muted,
          fontSize: 12,
          background: '#F8FAFC',
        }}>
          Showing vulnerabilities and recommendations for scan #{selectedScanId}.
        </div>
      )}

      {/* Filters */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
        <select
          value={sevFilter}
          onChange={e => setSevFilter(e.target.value)}
          style={{ ...inputBase, minWidth: 150 }}
        >
          <option value="all">All Severities</option>
          {['critical', 'high', 'medium', 'low', 'info'].map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>

        <select
          value={assetFilter}
          onChange={e => setAssetFilter(e.target.value)}
          style={{ ...inputBase, minWidth: 170 }}
        >
          <option value="all">All Assets</option>
          {(assets || []).map(a => (
            <option key={a.id} value={String(a.id)}>{a.asset_name}</option>
          ))}
        </select>

        <div style={{ flex: 1, minWidth: 220, position: 'relative' }}>
          <input
            value={searchInput}
            onChange={e => setSearchInput(e.target.value)}
            placeholder="Search vulnerabilities..."
            style={{ ...inputBase, width: '100%', paddingLeft: 36 }}
          />
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={C.muted} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
            style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }}>
            <circle cx="11" cy="11" r="8" /><path d="M21 21l-4.35-4.35" />
          </svg>
        </div>
      </div>

      {filtered.length === 0 ? (
        <p style={{ color: C.muted }}>No vulnerabilities found.</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: `2px solid ${C.border}` }}>
              {['Severity', 'Vulnerability Name', 'CVE', 'Description', 'Asset'].map(h => (
                <th key={h} style={thStyle}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(v => (
              <tr key={v.id} style={{ borderBottom: `1px solid ${C.border}`, transition: 'background .15s' }}
                onMouseEnter={e => e.currentTarget.style.background = C.hover}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <td style={tdStyle}><span style={sevBadge(v.severity)}>{v.severity}</span></td>
                <td style={{ ...tdStyle, fontWeight: 500, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {v.vulnerability_name}
                </td>
                <td style={{ ...tdStyle, color: C.muted, fontFamily: 'monospace', fontSize: 12 }}>{v.cve_id || '—'}</td>
                <td style={{
                  ...tdStyle, color: C.muted, maxWidth: 300, overflow: 'hidden',
                  textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {v.description || '—'}
                </td>
                <td style={{ ...tdStyle, fontSize: 12, whiteSpace: 'nowrap' }}>{assetName(v.asset_id)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {selectedScanId && (
        <div style={{ marginTop: 20 }}>
          <SecurityRecommendationsPanel recommendations={recommendations} />
        </div>
      )}
    </div>
  );
}

/* ─── Scan Controls Panel ─────────────────────────────────────────────────── */

export function ScanPanel({
  assets,
  onScan,
  onDiscover,
  discoveryResults = [],
  discoveryDomain = '',
  discoveryTaskId = '',
  discoveryStatus = 'idle',
  discoveryStatusMessage = '',
  discoveryElapsedSeconds = 0,
  discoveryLoading = false,
  onAddDiscoveredAsset,
}) {
  const [selectedAsset, setSelectedAsset] = useState('');
  const [scanType, setScanType] = useState('full');
  const [domain, setDomain] = useState('');
  const [added, setAdded] = useState({});
  const [showFoundSubdomains, setShowFoundSubdomains] = useState(false);
  const [subdomainSearchInput, setSubdomainSearchInput] = useState('');
  const debouncedSubdomainSearch = useDebouncedValue(subdomainSearchInput);

  useEffect(() => {
    if (discoveryResults.length > 0) {
      setShowFoundSubdomains(true);
    }
  }, [discoveryResults]);

  const filteredSubdomains = useMemo(() => {
    const q = debouncedSubdomainSearch.trim().toLowerCase();
    if (!q) return discoveryResults;
    return discoveryResults.filter((s) => s.toLowerCase().includes(q));
  }, [discoveryResults, debouncedSubdomainSearch]);

  const discoveryStatusColor = useMemo(() => {
    if (discoveryStatus === 'completed') return '#16A34A';
    if (discoveryStatus === 'failed') return '#DC2626';
    if (discoveryStatus === 'timeout') return '#D97706';
    if (discoveryStatus === 'running') return '#2563EB';
    if (discoveryStatus === 'pending' || discoveryStatus === 'queued') return '#7C3AED';
    return C.muted;
  }, [discoveryStatus]);

  const discoveryStatusLabel = useMemo(() => {
    if (discoveryStatus === 'queued') return 'Queued';
    if (discoveryStatus === 'pending') return 'Pending';
    if (discoveryStatus === 'running') return 'Running';
    if (discoveryStatus === 'completed') return 'Completed';
    if (discoveryStatus === 'failed') return 'Failed';
    if (discoveryStatus === 'timeout') return 'Still Running';
    return 'Idle';
  }, [discoveryStatus]);

  const scanLabels = { quick: 'Quick Scan', network: 'Network Scan', full: 'Full Scan' };

  return (
    <div style={{ ...cardStyle, display: 'flex', flexDirection: 'column', gap: 20 }}>
      <h3 style={{ ...sectionTitle, marginBottom: 0 }}>Scan Control Panel</h3>

      <div>
        <label style={{ color: C.muted, fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 6 }}>Target Asset</label>
        <select
          value={selectedAsset}
          onChange={e => setSelectedAsset(e.target.value)}
          style={{ ...inputBase, width: '100%' }}
        >
          <option value="">Select asset...</option>
          {(assets || []).map(a => (
            <option key={a.id} value={a.id}>{a.asset_name} ({a.asset_type})</option>
          ))}
        </select>
      </div>

      <div>
        <label style={{ color: C.muted, fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 6 }}>Scan Type</label>
        <select
          value={scanType}
          onChange={e => setScanType(e.target.value)}
          style={{ ...inputBase, width: '100%' }}
        >
          {Object.entries(scanLabels).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
      </div>

      <button
        style={{ ...btnPrimary, width: '100%', padding: '10px 0' }}
        disabled={!selectedAsset}
        onClick={() => { if (selectedAsset) onScan?.(Number(selectedAsset), scanType); }}
      >
        Start Scan
      </button>

      <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 20 }}>
        <label style={{ color: C.muted, fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 6 }}>Discover Subdomains</label>
        <input
          value={domain}
          onChange={e => setDomain(e.target.value)}
          placeholder="example.com"
          style={{ ...inputBase, width: '100%', marginBottom: 10 }}
        />
        <button
          style={{ ...btnPrimary, width: '100%', padding: '10px 0', background: '#7C3AED' }}
          disabled={!domain || discoveryLoading}
          onClick={() => {
            if (domain) {
              setAdded({});
              onDiscover?.(domain);
            }
          }}
        >
          {discoveryLoading ? 'Discovering...' : 'Discover'}
        </button>

        {discoveryStatus !== 'idle' && (
          <div style={{
            marginTop: 10,
            border: `1px solid ${C.border}`,
            borderLeft: `4px solid ${discoveryStatusColor}`,
            borderRadius: 8,
            background: '#F8FAFC',
            padding: '8px 10px',
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 700, color: discoveryStatusColor }}>
                Discovery Status: {discoveryStatusLabel}
              </span>
              {(discoveryStatus === 'pending' || discoveryStatus === 'running') && (
                <span style={{ fontSize: 11, color: C.muted }}>
                  Elapsed: {discoveryElapsedSeconds}s
                </span>
              )}
            </div>
            {discoveryStatusMessage && (
              <div style={{ fontSize: 12, color: C.muted }}>
                {discoveryStatusMessage}
              </div>
            )}
            {discoveryTaskId && (
              <div style={{ fontSize: 11, color: C.muted, fontFamily: 'monospace' }}>
                Task: {discoveryTaskId}
              </div>
            )}
          </div>
        )}

        {!discoveryLoading && discoveryResults.length > 0 && (
          <button
            style={{ ...btnPrimary, width: '100%', padding: '9px 0', marginTop: 8, background: '#0EA5E9' }}
            onClick={() => setShowFoundSubdomains((prev) => !prev)}
          >
            {showFoundSubdomains ? 'Hide Found Subdomains' : `View Found Subdomains (${discoveryResults.length})`}
          </button>
        )}

        {(discoveryLoading || (discoveryResults.length > 0 && showFoundSubdomains)) && (
          <div style={{ marginTop: 14, border: `1px solid ${C.border}`, borderRadius: 10, background: '#FFFFFF' }}>
            <div style={{
              padding: '10px 12px', borderBottom: `1px solid ${C.border}`,
              fontSize: 13, fontWeight: 600, color: C.text,
            }}>
              Subdomain Discovery Results{discoveryDomain ? ` (${discoveryDomain})` : ''}
            </div>

            {discoveryLoading && (
              <div style={{ padding: '10px 12px', fontSize: 12, color: C.muted }}>
                Running enumeration and DNS verification...
              </div>
            )}

            {!discoveryLoading && discoveryResults.length === 0 && (
              <div style={{ padding: '10px 12px', fontSize: 12, color: C.muted }}>
                No subdomains discovered.
              </div>
            )}

            {!discoveryLoading && discoveryResults.length > 0 && (
              <>
                <div style={{ padding: '10px 10px 0' }}>
                  <input
                    value={subdomainSearchInput}
                    onChange={e => setSubdomainSearchInput(e.target.value)}
                    placeholder="Search found subdomains..."
                    style={{ ...inputBase, width: '100%' }}
                  />
                  <div style={{ marginTop: 8, fontSize: 11, color: C.muted }}>
                    Showing {filteredSubdomains.length} of {discoveryResults.length}
                  </div>
                </div>
                <div style={{ maxHeight: 280, overflowY: 'auto', marginTop: 8 }}>
                {filteredSubdomains.map((subdomain) => (
                  <div key={subdomain} style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    gap: 8, padding: '8px 10px', borderBottom: `1px solid ${C.border}`,
                  }}>
                    <div style={{ fontSize: 12, color: C.text, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {subdomain}
                    </div>
                    <button
                      style={{ ...btnPrimary, padding: '4px 8px', fontSize: 11, background: '#0EA5E9' }}
                      disabled={!!added[subdomain]}
                      onClick={async () => {
                        try {
                          await onAddDiscoveredAsset?.(subdomain);
                          setAdded(prev => ({ ...prev, [subdomain]: true }));
                        } catch {
                          // Parent handler surfaces user-facing errors.
                        }
                      }}
                    >
                      {added[subdomain] ? 'Added' : 'Add Asset'}
                    </button>
                  </div>
                ))}
                </div>
                {filteredSubdomains.length === 0 && (
                  <div style={{ padding: '10px 12px', fontSize: 12, color: C.muted }}>
                    No subdomains match your search.
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Add Asset Form ──────────────────────────────────────────────────────── */

export function AddAssetForm({ onAdd }) {
  const [name, setName] = useState('');
  const [type, setType] = useState('domain');

  return (
    <div style={{ ...cardStyle, display: 'flex', gap: 12, alignItems: 'end', flexWrap: 'wrap' }}>
      <div style={{ flex: 1, minWidth: 200 }}>
        <label style={{ color: C.muted, fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 6 }}>Asset Name</label>
        <input
          value={name}
          onChange={e => setName(e.target.value)}
          placeholder="e.g. example.com or 192.168.1.0/24"
          style={{ ...inputBase, width: '100%' }}
        />
      </div>
      <div style={{ minWidth: 140 }}>
        <label style={{ color: C.muted, fontSize: 12, fontWeight: 500, display: 'block', marginBottom: 6 }}>Type</label>
        <select value={type} onChange={e => setType(e.target.value)} style={{ ...inputBase, width: '100%' }}>
          <option value="domain">Domain</option>
          <option value="subdomain">Subdomain</option>
          <option value="ip">IP Address</option>
          <option value="cidr">CIDR Range</option>
        </select>
      </div>
      <button
        style={{ ...btnPrimary, background: '#22C55E', padding: '10px 20px' }}
        disabled={!name}
        onClick={() => { if (name) { onAdd?.(name, type); setName(''); } }}
      >
        Add Asset
      </button>
    </div>
  );
}

/* ─── Scan History Table ──────────────────────────────────────────────────── */

function ScanProgressBar({ progress }) {
  const pct = Math.max(0, Math.min(progress ?? 0, 100));
  const barColor = pct >= 100 ? C.success : (pct >= 60 ? C.high : C.accent);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 140 }}>
      <div style={{
        width: 96,
        height: 8,
        borderRadius: 9999,
        background: '#E2E8F0',
        overflow: 'hidden',
      }}>
        <div style={{
          width: `${pct}%`,
          height: '100%',
          background: barColor,
          transition: 'width .35s ease',
        }} />
      </div>
      <span style={{ fontSize: 12, color: C.muted, minWidth: 30 }}>{pct}%</span>
    </div>
  );
}

function parseBackendDate(value) {
  if (!value) return null;
  if (value instanceof Date) return value;
  if (typeof value === 'string') {
    // Backend sends naive UTC timestamps; force UTC parsing when timezone is missing.
    const hasZone = /[zZ]|[+-]\d\d:\d\d$/.test(value);
    const normalized = value.includes('T') ? value : value.replace(' ', 'T');
    return new Date(hasZone ? normalized : `${normalized}Z`);
  }
  return new Date(value);
}

function formatDateTime(value) {
  const d = parseBackendDate(value);
  if (!d || Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString();
}

function formatDuration(startedAt, completedAt) {
  const start = parseBackendDate(startedAt);
  const end = parseBackendDate(completedAt) || new Date();
  if (!start || Number.isNaN(start.getTime()) || !end || Number.isNaN(end.getTime())) return '—';

  const totalSec = Math.max(0, Math.floor((end.getTime() - start.getTime()) / 1000));
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;

  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function ScanHistory({ scans, onCancel, onReport, onViewResults }) {
  const statusStyles = {
    pending:   { bg: '#94A3B81A', fg: '#94A3B8' },
    running:   { bg: '#EAB3081A', fg: '#EAB308' },
    completed: { bg: '#22C55E1A', fg: '#22C55E' },
    failed:    { bg: '#EF44441A', fg: '#EF4444' },
    cancelled: { bg: '#F971161A', fg: '#F97116' },
  };

  return (
    <div style={{ ...cardStyle, overflowX: 'auto' }}>
      <h3 style={sectionTitle}>Recent Scans</h3>
      {(!scans || scans.length === 0) ? (
        <p style={{ color: C.muted }}>No scans yet.</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: `2px solid ${C.border}` }}>
              {['Scan ID', 'Asset', 'Type', 'Status', 'Progress', 'Error', 'Started', 'Completed', 'Duration', 'Actions'].map(h => (
                <th key={h} style={thStyle}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {scans.map(s => {
              const ss = statusStyles[s.scan_status] || statusStyles.pending;
              const isRunning = s.scan_status === 'pending' || s.scan_status === 'running';
              const isCompleted = s.scan_status === 'completed';
              return (
                <tr key={s.id} style={{ borderBottom: `1px solid ${C.border}`, transition: 'background .15s' }}
                  onMouseEnter={e => e.currentTarget.style.background = C.hover}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={tdStyle}>#{s.id}</td>
                  <td style={{ ...tdStyle, fontWeight: 500 }}>{s.asset_name || '—'}</td>
                  <td style={{ ...tdStyle, textTransform: 'capitalize' }}>{s.scan_type}</td>
                  <td style={tdStyle}>
                    <span style={{
                      display: 'inline-block', padding: '3px 10px', borderRadius: 9999,
                      fontSize: 12, fontWeight: 600, background: ss.bg, color: ss.fg,
                    }}>
                      {s.scan_status}
                    </span>
                  </td>
                  <td style={tdStyle}><ScanProgressBar progress={s.scan_progress} /></td>
                  <td style={{ ...tdStyle, color: s.scan_status === 'failed' ? C.critical : C.muted, maxWidth: 280 }}>
                    {s.scan_status === 'failed' ? (s.scan_error || 'Scan failed without detailed error') : '—'}
                  </td>
                  <td style={{ ...tdStyle, color: C.muted, fontSize: 12 }}>
                    {formatDateTime(s.started_at)}
                  </td>
                  <td style={{ ...tdStyle, color: C.muted, fontSize: 12 }}>
                    {formatDateTime(s.completed_at)}
                  </td>
                  <td style={{ ...tdStyle, color: C.muted, fontSize: 12 }}>
                    {formatDuration(s.started_at, s.completed_at)}
                  </td>
                  <td style={tdStyle}>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      {isRunning && (
                        <button
                          style={{ ...btnPrimary, padding: '4px 10px', fontSize: 12, background: C.critical }}
                          onClick={() => onCancel?.(s.id)}
                        >
                          Cancel Scan
                        </button>
                      )}
                      {isCompleted && (
                        <button
                          style={{ ...btnPrimary, padding: '4px 10px', fontSize: 12, background: C.accent }}
                          onClick={() => onViewResults?.(s.id)}
                        >
                          View Results
                        </button>
                      )}
                      {isCompleted && (
                        <button
                          style={{ ...btnPrimary, padding: '4px 10px', fontSize: 12, background: '#0EA5E9' }}
                          onClick={() => onReport?.(s.id)}
                        >
                          Generate Report
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

/* ─── Asset List with Actions ─────────────────────────────────────────────── */

export function AssetList({ assets, onScan, onViewVulns, onReport }) {
  const [searchInput, setSearchInput] = useState('');
  const debouncedSearch = useDebouncedValue(searchInput);

  const filteredAssets = useMemo(() => {
    const q = debouncedSearch.trim().toLowerCase();
    if (!q) return assets || [];
    return (assets || []).filter((a) => {
      return (
        (a.asset_name || '').toLowerCase().includes(q) ||
        (a.asset_type || '').toLowerCase().includes(q) ||
        String(a.id || '').includes(q)
      );
    });
  }, [assets, debouncedSearch]);

  return (
    <div style={{ ...cardStyle, overflowX: 'auto' }}>
      <h3 style={sectionTitle}>Assets</h3>
      <div style={{ marginBottom: 14 }}>
        <input
          value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
          placeholder="Search assets by name, type, or ID..."
          style={{ ...inputBase, width: '100%', maxWidth: 440 }}
        />
      </div>
      {(!assets || assets.length === 0) ? (
        <p style={{ color: C.muted }}>No assets yet.</p>
      ) : filteredAssets.length === 0 ? (
        <p style={{ color: C.muted }}>No assets match your search.</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: `2px solid ${C.border}` }}>
              {['ID', 'Name', 'Type', 'Owner', 'Risk Score', 'Actions'].map(h => (
                <th key={h} style={thStyle}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredAssets.map(a => {
              const r = riskLevel(a.risk_score ?? 0);
              const tp = typePillColors[a.asset_type] || typePillColors.domain;
              return (
                <tr key={a.id} style={{ borderBottom: `1px solid ${C.border}`, transition: 'background .15s' }}
                  onMouseEnter={e => e.currentTarget.style.background = C.hover}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={tdStyle}>#{a.id}</td>
                  <td style={{ ...tdStyle, fontWeight: 500 }}>{a.asset_name}</td>
                  <td style={tdStyle}>
                    <span style={{
                      display: 'inline-block', padding: '3px 10px', borderRadius: 9999,
                      fontSize: 11, fontWeight: 600, background: tp.bg, color: tp.fg,
                    }}>
                      {a.asset_type}
                    </span>
                  </td>
                  <td style={{ ...tdStyle, color: C.muted }}>{a.owner || '—'}</td>
                  <td style={tdStyle}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 12 }}>{riskIndicator(a.risk_score ?? 0)}</span>
                      <span style={{ fontWeight: 700, color: r.color }}>{a.risk_score ?? 0}</span>
                      <span style={{
                        fontSize: 11, padding: '2px 8px', borderRadius: 9999,
                        background: r.color + '1A', color: r.color, fontWeight: 600,
                      }}>
                        {r.label}
                      </span>
                    </span>
                  </td>
                  <td style={tdStyle}>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <button
                        style={{ ...btnPrimary, padding: '4px 10px', fontSize: 11 }}
                        onClick={() => onScan?.(a.id)}
                      >
                        Start Scan
                      </button>
                      <button
                        style={{ ...btnPrimary, padding: '4px 10px', fontSize: 11, background: '#0EA5E9' }}
                        onClick={() => onViewVulns?.(a.id)}
                      >
                        View Vulnerabilities
                      </button>
                      <button
                        style={{ ...btnPrimary, padding: '4px 10px', fontSize: 11, background: '#22C55E' }}
                        onClick={() => onReport?.(a.id)}
                      >
                        Generate Report
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

export function SecurityRecommendationsPanel({ recommendations = [] }) {
  return (
    <div style={{
      border: `1px solid ${C.border}`,
      borderRadius: 10,
      padding: 16,
      background: '#FFFFFF',
    }}>
      <h4 style={{ margin: '0 0 10px', fontSize: 16, color: C.text }}>Security Recommendations</h4>
      {recommendations.length === 0 ? (
        <p style={{ margin: 0, color: C.muted, fontSize: 13 }}>
          Review system configuration and apply standard security best practices.
        </p>
      ) : (
        <ul style={{ margin: 0, paddingLeft: 18, color: C.text, lineHeight: 1.6, fontSize: 13 }}>
          {recommendations.map((rec, idx) => (
            <li key={`${idx}-${rec.slice(0, 24)}`}>{rec}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
