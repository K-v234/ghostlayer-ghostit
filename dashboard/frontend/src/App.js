import React, { useState, useEffect, useCallback, useRef } from "react";
import "./App.css";

const API = "http://127.0.0.1:8001/api";
const PIPELINE = "http://127.0.0.1:8000";

// ── Auth ──────────────────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [user, setUser] = useState("admin");
  const [pass, setPass] = useState("");
  const [err,  setErr]  = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    setLoading(true); setErr("");
    try {
      const r = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, password: pass }),
      });
      if (!r.ok) { setErr("Invalid credentials"); setLoading(false); return; }
      const d = await r.json();
      onLogin(d.token);
    } catch { setErr("Server unreachable"); setLoading(false); }
  };

  return (
    <div className="login-wrap">
      <div className="login-box">
        <div className="login-logo">
          <span className="ghost-icon">👻</span>
          <div>
            <div className="login-title">Ghost IT</div>
            <div className="login-sub">Autonomous Digital Immune System</div>
          </div>
        </div>
        <div className="login-fields">
          <label>Username</label>
          <input value={user} onChange={e => setUser(e.target.value)} autoFocus />
          <label>Password</label>
          <input type="password" value={pass} onChange={e => setPass(e.target.value)}
            onKeyDown={e => e.key === "Enter" && submit()} />
        </div>
        <button className="login-btn" onClick={submit} disabled={loading}>
          {loading ? "Authenticating..." : "Sign In"}
        </button>
        {err && <div className="login-err">{err}</div>}
        <div className="login-footer">Ghost Layer Technologies · Chennai · India</div>
      </div>
    </div>
  );
}

// ── Hooks ─────────────────────────────────────────────────────────────────────
function useAuthFetch(token, url, interval = 10000) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const fetch_ = useCallback(() => {
    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(setData).catch(e => setError(e));
  }, [token, url]);
  useEffect(() => { fetch_(); const id = setInterval(fetch_, interval); return () => clearInterval(id); }, [fetch_, interval]);
  return { data, error };
}

function usePipeline(path, interval = 15000) {
  const [data, setData] = useState(null);
  const fetch_ = useCallback(() => {
    fetch(`${PIPELINE}${path}`)
      .then(r => r.json()).then(setData).catch(() => {});
  }, [path]);
  useEffect(() => { fetch_(); const id = setInterval(fetch_, interval); return () => clearInterval(id); }, [fetch_, interval]);
  return data;
}

// ── Severity ──────────────────────────────────────────────────────────────────
const SEV_COLOR = { critical: "#ff3b3b", high: "#ff8c00", medium: "#ffd700", low: "#44cc44", info: "#888", warn: "#ffd700" };
function SevBadge({ s }) {
  return <span className="sev-badge" style={{ background: SEV_COLOR[s] || "#555" }}>{(s||"?").toUpperCase()}</span>;
}

// ── Threat Score ──────────────────────────────────────────────────────────────
function ThreatScore({ incidents, alerts }) {
  const critical = (incidents || []).filter(i => i.severity === "critical" && !i.closed).length;
  const high     = (incidents || []).filter(i => i.severity === "high" && !i.closed).length;
  const alertCt  = alerts || 0;
  let score = 0;
  if (critical > 0) score = 85 + Math.min(critical * 5, 15);
  else if (high > 0) score = 55 + Math.min(high * 5, 25);
  else if (alertCt > 0) score = 25 + Math.min(alertCt, 25);
  else score = 5;

  const color = score >= 75 ? "#ff3b3b" : score >= 40 ? "#ff8c00" : "#44cc44";
  const label = score >= 75 ? "HIGH RISK" : score >= 40 ? "ELEVATED" : "SECURE";

  return (
    <div className="threat-score-card">
      <div className="threat-label">Threat Level</div>
      <div className="threat-ring" style={{ borderColor: color }}>
        <div className="threat-number" style={{ color }}>{score}</div>
        <div className="threat-max">/100</div>
      </div>
      <div className="threat-status" style={{ color }}>{label}</div>
    </div>
  );
}

// ── Stats Cards ───────────────────────────────────────────────────────────────
function StatsCards({ pipelineStats, dashStats }) {
  const cards = [
    { label: "Total Events", value: pipelineStats?.total?.toLocaleString() ?? "—", icon: "📊", color: "#4af" },
    { label: "Open Incidents", value: dashStats?.open_incidents ?? "—", icon: "🔴", color: dashStats?.open_incidents > 0 ? "#ff8c00" : "#44cc44" },
    { label: "Critical", value: dashStats?.critical_incidents ?? "—", icon: "⚠️", color: dashStats?.critical_incidents > 0 ? "#ff3b3b" : "#44cc44" },
    { label: "Active Procs", value: pipelineStats?.unique_procs?.toLocaleString() ?? "—", icon: "⚙️", color: "#4af" },
    { label: "Unique PIDs", value: pipelineStats?.unique_pids?.toLocaleString() ?? "—", icon: "🔢", color: "#4af" },
    { label: "Last Event", value: pipelineStats?.last_seen?.slice(11, 19) ?? "—", icon: "🕐", color: "#888" },
  ];
  return (
    <div className="stats-grid">
      {cards.map(c => (
        <div key={c.label} className="stat-card">
          <div className="stat-icon">{c.icon}</div>
          <div className="stat-value" style={{ color: c.color }}>{c.value}</div>
          <div className="stat-label">{c.label}</div>
        </div>
      ))}
    </div>
  );
}

// ── Event Timeline Chart ──────────────────────────────────────────────────────
function EventChart() {
  const data = usePipeline("/timeline?minutes=60", 30000);
  const points = data?.timeline || [];
  if (points.length < 2) return <div className="panel"><h3>📈 Event Rate (last hour)</h3><p className="muted">Loading...</p></div>;

  const max = Math.max(...points.map(p => p.events));
  const W = 600, H = 120, PAD = 10;

  const pathD = points.map((p, i) => {
    const x = PAD + (i / (points.length - 1)) * (W - PAD * 2);
    const y = H - PAD - ((p.events / max) * (H - PAD * 2));
    return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(" ");

  const total = points.reduce((a, p) => a + p.events, 0);
  const avg = Math.round(total / points.length);

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>📈 Event Rate — Last Hour</h3>
        <span className="panel-meta">avg {avg.toLocaleString()}/min · {points.length} datapoints</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="chart-svg">
        <defs>
          <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#4af" stopOpacity="0.3"/>
            <stop offset="100%" stopColor="#4af" stopOpacity="0"/>
          </linearGradient>
        </defs>
        <path d={`${pathD} L ${(W-PAD).toFixed(1)} ${H} L ${PAD} ${H} Z`} fill="url(#grad)"/>
        <path d={pathD} fill="none" stroke="#4af" strokeWidth="1.5"/>
        {points.filter((_, i) => i % 10 === 0).map((p, i, arr) => {
          const idx = points.indexOf(p);
          const x = PAD + (idx / (points.length - 1)) * (W - PAD * 2);
          return <text key={i} x={x} y={H - 2} className="chart-label">{p.minute.slice(11, 16)}</text>;
        })}
      </svg>
    </div>
  );
}

// ── Alert Feed ────────────────────────────────────────────────────────────────
function AlertFeed({ token }) {
  const { data } = useAuthFetch(token, `${API}/alerts?limit=50`, 10000);
  const alerts = data?.alerts || [];
  const [selected, setSelected] = useState(null);

  if (selected) return (
    <div className="panel">
      <div className="panel-header">
        <h3>🔍 Alert Detail</h3>
        <button className="back-btn" onClick={() => setSelected(null)}>← Back</button>
      </div>
      <div className="alert-detail">
        <div className="detail-row"><span>Score</span><span className="detail-val" style={{color: "#ff3b3b"}}>{selected.score}</span></div>
        <div className="detail-row"><span>Process</span><span className="detail-val">{selected.comm === "canary" && selected.daddr && selected.daddr !== "local_process" ? selected.daddr : selected.comm}</span></div>
        <div className="detail-row"><span>Type</span><span className="detail-val">{selected.type}</span></div>
        <div className="detail-row"><span>Attacker</span><span className="detail-val" style={{color:"#ff3b3b"}}>{selected.daddr || "—"}</span></div>
        <div className="detail-row"><span>Port</span><span className="detail-val">{selected.dport || "—"}</span></div>
        <div className="detail-row"><span>File</span><span className="detail-val">{selected.file || "—"}</span></div>
        <div className="detail-row"><span>PII Flag</span><span className="detail-val">{selected.dpdp_pii_flag ? "⚠️ Yes" : "✅ No"}</span></div>
        <div className="detail-section">Detection Reasons</div>
        {(selected.reasons || []).map((r, i) => <div key={i} className="reason-tag">{r}</div>)}
      </div>
    </div>
  );

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>🚨 Live Alert Feed</h3>
        <span className="panel-meta">{alerts.length} alerts</span>
      </div>
      {alerts.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">✅</div>
          <div className="empty-text">System Clean</div>
          <div className="empty-sub">No alerts detected — all endpoints secure</div>
        </div>
      ) : (
        <div className="alert-list">
          {alerts.map(a => (
            <div key={a.id} className="alert-card" onClick={() => setSelected(a)}>
              <div className="alert-score" style={{color: a.score >= 80 ? "#ff3b3b" : "#ff8c00"}}>{a.score}</div>
              <div className="alert-info">
                <div className="alert-comm">
                  {a.comm === "canary" ? "🪤 Canary" : a.comm}
                  {a.daddr && a.daddr !== "local_process" && a.daddr !== "" &&
                    <span className="alert-pid"> · {a.daddr}</span>}
                </div>
                <div className="alert-reasons">{(a.reasons || []).slice(0,2).join(" · ")}</div>
              </div>
              <div className="alert-arrow">›</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Incident Timeline ─────────────────────────────────────────────────────────
function IncidentTimeline({ token }) {
  const { data } = useAuthFetch(token, `${API}/incidents?limit=30`, 15000);
  const [selected, setSelected] = useState(null);
  const incidents = data?.incidents || [];

  if (selected) return (
    <div className="panel">
      <div className="panel-header">
        <h3>🔍 Incident Detail</h3>
        <button className="back-btn" onClick={() => setSelected(null)}>← Back</button>
      </div>
      <div className="incident-detail">
        <div className="detail-row"><span>Incident ID</span><span className="detail-val mono">{selected.incident_id?.slice(0,8)}…</span></div>
        <div className="detail-row"><span>Severity</span><SevBadge s={selected.severity}/></div>
        <div className="detail-row"><span>Confidence</span><span className="detail-val">{Math.round((selected.confidence||0)*100)}%</span></div>
        <div className="detail-row"><span>Tactic</span><span className="detail-val">{selected.tactic_name || "—"}</span></div>
        <div className="detail-row"><span>Technique</span><span className="detail-val">{selected.technique_id} — {selected.technique_name}</span></div>
        <div className="detail-row"><span>Host</span><span className="detail-val">{selected.host || "—"}</span></div>
        <div className="detail-row"><span>Alerts</span><span className="detail-val">{selected.alert_count}</span></div>
        <div className="detail-row"><span>Sources</span><span className="detail-val">{(selected.sources||[]).join(", ")}</span></div>
        <div className="detail-row"><span>Window</span><span className="detail-val">{selected.window_type}</span></div>
        <div className="detail-row"><span>Status</span><span className="detail-val">{selected.closed ? "🔒 Closed" : "🔴 Open"}</span></div>
        <div className="detail-section">Summary</div>
        <div className="incident-summary-detail">{selected.summary}</div>
        <div className="detail-section">Timeline</div>
        <div className="detail-row"><span>Created</span><span className="detail-val">{selected.created_at?.slice(0,19)}</span></div>
        <div className="detail-row"><span>Updated</span><span className="detail-val">{selected.updated_at?.slice(0,19)}</span></div>
      </div>
    </div>
  );

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>📋 Incident Timeline</h3>
        <span className="panel-meta">{incidents.filter(i=>!i.closed).length} open · {incidents.length} total</span>
      </div>
      {incidents.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📋</div>
          <div className="empty-text">No Incidents</div>
          <div className="empty-sub">No correlated incidents detected</div>
        </div>
      ) : (
        <div className="incident-list">
          {incidents.map(i => (
            <div key={i.incident_id} className={`incident-card ${i.closed ? "closed" : ""}`} onClick={() => setSelected(i)}>
              <div className="incident-left">
                <SevBadge s={i.severity}/>
                <div className="incident-conf">{Math.round((i.confidence||0)*100)}%</div>
              </div>
              <div className="incident-mid">
                <div className="incident-tactic">{i.tactic_name || "Unknown Tactic"}</div>
                <div className="incident-technique">{i.technique_id} · {i.alert_count} alerts · {(i.sources||[]).join(", ")}</div>
                <div className="incident-time">{i.updated_at?.slice(0,19)}</div>
              </div>
              <div className="incident-right">
                {i.closed ? <span className="badge-closed">CLOSED</span> : <span className="badge-open">OPEN</span>}
                <span className="arrow">›</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Endpoint Grid ─────────────────────────────────────────────────────────────
function EndpointGrid({ token }) {
  const { data } = useAuthFetch(token, `${API}/endpoints`, 20000);
  const [search, setSearch] = useState("");
  const endpoints = (data?.endpoints || []).filter(e =>
    !search || e.comm?.toLowerCase().includes(search.toLowerCase())
  );

  const getRisk = (e) => {
    if (e.alerts > 0) return "high";
    if ((e.max_score || 0) >= 60) return "medium";
    return "low";
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>🖥️ Active Endpoints</h3>
        <input className="search-input" placeholder="Filter process..." value={search}
          onChange={e => setSearch(e.target.value)} />
      </div>
      <table className="endpoint-table">
        <thead>
          <tr>
            <th>Risk</th><th>Process</th><th>PID</th>
            <th>Events</th><th>Alerts</th><th>Max Score</th><th>Last Seen</th>
          </tr>
        </thead>
        <tbody>
          {endpoints.length === 0 && (
            <tr><td colSpan={7} className="muted center">No active processes</td></tr>
          )}
          {endpoints.slice(0, 50).map((e, i) => {
            const risk = getRisk(e);
            const lastSeen = e.last_seen ? new Date(e.last_seen).toLocaleTimeString() : "—";
            return (
              <tr key={i} className={`ep-row risk-${risk}`}>
                <td><span className={`risk-dot risk-${risk}`}/></td>
                <td className="ep-comm">{e.comm}</td>
                <td className="ep-pid">{e.pid || "—"}</td>
                <td>{(e.event_count||0).toLocaleString()}</td>
                <td style={{color: e.alerts > 0 ? "#ff3b3b" : "#888"}}>{e.alerts || 0}</td>
                <td style={{color: (e.max_score||0) >= 80 ? "#ff3b3b" : (e.max_score||0) >= 50 ? "#ff8c00" : "#888"}}>
                  {e.max_score || 0}
                </td>
                <td className="ep-time">{lastSeen}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── MITRE ATT&CK ─────────────────────────────────────────────────────────────
function MitreMap({ token }) {
  const { data } = useAuthFetch(token, `${API}/incidents?limit=200`, 30000);
  const incidents = data?.incidents || [];

  const TACTICS = [
    "Reconnaissance","Resource Development","Initial Access","Execution",
    "Persistence","Privilege Escalation","Defense Evasion","Credential Access",
    "Discovery","Lateral Movement","Collection","Command and Control",
    "Exfiltration","Impact"
  ];

  const tacticMap = {};
  incidents.forEach(i => {
    if (!i.tactic_name) return;
    if (!tacticMap[i.tactic_name]) tacticMap[i.tactic_name] = {count:0, critical:0, high:0, techniques: new Set()};
    tacticMap[i.tactic_name].count++;
    if (i.severity === "critical") tacticMap[i.tactic_name].critical++;
    if (i.severity === "high") tacticMap[i.tactic_name].high++;
    if (i.technique_id) tacticMap[i.tactic_name].techniques.add(i.technique_id);
  });

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>🎯 MITRE ATT&CK Matrix</h3>
        <span className="panel-meta">{Object.keys(tacticMap).length} tactics detected</span>
      </div>
      <div className="mitre-matrix">
        {TACTICS.map(tactic => {
          const d = tacticMap[tactic];
          const active = !!d;
          const bg = !active ? "#0d1117" : d.critical > 0 ? "#3a0a0a" : d.high > 0 ? "#2a1a00" : "#0a2a0a";
          const border = !active ? "#1e3a5f22" : d.critical > 0 ? "#ff3b3b" : d.high > 0 ? "#ff8c00" : "#44cc44";
          return (
            <div key={tactic} className="mitre-cell" style={{background: bg, borderColor: border}}>
              <div className="mitre-tactic">{tactic}</div>
              {active ? (
                <>
                  <div className="mitre-count">{d.count} incidents</div>
                  {d.techniques.size > 0 && <div className="mitre-tech">{d.techniques.size} techniques</div>}
                  {d.critical > 0 && <div className="mitre-crit">{d.critical} CRITICAL</div>}
                </>
              ) : (
                <div className="mitre-clean">Clean</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── DPDP Compliance ───────────────────────────────────────────────────────────
function Compliance({ token }) {
  const [customerId, setCustomerId] = useState("");
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);

  const generateReport = async () => {
    if (!customerId) return;
    setLoading(true);
    try {
      const r = await fetch(`${API}/compliance/audit/${customerId}`,
        { headers: { Authorization: `Bearer ${token}` } });
      setReport(await r.json());
    } catch {}
    setLoading(false);
  };

  return (
    <div className="panel">
      <div className="panel-header"><h3>🛡️ DPDP Compliance</h3></div>
      <div className="compliance-section">
        <div className="compliance-row">
          <input className="search-input" placeholder="Customer ID..."
            value={customerId} onChange={e => setCustomerId(e.target.value)} />
          <button className="action-btn" onClick={generateReport} disabled={loading}>
            {loading ? "Generating..." : "Generate Audit Report"}
          </button>
        </div>
        {report && (
          <div className="compliance-report">
            <div className={`compliance-status ${report.overall_status === "COMPLIANT" ? "ok" : "warn"}`}>
              {report.overall_status === "COMPLIANT" ? "✅ COMPLIANT" : "⚠️ REVIEW REQUIRED"}
            </div>
            <div className="detail-row"><span>Report ID</span><span className="detail-val mono">{report.report_id}</span></div>
            <div className="detail-row"><span>Data Residency</span>
              <span className="detail-val" style={{color: report.data_residency?.status === "COMPLIANT" ? "#44cc44" : "#ff3b3b"}}>
                {report.data_residency?.status}
              </span>
            </div>
            <div className="detail-row"><span>Foreign Transfers</span>
              <span className="detail-val">{report.data_residency?.foreign_transfers}</span>
            </div>
            <div className="detail-row"><span>Consent Records</span>
              <span className="detail-val">{report.consent_management?.total_records}</span>
            </div>
            <div className="detail-row"><span>Breach Notifications</span>
              <span className="detail-val">{report.breach_notifications?.total_breaches}</span>
            </div>
            <div className="detail-row"><span>Erasure Requests</span>
              <span className="detail-val">{report.right_to_erasure?.total_requests}</span>
            </div>
            <div className="detail-row"><span>Data Minimisation</span>
              <span className="detail-val" style={{color:"#44cc44"}}>{report.data_minimisation?.status}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Causal Intelligence ──────────────────────────────────────────────────────
function CausalIntelligence({ token }) {
  const [chains, setChains] = React.useState([]);
  const [analysis, setAnalysis] = React.useState({});
  const [loading, setLoading] = React.useState({});

  React.useEffect(() => {
    fetch("http://127.0.0.1:8000/chains")
      .then(r => r.json())
      .then(d => setChains(d.chains || []))
      .catch(() => {});
  }, []);

  const analyze = async (chain) => {
    setLoading(prev => ({...prev, [chain.chain_id]: true}));
    try {
      const prompt = `You are a cybersecurity analyst. Explain this attack chain in simple, clear language that a non-technical business owner (CTO/CEO) can understand. Be direct and actionable.

Attack Chain Data:
- Chain ID: ${chain.chain_id}
- Severity: ${chain.severity.toUpperCase()}
- Duration: ${chain.duration_s} seconds
- Events detected: ${chain.event_count}
- Attack stage: ${chain.current_stage}
- MITRE tactics: ${chain.tactics.join(", ")}
- MITRE techniques: ${chain.techniques.join(", ")}
- Escalating: ${chain.escalating ? "YES - GROWING THREAT" : "No"}

Explain in 3 short paragraphs:
1. What happened (plain English, no jargon)
2. What the attacker was trying to do
3. What action to take right now

Keep it under 150 words total. Be direct.`;

      const response = await fetch(`${API}/causal/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ chain })
      });
      const data = await response.json();
      const text = data.analysis || "Analysis unavailable";
      setAnalysis(prev => ({...prev, [chain.chain_id]: text}));
    } catch (e) {
      setAnalysis(prev => ({...prev, [chain.chain_id]: "Analysis failed — check API connection"}));
    }
    setLoading(prev => ({...prev, [chain.chain_id]: false}));
  };

  const SEV_COLOR = {critical:"#ff3b3b", high:"#ff8c00", medium:"#ffd700", low:"#44cc44"};

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>🧠 Causal Intelligence — Attack Chain Analysis</h3>
        <span className="panel-meta">{chains.length} active chain(s)</span>
      </div>
      {chains.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">🧠</div>
          <div className="empty-text">No Active Attack Chains</div>
          <div className="empty-sub">System is clean — no ongoing attack sequences detected</div>
        </div>
      ) : chains.map(chain => (
        <div key={chain.chain_id} style={{
          background:"#070b14", border:`1px solid ${SEV_COLOR[chain.severity]}44`,
          borderLeft:`3px solid ${SEV_COLOR[chain.severity]}`,
          borderRadius:"8px", padding:"16px", marginBottom:"12px"
        }}>
          <div style={{display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:"12px"}}>
            <div>
              <span style={{color:SEV_COLOR[chain.severity], fontWeight:"700", marginRight:"10px"}}>
                {chain.severity.toUpperCase()}
              </span>
              <span style={{color:"#c8d4e8", fontSize:"0.85rem"}}>{chain.current_stage}</span>
              <span style={{color:"#555", fontSize:"0.72rem", marginLeft:"10px"}}>
                #{chain.chain_id.slice(0,8)} · {chain.event_count} events · {chain.duration_s}s
              </span>
            </div>
            <div style={{display:"flex", gap:"8px", alignItems:"center"}}>
              {chain.escalating && <span style={{color:"#ff3b3b", fontSize:"0.7rem", fontWeight:"700"}}>⚠ ESCALATING</span>}
              <span style={{fontSize:"0.7rem", color:"#555"}}>{chain.tactics.join(" → ")}</span>
            </div>
          </div>
          <div style={{display:"flex", gap:"8px", marginBottom:"12px", flexWrap:"wrap"}}>
            {chain.techniques.map(t => (
              <span key={t} style={{background:"#1e3a5f33", border:"1px solid #1e3a5f", color:"#4af",
                padding:"2px 8px", borderRadius:"4px", fontSize:"0.68rem"}}>{t}</span>
            ))}
          </div>
          {!analysis[chain.chain_id] ? (
            <button onClick={() => analyze(chain)} disabled={loading[chain.chain_id]}
              style={{background:"#1e3a5f", color:"#4af", border:"1px solid #4af33",
                borderRadius:"4px", padding:"8px 16px", cursor:"pointer", fontSize:"0.75rem",
                opacity: loading[chain.chain_id] ? 0.6 : 1}}>
              {loading[chain.chain_id] ? "🧠 Analyzing..." : "🧠 Explain This Attack"}
            </button>
          ) : (
            <div style={{background:"#0d1421", border:"1px solid #1e3a5f", borderRadius:"6px",
              padding:"14px", fontSize:"0.8rem", color:"#c8d4e8", lineHeight:"1.7",
              whiteSpace:"pre-wrap"}}>
              {analysis[chain.chain_id]}
              <div style={{marginTop:"10px", display:"flex", gap:"8px"}}>
                <button onClick={() => analyze(chain)}
                  style={{background:"transparent", color:"#555", border:"1px solid #1e3a5f",
                    borderRadius:"4px", padding:"4px 10px", cursor:"pointer", fontSize:"0.65rem"}}>
                  Re-analyze
                </button>
                <button onClick={() => setAnalysis(prev => ({...prev, [chain.chain_id]: null}))}
                  style={{background:"transparent", color:"#555", border:"1px solid #1e3a5f",
                    borderRadius:"4px", padding:"4px 10px", cursor:"pointer", fontSize:"0.65rem"}}>
                  Clear
                </button>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
const TABS = [
  { id: "overview", label: "Overview", icon: "🏠" },
  { id: "alerts",   label: "Alerts",   icon: "🚨" },
  { id: "incidents",label: "Incidents",icon: "📋" },
  { id: "endpoints",label: "Endpoints",icon: "🖥️" },
  { id: "mitre",    label: "MITRE",    icon: "🎯" },
  { id: "compliance",label: "DPDP",   icon: "🛡️" },
  { id: "causal",    label: "Causal AI", icon: "🧠" },
];

export default function App() {
  const [token, setToken] = useState(localStorage.getItem("ghost_token") || "");
  const [tab, setTab] = useState("overview");
  const pipelineStats = usePipeline("/stats", 15000);
  const { data: dashStats } = useAuthFetch(token, `${API}/stats`, 15000);
  const { data: incidentData } = useAuthFetch(token, `${API}/incidents?limit=100`, 20000);

  const handleLogin = t => { setToken(t); localStorage.setItem("ghost_token", t); };
  const handleLogout = () => {
    fetch(`${API}/auth/logout`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
    setToken(""); localStorage.removeItem("ghost_token");
  };

  if (!token) return <Login onLogin={handleLogin} />;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <span className="ghost-icon-sm">👻</span>
          <div className="sidebar-brand">
            <div className="brand-name">Ghost IT</div>
            <div className="brand-sub">v1.0 · Chennai</div>
          </div>
        </div>
        <ThreatScore
          incidents={incidentData?.incidents}
          alerts={dashStats?.open_incidents}
        />
        <nav className="sidebar-nav">
          {TABS.map(t => (
            <button key={t.id} className={`nav-btn ${tab === t.id ? "active" : ""}`}
                    onClick={() => setTab(t.id)}>
              <span className="nav-icon">{t.icon}</span>
              <span className="nav-label">{t.label}</span>
            </button>
          ))}
        </nav>
        <button className="logout-btn" onClick={handleLogout}>⎋ Sign Out</button>
      </aside>
      <main className="main-content">
        <div className="content-header">
          <div className="content-title">{TABS.find(t=>t.id===tab)?.icon} {TABS.find(t=>t.id===tab)?.label}</div>
          <div className="header-stats">
            <span className="hs">Events: <b>{pipelineStats?.total?.toLocaleString() ?? "—"}</b></span>
            <span className="hs">Open: <b style={{color: dashStats?.open_incidents > 0 ? "#ff8c00" : "#44cc44"}}>{dashStats?.open_incidents ?? "—"}</b></span>
            <span className="hs">Last: <b>{pipelineStats?.last_seen?.slice(11,19) ?? "—"}</b></span>
            <span className="status-dot"/>
          </div>
        </div>
        <div className="content-body">
          {tab === "overview" && (
            <>
              <StatsCards pipelineStats={pipelineStats} dashStats={dashStats}/>
              <EventChart/>
            </>
          )}
          {tab === "alerts"    && <AlertFeed token={token}/>}
          {tab === "incidents" && <IncidentTimeline token={token}/>}
          {tab === "endpoints" && <EndpointGrid token={token}/>}
          {tab === "mitre"     && <MitreMap token={token}/>}
          {tab === "compliance"&& <Compliance token={token}/>}
          {tab === "causal"     && <CausalIntelligence token={token}/>}
        </div>
      </main>
    </div>
  );
}
