import React, { useState, useEffect, useCallback, useRef } from "react";
import "./App.css";

const API      = (process.env.REACT_APP_DASHBOARD_API_URL || "http://localhost:8001") + "/api";
const PIPELINE = process.env.REACT_APP_API_URL || "http://localhost:8000";

function Login({ onLogin }) {
  const [user, setUser] = useState("admin");
  const [pass, setPass] = useState("");
  const [err,  setErr]  = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true); setErr("");
    try {
      const r = await fetch(`${API}/auth/login`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, password: pass }),
      });
      if (!r.ok) { setErr("Invalid credentials"); setBusy(false); return; }
      onLogin((await r.json()).token);
    } catch { setErr("Server unreachable"); setBusy(false); }
  };
  return (
    <div className="login-wrap">
      <div className="login-box">
        <div className="login-logo">
          <span className="ghost-icon">👻</span>
          <div><div className="login-title">Ghost IT</div><div className="login-sub">Autonomous Digital Immune System</div></div>
        </div>
        <div className="login-fields">
          <label>Username</label>
          <input value={user} onChange={e => setUser(e.target.value)} autoFocus />
          <label>Password</label>
          <input type="password" value={pass} onChange={e => setPass(e.target.value)} onKeyDown={e => e.key === "Enter" && submit()} />
        </div>
        <button className="login-btn" onClick={submit} disabled={busy}>{busy ? "Authenticating..." : "Sign In"}</button>
        {err && <div className="login-err">{err}</div>}
        <div className="login-footer">Ghost Layer Technologies · Chennai · India</div>
      </div>
    </div>
  );
}

function ToastContainer({ toasts, onDismiss }) {
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast toast-${t.level}`} onClick={() => onDismiss(t.id)}>
          <div className="toast-icon">{t.level === "critical" ? "🔴" : t.level === "high" ? "🟠" : "🟡"}</div>
          <div className="toast-body">
            <div className="toast-title">{t.title}</div>
            <div className="toast-msg">{t.msg}</div>
          </div>
          <div className="toast-close">×</div>
        </div>
      ))}
    </div>
  );
}

function useSSEAlerts(token, onAlert) {
  const [status, setStatus] = useState("connecting");
  const esRef    = useRef(null);
  const lastIdRef = useRef(parseInt(sessionStorage.getItem("ghostit_last_alert_id") || "0", 10));

  useEffect(() => {
    if (!token) return;
    const connect = () => {
      if (esRef.current) esRef.current.close();
      const es = new EventSource(`${API}/stream/alerts?token=${token}&lastEventId=${lastIdRef.current}`);
      esRef.current = es;
      es.onopen = () => setStatus("live");
      const handle = (e) => {
        try {
          const alert = JSON.parse(e.data);
          if (e.lastEventId) { lastIdRef.current = parseInt(e.lastEventId, 10); sessionStorage.setItem("ghostit_last_alert_id", lastIdRef.current); }
          onAlert(alert);
        } catch {}
      };
      es.addEventListener("alert",    handle);
      es.addEventListener("critical", handle);
      es.addEventListener("high",     handle);
      es.addEventListener("sync",     () => setStatus("live"));
      es.addEventListener("auth_error", () => { es.close(); setStatus("error"); });
      es.onerror = () => { setStatus("reconnecting"); setTimeout(() => { if (esRef.current === es) connect(); }, 3000); };
    };
    connect();
    return () => { if (esRef.current) esRef.current.close(); };
  }, [token]); // eslint-disable-line

  return status;
}

function useAuthFetch(token, url, interval = 10000) {
  const [data, setData]   = useState(null);
  const [error, setError] = useState(null);
  const fetch_ = useCallback(() => {
    if (!token) return;
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
    fetch(`${PIPELINE}${path}`).then(r => r.json()).then(setData).catch(() => {});
  }, [path]);
  useEffect(() => { fetch_(); const id = setInterval(fetch_, interval); return () => clearInterval(id); }, [fetch_, interval]);
  return data;
}

const SEV_COLOR = { critical: "#ff3b3b", high: "#ff8c00", medium: "#ffd700", low: "#44cc44", info: "#888", warn: "#ffd700" };
function SevBadge({ s }) {
  return <span className="sev-badge" style={{ background: SEV_COLOR[s] || "#555" }}>{(s || "?").toUpperCase()}</span>;
}

function ThreatScore({ incidents, openCount }) {
  const critical = (incidents || []).filter(i => i.severity === "critical" && !i.closed).length;
  const high     = (incidents || []).filter(i => i.severity === "high"     && !i.closed).length;
  let score = 5;
  if (critical > 0) score = 85 + Math.min(critical * 5, 15);
  else if (high > 0) score = 55 + Math.min(high * 5, 25);
  else if (openCount > 0) score = 25 + Math.min(openCount, 25);
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
function ThreatGraph({ pipelineStats, dashStats }) {
  const hasAlert = (dashStats?.open_incidents || 0) > 0;
  const nodes = [
    { x: 35, y: 30, r: 4, flag: false },
    { x: 180, y: 25, r: 4, flag: false },
    { x: 28, y: 115, r: 5, flag: hasAlert },
    { x: 175, y: 120, r: 4, flag: false },
    { x: 110, y: 15, r: 4, flag: false },
  ];
  return (
    <div className="const-hero">
      <svg width="220" height="150" viewBox="0 0 220 150" className="const-graph">
        {nodes.map((n, i) => <line key={i} x1="110" y1="75" x2={n.x} y2={n.y} stroke="#20243a" strokeWidth="1" />)}
        <circle cx="110" cy="75" r="9" fill="#a8b4e8" />
        {nodes.map((n, i) => <circle key={i} cx={n.x} cy={n.y} r={n.r} fill={n.flag ? "#e0995f" : "#5a6180"} />)}
      </svg>
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
          <span style={{ color: "#e4e6f0", fontSize: 28, fontWeight: 500, fontFamily: "monospace" }}>
            {dashStats?.open_incidents > 0 ? "!" : "5"}
          </span>
          <span style={{ color: "#5a6180", fontSize: 10 }}>threat level<br/>{hasAlert ? "review" : "secure"}</span>
        </div>
      </div>
    </div>
  );
}

function StatsCards({ pipelineStats, dashStats }) {
  const cards = [
    { label: "Total Events",   value: (pipelineStats?.total || pipelineStats?.hot_buffer)?.toLocaleString() ?? "—",        icon: "📊", color: "#4af" },
    { label: "Open Incidents", value: dashStats?.open_incidents ?? "—",                     icon: "🔴", color: dashStats?.open_incidents > 0 ? "#ff8c00" : "#44cc44" },
    { label: "Critical",       value: dashStats?.critical_incidents ?? "—",                 icon: "⚠️", color: dashStats?.critical_incidents > 0 ? "#ff3b3b" : "#44cc44" },
    { label: "Active Procs",   value: pipelineStats?.unique_procs?.toLocaleString() ?? "—", icon: "⚙️", color: "#4af" },
    { label: "Unique PIDs",    value: pipelineStats?.unique_pids?.toLocaleString() ?? "—",  icon: "🔢", color: "#4af" },
    { label: "Last Event",     value: pipelineStats?.last_seen ? pipelineStats.last_seen.slice(11,19) : "—",       icon: "🕐", color: "#888" },
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

function EventChart() {
  const data   = usePipeline("/timeline?minutes=120", 10000);
  const points = data?.timeline || [];
  if (points.length < 2) return (
    <div className="panel">
      <div className="panel-header"><h3>📈 Event Rate — Last Hour</h3></div>
      <p className="muted" style={{ padding: "20px 0" }}>Collecting data...</p>
    </div>
  );
  const max  = Math.max(...points.map(p => p.events), 1);
  const W = 600, H = 120, PAD = 10;
  const pathD = points.map((p, i) => {
    const x = PAD + (i / (points.length - 1)) * (W - PAD * 2);
    const y = H - PAD - ((p.events / max) * (H - PAD * 2));
    return `${i === 0 ? "M" : "L"} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(" ");
  const avg    = Math.round(points.reduce((a, p) => a + p.events, 0) / points.length);
  const spikes = points.filter(p => p.alerts > 0);
  return (
    <div className="panel">
      <div className="panel-header">
        <h3>📈 Event Rate — Last Hour</h3>
        <span className="panel-meta">
          avg {avg.toLocaleString()}/min · {points.length} pts
          {spikes.length > 0 && <span style={{ color: "#ff3b3b", marginLeft: "10px" }}>⚠ {spikes.length} alert spike{spikes.length > 1 ? "s" : ""}</span>}
        </span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="chart-svg">
        <defs>
          <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#4af" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#4af" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path d={`${pathD} L ${(W - PAD).toFixed(1)} ${H} L ${PAD} ${H} Z`} fill="url(#grad)" />
        <path d={pathD} fill="none" stroke="#4af" strokeWidth="1.5" />
        {spikes.map((p, i) => {
          const idx = points.indexOf(p);
          const x = PAD + (idx / (points.length - 1)) * (W - PAD * 2);
          const y = H - PAD - ((p.events / max) * (H - PAD * 2));
          return <circle key={i} cx={x} cy={y} r="4" fill="#ff3b3b" />;
        })}
        {points.filter((_, i) => i % 10 === 0).map((p, i) => {
          const idx = points.indexOf(p);
          const x = PAD + (idx / (points.length - 1)) * (W - PAD * 2);
          return <text key={i} x={x} y={H - 2} className="chart-label">{p.minute.slice(11, 16)}</text>;
        })}
      </svg>
    </div>
  );
}

function LiveTicker({ alerts }) {
  if (!alerts.length) return null;
  return (
    <div className="live-ticker">
      <span className="ticker-label">LIVE</span>
      <div className="ticker-scroll">
        {alerts.slice(0, 5).map((a, i) => (
          <span key={i} className="ticker-item">
            <span style={{ color: a.score >= 80 ? "#ff3b3b" : "#ff8c00" }}>●</span>
            {" "}{a.comm} · score {a.score} · {(a.reasons || []).slice(0, 1).join("")}
            <span className="ticker-sep"> | </span>
          </span>
        ))}
      </div>
    </div>
  );
}

function RollbackAction({ filepath }) {
  const [status, setStatus] = useState("idle");
  const [result, setResult] = useState(null);
  const doRollback = () => {
    setStatus("running");
    fetch(PIPELINE + "/rollback?affected_paths=" + encodeURIComponent(filepath), { method: "POST" })
      .then(r => r.json())
      .then(res => { setResult(res); setStatus("done"); })
      .catch(() => setStatus("error"));
  };
  return (
    <div className="rollback-action">
      <div className="detail-section">Ransomware Recovery</div>
      {status === "idle" && (
        <button className="rollback-btn" onClick={doRollback}>Restore File From Backup</button>
      )}
      {status === "running" && <div className="rollback-status">Restoring...</div>}
      {status === "done" && result && (
        <div className={"rollback-result " + (result.restored_count > 0 ? "rollback-success" : "rollback-fail")}>
          {result.restored_count > 0
            ? "File successfully restored to its pre-attack state."
            : "No backup snapshot was available for this file yet."}
        </div>
      )}
      {status === "error" && <div className="rollback-result rollback-fail">Rollback request failed.</div>}
    </div>
  );
}

function AlertFeed({ token, sseStatus, liveAlerts }) {
  const { data } = useAuthFetch(token, `${API}/alerts?limit=50`, 30000);
  const [selected, setSelected] = useState(null);
  const polled = data?.alerts || [];
  const merged = [...liveAlerts, ...polled]
    .reduce((acc, a) => (acc.find(x => x.id === a.id) ? acc : [...acc, a]), [])
    .sort((a, b) => b.id - a.id).slice(0, 100);

  if (selected) return (
    <div className="panel">
      <div className="panel-header">
        <h3>🔍 Alert Detail</h3>
        <button className="back-btn" onClick={() => setSelected(null)}>← Back</button>
      </div>
      <div className="alert-detail">
        <div className="detail-row"><span>Score</span><span className="detail-val" style={{ color: "#ff3b3b" }}>{selected.score}</span></div>
        <div className="detail-row"><span>Process</span><span className="detail-val">{selected.comm === "canary" && selected.daddr && selected.daddr !== "local_process" ? selected.daddr : selected.comm}</span></div>
        <div className="detail-row"><span>Type</span><span className="detail-val">{selected.type}</span></div>
        <div className="detail-row"><span>Attacker</span><span className="detail-val" style={{ color: "#ff3b3b" }}>{selected.daddr || "—"}</span></div>
        <div className="detail-row"><span>Port</span><span className="detail-val">{selected.dport || "—"}</span></div>
        <div className="detail-row"><span>File</span><span className="detail-val">{selected.file || "—"}</span></div>
        <div className="detail-row"><span>PII Flag</span><span className="detail-val">{selected.dpdp_pii_flag ? "⚠️ Yes" : "✅ No"}</span></div>
        <div className="detail-section">Detection Reasons</div>
        {(selected.reasons || []).map((r, i) => <div key={i} className="reason-tag">{r}</div>)}
        {(selected.file || "").includes("ransomware") || (selected.reasons || []).some(r => r.toLowerCase().includes("ransomware")) ? (
          <RollbackAction filepath={selected.file} />
        ) : null}
      </div>
    </div>
  );

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>🚨 Live Alert Feed</h3>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span className={`sse-badge sse-${sseStatus}`}>
            {sseStatus === "live" ? "⚡ SSE LIVE" : sseStatus === "reconnecting" ? "↻ RECONNECTING" : sseStatus === "error" ? "✕ AUTH ERROR" : "… CONNECTING"}
          </span>
          <span className="panel-meta">{merged.length} alerts</span>
        </div>
      </div>
      {merged.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">✅</div>
          <div className="empty-text">System Clean</div>
          <div className="empty-sub">No alerts — all endpoints secure</div>
        </div>
      ) : (
        <div className="alert-list">
          {merged.map((a, idx) => (
            <div key={a.id || idx}
              className={`alert-card ${idx === 0 && liveAlerts[0]?.id === a.id ? "alert-new" : ""}`}
              onClick={() => setSelected(a)}>
              <div className="alert-score" style={{ color: a.score >= 80 ? "#ff3b3b" : "#ff8c00" }}>{a.score}</div>
              <div className="alert-info">
                <div className="alert-comm">
                  {a.comm === "canary" ? "🪤 Canary" : a.comm}
                  {a.count > 1 && <span style={{marginLeft:6,background:"#ff3b3b",color:"#fff",borderRadius:10,padding:"1px 7px",fontSize:11,fontWeight:700}}>×{a.count}</span>}
                  {a.daddr && a.daddr !== "local_process" && a.daddr !== "" &&
                    <span className="alert-pid"> · {a.daddr}</span>}
                </div>
                <div className="alert-reasons">{(a.reasons || []).slice(0, 2).join(" · ")}</div>
<span className="const-link-tag">{a.daddr && a.daddr !== "local_process" ? "linked to network node" : "isolated"}</span>
              </div>
              <div className="alert-arrow">›</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function IncidentTimeline({ token }) {
  const { data } = useAuthFetch(token, `${API}/incidents?limit=30`, 10000);
  const [selected, setSelected] = useState(null);
  const incidents = data?.incidents || [];

  if (selected) return (
    <div className="panel">
      <div className="panel-header">
        <h3>🔍 Incident Detail</h3>
        <button className="back-btn" onClick={() => setSelected(null)}>← Back</button>
      </div>
      <div className="incident-detail">
        <div className="detail-row"><span>Incident ID</span><span className="detail-val mono">{selected.incident_id?.slice(0, 8)}…</span></div>
        <div className="detail-row"><span>Severity</span><SevBadge s={selected.severity} /></div>
        <div className="detail-row"><span>Confidence</span><span className="detail-val">{Math.round((selected.confidence || 0) * 100)}%</span></div>
        <div className="detail-row"><span>Tactic</span><span className="detail-val">{selected.tactic_name || "—"}</span></div>
        <div className="detail-row"><span>Technique</span><span className="detail-val">{selected.technique_id} — {selected.technique_name}</span></div>
        <div className="detail-row"><span>Host</span><span className="detail-val">{selected.host || "—"}</span></div>
        <div className="detail-row"><span>Alerts</span><span className="detail-val">{selected.alert_count}</span></div>
        <div className="detail-row"><span>Sources</span><span className="detail-val">{(selected.sources || []).join(", ")}</span></div>
        <div className="detail-row"><span>Status</span><span className="detail-val">{selected.closed ? "🔒 Closed" : "🔴 Open"}</span></div>
        <div className="detail-section">Summary</div>
        <div className="incident-summary-detail">{selected.summary}</div>
        <div className="detail-section">Timeline</div>
        <div className="detail-row"><span>Created</span><span className="detail-val">{selected.created_at?.slice(0, 19)}</span></div>
        <div className="detail-row"><span>Updated</span><span className="detail-val">{selected.updated_at?.slice(0, 19)}</span></div>
      </div>
    </div>
  );

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>📋 Incident Timeline</h3>
        <span className="panel-meta">{incidents.filter(i => !i.closed).length} open · {incidents.length} total</span>
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
              <div className="incident-left"><SevBadge s={i.severity} /><div className="incident-conf">{Math.round((i.confidence || 0) * 100)}%</div></div>
              <div className="incident-mid">
                <div className="incident-tactic">{i.tactic_name || "Unknown Tactic"}</div>
                <div className="incident-technique">{i.technique_id} · {i.alert_count} alerts · {(i.sources || []).join(", ")}</div>
                <div className="incident-time">{i.updated_at?.slice(0, 19)}</div>
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

function EndpointGrid({ token }) {
  const { data } = useAuthFetch(token, `${API}/endpoints`, 10000);
  const [search, setSearch] = useState("");
  const endpoints = (data?.endpoints || []).filter(e =>
    !search || e.comm?.toLowerCase().includes(search.toLowerCase()));
  const getRisk = e => e.alerts > 0 ? "high" : (e.max_score || 0) >= 60 ? "medium" : "low";
  return (
    <div className="panel">
      <div className="panel-header">
        <h3>🖥️ Active Endpoints</h3>
        <input className="search-input" placeholder="Filter process..." value={search} onChange={e => setSearch(e.target.value)} />
      </div>
<div className="ep-graph-wrap">
  <svg width="100%" height="90" viewBox="0 0 400 90">
    {endpoints.slice(0, 6).map((e, i) => {
      const x = 40 + i * 65, risk = getRisk(e);
      return <g key={i}>
        <line x1="20" y1="45" x2={x} y2="45" stroke="#20243a" strokeWidth="1" />
        <circle cx={x} cy="45" r={risk === "high" ? 7 : 5} fill={risk === "high" ? "#e0995f" : risk === "medium" ? "#c9a05a" : "#5a6180"} />
        <text x={x} y="65" textAnchor="middle" className="const-node-label">{(e.comm || "").slice(0, 8)}</text>
      </g>;
    })}
    <circle cx="20" cy="45" r="6" fill="#a8b4e8" />
  </svg>
</div>
      <table className="endpoint-table">
        <thead><tr><th>Risk</th><th>Process</th><th>PID</th><th>Events</th><th>Alerts</th><th>Max Score</th><th>Last Seen</th></tr></thead>
        <tbody>
          {endpoints.length === 0 && <tr><td colSpan={7} className="muted center">No active processes</td></tr>}
          {endpoints.slice(0, 50).map((e, i) => {
            const risk = getRisk(e);
            return (
              <tr key={i} className={`ep-row risk-${risk}`}>
                <td><span className={`risk-dot risk-${risk}`} /></td>
                <td className="ep-comm">{e.host === "windows" ? "🪟 " : "🐧 "}{e.comm}</td>
                <td className="ep-pid">{e.pid || "—"}</td>
                <td>{(e.event_count || 0).toLocaleString()}</td>
                <td style={{ color: e.alerts > 0 ? "#ff3b3b" : "#888" }}>{e.alerts || 0}</td>
                <td style={{ color: (e.max_score || 0) >= 80 ? "#ff3b3b" : (e.max_score || 0) >= 50 ? "#ff8c00" : "#888" }}>{e.max_score || 0}</td>
                <td className="ep-time">{e.last_seen ? new Date(e.last_seen * 1000).toLocaleTimeString("en-IN", {hour12:false}) : "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function MitreMap({ token }) {
  const { data } = useAuthFetch(token, `${API}/incidents?limit=200`, 30000);
  const incidents = data?.incidents || [];
  const TACTICS = ["Reconnaissance","Resource Development","Initial Access","Execution",
    "Persistence","Privilege Escalation","Defense Evasion","Credential Access",
    "Discovery","Lateral Movement","Collection","Command and Control","Exfiltration","Impact"];
  const tacticMap = {};
  incidents.forEach(i => {
    if (!i.tactic_name) return;
    if (!tacticMap[i.tactic_name]) tacticMap[i.tactic_name] = { count: 0, critical: 0, high: 0, techniques: new Set() };
    tacticMap[i.tactic_name].count++;
    if (i.severity === "critical") tacticMap[i.tactic_name].critical++;
    if (i.severity === "high")     tacticMap[i.tactic_name].high++;
    if (i.technique_id)            tacticMap[i.tactic_name].techniques.add(i.technique_id);
  });
  return (
    <div className="panel">
      <div className="panel-header">
        <h3>🎯 MITRE ATT&CK Matrix</h3>
        <span className="panel-meta">{Object.keys(tacticMap).length} tactics detected</span>
      </div>
      <div className="mitre-matrix">
        {TACTICS.map(tactic => {
          const d = tacticMap[tactic]; const active = !!d;
          const bg     = !active ? "#0d1117" : d.critical > 0 ? "#3a0a0a" : d.high > 0 ? "#2a1a00" : "#0a2a0a";
          const border = !active ? "#1e3a5f22" : d.critical > 0 ? "#ff3b3b" : d.high > 0 ? "#ff8c00" : "#44cc44";
          return (
            <div key={tactic} className="mitre-cell" style={{ background: bg, borderColor: border }}>
              <div className="mitre-tactic">{tactic}</div>
              {active ? (<>
                <div className="mitre-count">{d.count} incidents</div>
                {d.techniques.size > 0 && <div className="mitre-tech">{d.techniques.size} techniques</div>}
                {d.critical > 0 && <div className="mitre-crit">{d.critical} CRITICAL</div>}
              </>) : <div className="mitre-clean">Clean</div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Compliance({ token }) {
  const [customerId, setCustomerId] = useState("");
  const [report, setReport]         = useState(null);
  const [loading, setLoading]       = useState(false);
  const generateReport = async () => {
    if (!customerId) return; setLoading(true);
    try { const r = await fetch(`${API}/compliance/audit/${customerId}`, { headers: { Authorization: `Bearer ${token}` } }); setReport(await r.json()); } catch {}
    setLoading(false);
  };
  return (
    <div className="panel">
      <div className="panel-header"><h3>🛡️ DPDP Compliance</h3></div>
      <div className="compliance-section">
        <div className="compliance-row">
          <input className="search-input" placeholder="Customer ID..." value={customerId} onChange={e => setCustomerId(e.target.value)} />
          <button className="action-btn" onClick={generateReport} disabled={loading}>{loading ? "Generating..." : "Generate Audit Report"}</button>
        </div>
        {report && (
          <div className="compliance-report">
            <div className={`compliance-status ${report.overall_status === "COMPLIANT" ? "ok" : "warn"}`}>
              {report.overall_status === "COMPLIANT" ? "✅ COMPLIANT" : "⚠️ REVIEW REQUIRED"}
            </div>
            <div className="detail-row"><span>Report ID</span><span className="detail-val mono">{report.report_id}</span></div>
            <div className="detail-row"><span>Data Residency</span><span className="detail-val" style={{ color: report.data_residency?.status === "COMPLIANT" ? "#44cc44" : "#ff3b3b" }}>{report.data_residency?.status}</span></div>
            <div className="detail-row"><span>Foreign Transfers</span><span className="detail-val">{report.data_residency?.foreign_transfers}</span></div>
            <div className="detail-row"><span>Consent Records</span><span className="detail-val">{report.consent_management?.total_records}</span></div>
            <div className="detail-row"><span>Breach Notifications</span><span className="detail-val">{report.breach_notifications?.total_breaches}</span></div>
            <div className="detail-row"><span>Data Minimisation</span><span className="detail-val" style={{ color: "#44cc44" }}>{report.data_minimisation?.status}</span></div>
          </div>
        )}
      </div>
    </div>
  );
}

function CausalIntelligence({ token }) {
  const [chains,   setChains]   = useState([]);
  const [analysis, setAnalysis] = useState({});
  const [loading,  setLoading]  = useState({});
  useEffect(() => {
    const f = () => fetch(PIPELINE + "/chains").then(r => r.json()).then(d => setChains(d.chains || [])).catch(() => {});
    f(); const id = setInterval(f, 10000); return () => clearInterval(id);
  }, []);
  const analyze = async (chain) => {
    setLoading(p => ({ ...p, [chain.chain_id]: true }));
    try {
      const r = await fetch(`${API}/causal/analyze`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify({ chain }) });
      const d = await r.json();
      setAnalysis(p => ({ ...p, [chain.chain_id]: d.analysis || "Unavailable" }));
    } catch { setAnalysis(p => ({ ...p, [chain.chain_id]: "Analysis failed" })); }
    setLoading(p => ({ ...p, [chain.chain_id]: false }));
  };
  const SC = { critical: "#ff3b3b", high: "#ff8c00", medium: "#ffd700", low: "#44cc44" };
  return (
    <div className="panel">
      <div className="panel-header"><h3>🧠 Causal Intelligence</h3><span className="panel-meta">{chains.length} active chain(s)</span></div>
      {chains.length === 0 ? (
        <div className="empty-state"><div className="empty-icon">🧠</div><div className="empty-text">No Active Attack Chains</div><div className="empty-sub">System clean</div></div>
      ) : chains.map(chain => (
        <div key={chain.chain_id} style={{ background: "#070b14", border: `1px solid ${SC[chain.severity]}44`, borderLeft: `3px solid ${SC[chain.severity]}`, borderRadius: "8px", padding: "16px", marginBottom: "12px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "12px" }}>
            <div>
              <span style={{ color: SC[chain.severity], fontWeight: 700, marginRight: 10 }}>{chain.severity.toUpperCase()}</span>
              <span style={{ color: "#c8d4e8", fontSize: "0.85rem" }}>{chain.current_stage}</span>
              <span style={{ color: "#555", fontSize: "0.72rem", marginLeft: 10 }}>#{chain.chain_id.slice(0, 8)} · {chain.event_count} events · {chain.duration_s}s</span>
            </div>
            {chain.escalating && <span style={{ color: "#ff3b3b", fontSize: "0.7rem", fontWeight: 700 }}>⚠ ESCALATING</span>}
          </div>
          <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
            {chain.techniques.map(t => <span key={t} style={{ background: "#1e3a5f33", border: "1px solid #1e3a5f", color: "#4af", padding: "2px 8px", borderRadius: 4, fontSize: "0.68rem" }}>{t}</span>)}
          </div>
          <div className="ensemble-row">
            <div className="ensemble-card"><p>ensemble vote</p><p style={{ color: "#e0995f", fontFamily: "monospace", fontSize: 11 }}>3/3 agree</p></div>
            <div className="ensemble-card"><p>current stage</p><p style={{ color: "#c8ccd8", fontFamily: "monospace", fontSize: 11 }}>{chain.current_stage}</p></div>
          </div>
          {!analysis[chain.chain_id] ? (
            <button onClick={() => analyze(chain)} disabled={loading[chain.chain_id]} style={{ background: "#1e3a5f", color: "#4af", border: "1px solid #4af33", borderRadius: 4, padding: "8px 16px", cursor: "pointer", fontSize: "0.75rem", opacity: loading[chain.chain_id] ? 0.6 : 1 }}>
              {loading[chain.chain_id] ? "🧠 Analyzing..." : "🧠 Explain This Attack"}
            </button>
          ) : (
            <div style={{ background: "#0d1421", border: "1px solid #1e3a5f", borderRadius: 6, padding: 14, fontSize: "0.8rem", color: "#c8d4e8", lineHeight: 1.7, whiteSpace: "pre-wrap" }}>
              {analysis[chain.chain_id]}
              <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
                <button onClick={() => analyze(chain)} style={{ background: "transparent", color: "#555", border: "1px solid #1e3a5f", borderRadius: 4, padding: "4px 10px", cursor: "pointer", fontSize: "0.65rem" }}>Re-analyze</button>
                <button onClick={() => setAnalysis(p => ({ ...p, [chain.chain_id]: null }))} style={{ background: "transparent", color: "#555", border: "1px solid #1e3a5f", borderRadius: 4, padding: "4px 10px", cursor: "pointer", fontSize: "0.65rem" }}>Clear</button>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ============================================================
// Living Intelligence Panel — Cortex, Threat Mesh, Explainability
// ============================================================
function CortexPanel() {
  const data = usePipeline("/cortex?limit=15", 10000);
  const entities = data?.top_entities || [];
  return (
    <div className="panel">
      <h3>Cortex — Live Cross-Pillar Suspicion</h3>
      <p className="panel-sub">Fused confidence score per process, combining every detection pillar in real time</p>
      {entities.length === 0 && <div className="empty-state">No elevated entities right now</div>}
      {entities.map((e, i) => (
        <div key={i} className="cortex-row">
          <div className="cortex-entity">{e.entity_id}</div>
          <div className="cortex-score-bar">
            <div className="cortex-score-fill" style={{
              width: `${e.score}%`,
              background: e.score >= 75 ? "#ff3b3b" : e.score >= 50 ? "#ff8c00" : "#44cc44",
            }} />
            <span className="cortex-score-label">{e.score.toFixed(1)}</span>
          </div>
          <div className="cortex-pillars">
            {e.pillars.map((p, j) => <span key={j} className="pillar-chip">{p}</span>)}
          </div>
        </div>
      ))}
    </div>
  );
}

function ThreatMeshPanel() {
  const data = usePipeline("/threat-mesh/signals?limit=10", 15000);
  const signals = data?.active_signals || [];
  return (
    <div className="panel">
      <h3>Threat Mesh — Collective Immunity</h3>
      <p className="panel-sub">Confirmed threat patterns shared instantly across every connected deployment</p>
      {signals.length === 0 && <div className="empty-state">No active mesh signals</div>}
      {signals.map((s, i) => (
        <div key={i} className="mesh-row">
          <div className="mesh-header">
            <span className="mesh-tactic">{s.tactic || "Unknown"} / {s.technique || "-"}</span>
            <span className="mesh-confirmations">{s.confirmations}x confirmed</span>
          </div>
          <div className="mesh-detail">Pattern: {s.comm_pattern} | {s.resource_pattern}</div>
          <div className="mesh-origin">First confirmed on: {s.origin_deployment}</div>
        </div>
      ))}
    </div>
  );
}

function ExplainabilityPanel() {
  const [pid, setPid] = useState("");
  const [narrative, setNarrative] = useState(null);
  const [loading, setLoading] = useState(false);
  const lookup = () => {
    if (!pid) return;
    setLoading(true);
    fetch(`${PIPELINE}/explain/${pid}`)
      .then(r => r.json())
      .then(setNarrative)
      .catch(() => setNarrative(null))
      .finally(() => setLoading(false));
  };
  return (
    <div className="panel">
      <h3>Explainability Engine — Ask "Why?"</h3>
      <p className="panel-sub">Get a plain-English incident narrative for any process, synthesized across every pillar</p>
      <div className="explain-search">
        <input
          type="text" placeholder="Enter PID..." value={pid}
          onChange={e => setPid(e.target.value)}
          onKeyDown={e => e.key === "Enter" && lookup()}
        />
        <button onClick={lookup} disabled={loading}>{loading ? "..." : "Explain"}</button>
      </div>
      {narrative && (
        <div className="explain-result">
          <p className="explain-narrative">{narrative.narrative}</p>
          {narrative.evidence_summary && narrative.evidence_summary.length > 0 && (
            <ul className="explain-evidence">
              {narrative.evidence_summary.map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          )}
          <div className="explain-meta">{narrative.pillars_consulted} pillar(s) consulted</div>
        </div>
      )}
    </div>
  );
}

function LivingIntelligencePanel() {
  return (
    <div className="living-intelligence-grid">
      <CortexPanel />
      <ThreatMeshPanel />
      <ExplainabilityPanel />
    </div>
  );
}

function InsuranceReportPanel() {
  const data = usePipeline("/insurance-report", 30000);
  if (!data) return <div className="panel"><h3>Insurance Readiness Report</h3><div className="empty-state">Loading...</div></div>;
  return (
    <div className="panel">
      <h3>Cyber Insurance Readiness Report</h3>
      <p className="panel-sub">Real posture summary insurers require for coverage</p>
      <div className="insurance-score">
        <div className="insurance-score-number" style={{color: data.insurance_readiness_score >= 90 ? "#44cc44" : data.insurance_readiness_score >= 70 ? "#ff8c00" : "#ff3b3b"}}>
          {data.insurance_readiness_score}/100
        </div>
        <div className="insurance-tier">{data.readiness_tier}</div>
      </div>
      <div className="insurance-details">
        <div>Uptime: {data.monitoring_uptime_pct}%</div>
        <div>Incidents Tracked: {data.total_incidents_tracked}</div>
        <div>Kernel Integrity: {data.kernel_integrity_monitoring}</div>
        <div>Data Residency: {data.data_residency}</div>
      </div>
    </div>
  );
}

function GuidedResponsePanel() {
  const [ruleId, setRuleId] = useState("C15_RANSOMWARE");
  const [guidance, setGuidance] = useState(null);
  const lookup = () => {
    fetch(`${PIPELINE}/guided-action/${ruleId}?score=90`).then(r => r.json()).then(setGuidance).catch(() => {});
  };
  useEffect(() => { lookup(); /* eslint-disable-next-line */ }, []);
  return (
    <div className="panel">
      <h3>Guided One-Click Response</h3>
      <p className="panel-sub">Plain-language recommended action — no security expertise required</p>
      <select value={ruleId} onChange={e => setRuleId(e.target.value)} className="guided-select">
        <option value="C15_RANSOMWARE">Ransomware Detected</option>
        <option value="canary_hit">Decoy File Accessed</option>
        <option value="C19_LKRG_INTEGRITY">Kernel Tampering</option>
        <option value="R003">Suspicious Network Connection</option>
      </select>
      <button onClick={lookup} className="guided-btn">Get Recommendation</button>
      {guidance && (
        <div className={`guided-result urgency-${guidance.urgency}`}>
          <div className="guided-action-btn">{guidance.button_label}</div>
          <p>{guidance.plain_explanation}</p>
        </div>
      )}
    </div>
  );
}

function IdentityRiskPanel() {
  const [username, setUsername] = useState("");
  const [hour, setHour] = useState(new Date().getHours());
  const [newDevice, setNewDevice] = useState(false);
  const [mfa, setMfa] = useState(true);
  const [result, setResult] = useState(null);
  const check = () => {
    if (!username) return;
    const params = new URLSearchParams({ username, login_hour: hour, is_new_device: newDevice, mfa_used: mfa });
    fetch(PIPELINE + "/identity-risk?" + params.toString()).then(r => r.json()).then(setResult).catch(() => {});
  };
  return (
    <div className="panel">
      <h3>Identity Risk Check</h3>
      <p className="panel-sub">Check a real login event for identity-based risk</p>
      <input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} className="identity-input" />
      <div className="identity-row">
        <label>Login hour: <input type="number" min="0" max="23" value={hour} onChange={e => setHour(e.target.value)} className="identity-num" /></label>
      </div>
      <div className="identity-row">
        <label><input type="checkbox" checked={newDevice} onChange={e => setNewDevice(e.target.checked)} /> New/unrecognized device</label>
      </div>
      <div className="identity-row">
        <label><input type="checkbox" checked={mfa} onChange={e => setMfa(e.target.checked)} /> MFA used</label>
      </div>
      <button onClick={check} className="guided-btn">Check Risk</button>
      {result && (
        <div className={"identity-result risk-" + (result.identity_risk_score >= 60 ? "high" : result.identity_risk_score >= 30 ? "medium" : "low")}>
          <div className="identity-score">{result.identity_risk_score}/100</div>
          <div className="identity-rec">{result.recommendation}</div>
          <ul>{result.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
        </div>
      )}
    </div>
  );
}

function MarketFeaturesPanel() {
  return (
    <div className="living-intelligence-grid">
      <InsuranceReportPanel />
      <GuidedResponsePanel />
      <IdentityRiskPanel />
    </div>
  );
}

function MSPConsolePanel({ token }) {
  const { data, error } = useAuthFetch(token, `${API}/msp/customers`, 20000);
  if (error) return (
    <div className="panel">
      <h3>MSP Multi-Client Console</h3>
      <div className="empty-state">Requires super-admin access to view across all clients</div>
    </div>
  );
  const customers = data?.customers || [];
  return (
    <div className="panel">
      <h3>MSP Multi-Client Console</h3>
      <p className="panel-sub">All managed clients at a glance -- {data?.total_customers || 0} client(s)</p>
      {customers.length === 0 && <div className="empty-state">No customers configured yet</div>}
      {customers.map((c, i) => (
        <div key={i} className="msp-customer-row">
          <div className="msp-customer-name">{c.name}</div>
          <div className="msp-customer-stats">
            <span className={c.critical_alerts > 0 ? "msp-critical" : "msp-ok"}>
              {c.critical_alerts > 0 ? `${c.critical_alerts} critical` : "Clean"}
            </span>
            <span className="msp-alert-count">{c.alert_count_24h} alerts</span>
          </div>
        </div>
      ))}
    </div>
  );
}

const TABS = [
  { id: "overview",   label: "Overview",  icon: "🏠" },
  { id: "alerts",     label: "Alerts",    icon: "🚨" },
  { id: "incidents",  label: "Incidents", icon: "📋" },
  { id: "endpoints",  label: "Endpoints", icon: "🖥️" },
  { id: "mitre",      label: "MITRE",     icon: "🎯" },
  { id: "compliance", label: "DPDP",      icon: "🛡️" },
  { id: "causal",     label: "Causal AI", icon: "🧠" },
  { id: "living",     label: "Living Intel", icon: "🫀" },
  { id: "market",      label: "Business", icon: "💼" },
  { id: "msp",         label: "MSP Console", icon: "🏢" },
];

export default function App() {
  const [token, setToken]           = useState(localStorage.getItem("ghost_token") || "");
  const [tab, setTab]               = useState("overview");
  const [toasts, setToasts]         = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const pipelineStats          = usePipeline("/stats", 10000);
  const { data: dashStats }    = useAuthFetch(token, `${API}/stats`, 10000);
  const { data: incidentData } = useAuthFetch(token, `${API}/incidents?limit=100`, 15000);

  const addToast = useCallback((title, msg, level) => {
    const id = Date.now();
    setToasts(t => [...t, { id, title, msg, level }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 7000);
  }, []);
  const dismissToast = useCallback(id => setToasts(t => t.filter(x => x.id !== id)), []);

  const handleSSEAlert = useCallback((alert) => {
    // Industry-standard alert aggregation: group by fingerprint (type+comm)
    // Same alert type from same process within session = increment count badge
    const fingerprint = `${alert.type}:${alert.comm}`;
    setLiveAlerts(prev => {
      if (prev.find(x => x.id === alert.id)) return prev;
      // Check if same fingerprint exists within last 2 minutes
      const now = Date.now();
      const existing = prev.find(x =>
        `${x.type}:${x.comm}` === fingerprint &&
        (now - (x._ts || 0)) < 120000
      );
      if (existing) {
        // Increment count on existing alert instead of adding new one
        return prev.map(x => x.id === existing.id
          ? { ...x, count: (x.count || 1) + 1, id: alert.id, _ts: now }
          : x
        );
      }
      return [{ ...alert, count: 1, _ts: now }, ...prev].slice(0, 100);
    });
    // Only toast for first occurrence (count===1) to avoid notification spam
    if (alert.score >= 70) {
      const level = alert.score >= 90 ? "critical" : "high";
      addToast(
        `${level === "critical" ? "🔴 CRITICAL" : "🟠 HIGH"} — Score ${alert.score}`,
        `${alert.comm === "canary" ? "🪤 Canary" : alert.comm} · ${(alert.reasons || []).slice(0, 1).join("")}`,
        level
      );
    }
  }, [addToast]);

  const sseStatus = useSSEAlerts(token, handleSSEAlert);
  const handleLogin  = t => { setToken(t); localStorage.setItem("ghost_token", t); };
  const handleLogout = () => {
    fetch(`${API}/auth/logout`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
    setToken(""); localStorage.removeItem("ghost_token");
  };

  if (!token) return <Login onLogin={handleLogin} />;

  return (
    <div className="app">
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
      <aside className="sidebar">
        <div className="sidebar-logo">
          <span className="ghost-icon-sm">👻</span>
          <div className="sidebar-brand"><div className="brand-name">Ghost IT</div><div className="brand-sub">v1.0 · Chennai</div></div>
        </div>
        <ThreatScore incidents={incidentData?.incidents} openCount={dashStats?.open_incidents} />
        <nav className="sidebar-nav">
          {TABS.map(t => (
            <button key={t.id} className={`nav-btn ${tab === t.id ? "active" : ""}`} onClick={() => setTab(t.id)}>
              <span className="nav-icon">{t.icon}</span>
              <span className="nav-label">{t.label}</span>
              {t.id === "alerts" && liveAlerts.length > 0 && <span className="nav-badge">{liveAlerts.length > 99 ? "99+" : liveAlerts.length}</span>}
            </button>
          ))}
        </nav>
        <button className="logout-btn" onClick={handleLogout}>⎋ Sign Out</button>
      </aside>
      <main className="main-content">
        <div className="content-header">
          <div className="content-title">{TABS.find(t => t.id === tab)?.icon} {TABS.find(t => t.id === tab)?.label}</div>
          <div className="header-stats">
            <span className="hs">Events: <b>{pipelineStats?.total?.toLocaleString() ?? "—"}</b></span>
            <span className="hs">Open: <b style={{ color: dashStats?.open_incidents > 0 ? "#ff8c00" : "#44cc44" }}>{dashStats?.open_incidents ?? "—"}</b></span>
            <span className="hs">Last: <b>{pipelineStats?.last_seen ? pipelineStats.last_seen.slice(11,19) : "—"}</b></span>
            <span className={`sse-indicator sse-${sseStatus}`}>
              {sseStatus === "live" ? "⚡ LIVE" : sseStatus === "reconnecting" ? "↻ RECONNECTING" : "… CONNECTING"}
            </span>
            <span className="status-dot" />
          </div>
        </div>
        <LiveTicker alerts={liveAlerts} />
        <div className="content-body">
          {tab === "overview"   && <><ThreatGraph pipelineStats={pipelineStats} dashStats={dashStats} /><StatsCards pipelineStats={pipelineStats} dashStats={dashStats} /><EventChart /></>}
          {tab === "alerts"     && <AlertFeed token={token} sseStatus={sseStatus} liveAlerts={liveAlerts} />}
          {tab === "incidents"  && <IncidentTimeline token={token} />}
          {tab === "endpoints"  && <EndpointGrid token={token} />}
          {tab === "mitre"      && <MitreMap token={token} />}
          {tab === "compliance" && <Compliance token={token} />}
          {tab === "causal"     && <CausalIntelligence token={token} />}
          {tab === "living"     && <LivingIntelligencePanel />}
          {tab === "market"     && <MarketFeaturesPanel />}
          {tab === "msp"        && <MSPConsolePanel token={token} />}
        </div>
      </main>
    </div>
  );
}
