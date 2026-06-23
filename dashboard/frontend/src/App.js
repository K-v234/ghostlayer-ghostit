import { useState, useEffect, useCallback, useRef } from "react";
import "./App.css";

const API = "http://127.0.0.1:8001/api";
const WS  = "ws://127.0.0.1:8001/ws/alerts";
const BASE = "http://127.0.0.1:8001/app";

// ── Auth ──────────────────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [err,  setErr]  = useState("");

  const submit = async () => {
    try {
      const r = await fetch(`${API}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, password: pass }),
      });
      if (!r.ok) { setErr("Invalid credentials"); return; }
      const d = await r.json();
      onLogin(d.token);
    } catch { setErr("Server unreachable"); }
  };

  return (
    <div className="login-box">
      <h2>Ghost IT — Management Console</h2>
      <input placeholder="Username" value={user} onChange={e => setUser(e.target.value)} />
      <input placeholder="Password" type="password" value={pass} onChange={e => setPass(e.target.value)}
        onKeyDown={e => e.key === "Enter" && submit()} />
      <button onClick={submit}>Login</button>
      {err && <p className="error">{err}</p>}
    </div>
  );
}

// ── Authenticated fetch hook ──────────────────────────────────────────────────
function useAuth(token, endpoint, interval = 10000) {
  const [data, setData] = useState(null);
  const fetch_ = useCallback(() => {
    fetch(`${API}${endpoint}`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json()).then(setData).catch(() => {});
  }, [token, endpoint]);
  useEffect(() => {
    fetch_();
    const id = setInterval(fetch_, interval);
    return () => clearInterval(id);
  }, [fetch_, interval]);
  return data;
}

// ── Severity badge ────────────────────────────────────────────────────────────
function Sev({ s }) {
  const colors = { critical: "#ff4444", high: "#ff8800",
                   medium: "#ffcc00", low: "#44bb44", info: "#888" };
  return <span style={{ color: colors[s] || "#888", fontWeight: "bold",
    textTransform: "uppercase", fontSize: "0.75rem" }}>{s}</span>;
}

// ── Stats bar ─────────────────────────────────────────────────────────────────
function StatsBar({ token }) {
  const d = useAuth(token, "/stats", 15000);
  if (!d) return <div className="stats-bar">Loading…</div>;
  return (
    <div className="stats-bar">
      <span>Total Events: <b>{d.pipeline?.total?.toLocaleString() ?? "—"}</b></span>
      <span>Open Incidents: <b style={{color: d.open_incidents > 0 ? "#ff8800" : "#44bb44"}}>
        {d.open_incidents}</b></span>
      <span>Critical: <b style={{color: d.critical_incidents > 0 ? "#ff4444" : "#44bb44"}}>
        {d.critical_incidents}</b></span>
      <span>Last Seen: <b>{d.pipeline?.last_seen?.slice(11,19) ?? "—"}</b></span>
    </div>
  );
}

// ── Alert Feed ────────────────────────────────────────────────────────────────
function AlertFeed({ token }) {
  const [alerts, setAlerts] = useState([]);
  const ws = useRef(null);

  useEffect(() => {
    // Initial load
    fetch(`${API}/alerts?limit=50`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json()).then(d => setAlerts(d.alerts || [])).catch(() => {});

    // WebSocket live feed
    const sock = new WebSocket(`${WS}?token=${token}`);
    sock.onmessage = e => {
      const a = JSON.parse(e.data);
      setAlerts(prev => [a, ...prev].slice(0, 100));
    };
    ws.current = sock;
    return () => sock.close();
  }, [token]);

  return (
    <div className="panel">
      <h3>🚨 Live Alert Feed</h3>
      <div className="alert-list">
        {alerts.length === 0 && <p className="muted">No alerts — system clean</p>}
        {alerts.map(a => (
          <div key={a.id} className="alert-row">
            <span className="alert-score">{a.score}</span>
            <span className="alert-comm">{a.comm}</span>
            <span className="alert-reasons">
              {(a.reasons || []).slice(0, 2).join(" | ")}
            </span>
            {a.daddr && <span className="alert-dst">→ {a.daddr}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Incident Timeline ─────────────────────────────────────────────────────────
function IncidentTimeline({ token }) {
  const d = useAuth(token, "/incidents?limit=20", 15000);
  const incidents = d?.incidents || [];

  return (
    <div className="panel">
      <h3>📋 Incident Timeline</h3>
      <div className="incident-list">
        {incidents.length === 0 && <p className="muted">No incidents</p>}
        {incidents.map(i => (
          <div key={i.incident_id} className={`incident-row ${i.closed ? "closed" : ""}`}>
            <div className="incident-header">
              <Sev s={i.severity} />
              <span className="incident-tactic">{i.tactic_name || "Unknown"}</span>
              <span className="incident-technique">{i.technique_id}</span>
              <span className="incident-conf">{Math.round(i.confidence * 100)}%</span>
              {i.closed && <span className="badge-closed">CLOSED</span>}
            </div>
            <div className="incident-summary">{i.summary}</div>
            <div className="incident-meta">
              {i.alert_count} alerts · {(i.sources || []).join(", ")} ·{" "}
              {i.updated_at?.slice(0, 19)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Endpoint Grid ─────────────────────────────────────────────────────────────
function EndpointGrid({ token }) {
  const d = useAuth(token, "/endpoints", 15000);
  const endpoints = d?.endpoints || [];

  return (
    <div className="panel">
      <h3>🖥 Active Endpoints (last 5min)</h3>
      <table className="endpoint-table">
        <thead><tr><th>Process</th><th>PID</th><th>Events</th><th>Last Seen</th></tr></thead>
        <tbody>
          {endpoints.length === 0 && (
            <tr><td colSpan={4} className="muted">No active endpoints</td></tr>
          )}
          {endpoints.map((e, i) => (
            <tr key={i}>
              <td>{e.comm}</td>
              <td>{e.pid}</td>
              <td>{e.event_count}</td>
              <td>{String(e.last_seen).slice(0, 19)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── MITRE ATT&CK Map ──────────────────────────────────────────────────────────
function MitreMap({ token }) {
  const d = useAuth(token, "/incidents?limit=100", 30000);
  const incidents = d?.incidents || [];

  const tactics = {};
  incidents.forEach(i => {
    if (!i.tactic_name) return;
    if (!tactics[i.tactic_name]) tactics[i.tactic_name] = { count: 0, critical: 0 };
    tactics[i.tactic_name].count++;
    if (i.severity === "critical") tactics[i.tactic_name].critical++;
  });

  return (
    <div className="panel">
      <h3>🎯 MITRE ATT&CK Coverage</h3>
      <div className="mitre-grid">
        {Object.keys(tactics).length === 0 && <p className="muted">No tactic data yet</p>}
        {Object.entries(tactics).map(([tactic, data]) => (
          <div key={tactic} className="mitre-cell"
               style={{ background: data.critical > 0 ? "#3a1a1a" : "#1a2a1a" }}>
            <div className="mitre-tactic">{tactic}</div>
            <div className="mitre-count">{data.count} incidents</div>
            {data.critical > 0 && <div className="mitre-critical">{data.critical} CRITICAL</div>}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function App() {
  const [token, setToken] = useState(sessionStorage.getItem("ghost_token") || "");
  const [tab,   setTab]   = useState("alerts");

  const handleLogin = t => { setToken(t); sessionStorage.setItem("ghost_token", t); };
  const handleLogout = () => {
    fetch(`${API}/auth/logout`, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
    setToken(""); sessionStorage.removeItem("ghost_token");
  };

  if (!token) return <Login onLogin={handleLogin} />;

  return (
    <div className="app">
      <header className="app-header">
        <span className="logo">👻 Ghost IT</span>
        <nav>
          {["alerts","incidents","endpoints","mitre"].map(t => (
            <button key={t} className={tab === t ? "active" : ""}
                    onClick={() => setTab(t)}>{t.toUpperCase()}</button>
          ))}
        </nav>
        <button className="logout" onClick={handleLogout}>Logout</button>
      </header>
      <StatsBar token={token} />
      <main className="app-main">
        {tab === "alerts"    && <AlertFeed token={token} />}
        {tab === "incidents" && <IncidentTimeline token={token} />}
        {tab === "endpoints" && <EndpointGrid token={token} />}
        {tab === "mitre"     && <MitreMap token={token} />}
      </main>
    </div>
  );
}
