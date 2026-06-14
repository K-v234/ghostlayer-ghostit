import { useState, useEffect, useCallback } from "react";
import "./App.css";

const API = "http://127.0.0.1:8000";
const REFRESH_MS = 5000;

function useFetch(endpoint) {
  const [data, setData]   = useState(null);
  const [error, setError] = useState(null);

  const fetch_ = useCallback(() => {
    fetch(`${API}${endpoint}`)
      .then(r => r.json())
      .then(setData)
      .catch(e => setError(e.message));
  }, [endpoint]);

  useEffect(() => {
    fetch_();
    const id = setInterval(fetch_, REFRESH_MS);
    return () => clearInterval(id);
  }, [fetch_]);

  return { data, error };
}

function StatCard({ label, value, highlight }) {
  return (
    <div className={`stat-card ${highlight ? "highlight" : ""}`}>
      <div className="stat-value">{value ?? "—"}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function StatsBar() {
  const { data } = useFetch("/stats");
  return (
    <div className="stats-bar">
      <StatCard label="Total Events"     value={data?.total}        />
      <StatCard label="Alerts"           value={data?.alerts}       highlight={data?.alerts > 0} />
      <StatCard label="Unique Processes" value={data?.unique_procs} />
      <StatCard label="Unique PIDs"      value={data?.unique_pids}  />
      <StatCard label="Last Event"       value={data?.last_seen?.slice(11, 19)} />
    </div>
  );
}

function TopProcesses() {
  const { data } = useFetch("/top?limit=8");
  return (
    <div className="panel">
      <h2>Top Processes</h2>
      <table>
        <thead>
          <tr>
            <th>Process</th>
            <th>Events</th>
            <th>Alerts</th>
            <th>Max Score</th>
            <th>Types</th>
          </tr>
        </thead>
        <tbody>
          {data?.processes?.map((p, i) => (
            <tr key={i} className={p.alerts > 0 ? "row-alert" : ""}>
              <td className="mono">{p.comm}</td>
              <td>{p.total}</td>
              <td>{p.alerts > 0 ? <span className="badge-alert">{p.alerts}</span> : 0}</td>
              <td>
                <div className="score-bar">
                  <div className="score-fill" style={{ width: `${p.max_score}%`,
                    background: p.max_score >= 60 ? "#ff4444" :
                                p.max_score >= 30 ? "#ffaa00" : "#00cfff" }} />
                  <span>{p.max_score}</span>
                </div>
              </td>
              <td>{p.event_types}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AlertFeed() {
  const { data } = useFetch("/alerts?limit=20");
  const alerts   = data?.alerts ?? [];
  return (
    <div className="panel panel-alerts">
      <h2>🚨 Alerts <span className="count">{alerts.length}</span></h2>
      {alerts.length === 0
        ? <div className="empty">No alerts — system clean</div>
        : alerts.map((e, i) => (
          <div key={i} className="alert-row">
            <span className="alert-time">{String(e.received_at).slice(11, 19)}</span>
            <span className="alert-comm mono">{e.comm}</span>
            <span className="alert-type">{e.type}</span>
            <span className="alert-score">{e.score}</span>
            <span className="alert-reasons">{(e.reasons ?? []).join(", ")}</span>
          </div>
        ))
      }
    </div>
  );
}

function EventFeed() {
  const [type,  setType]  = useState("");
  const [comm,  setComm]  = useState("");
  const [min,   setMin]   = useState(0);

  const params = new URLSearchParams({ limit: 50 });
  if (type) params.set("type",      type);
  if (comm) params.set("comm",      comm);
  if (min)  params.set("min_score", min);

  const { data } = useFetch(`/events?${params}`);
  const events   = data?.events ?? [];

  return (
    <div className="panel">
      <h2>Event Feed <span className="count">{data?.total ?? 0}</span></h2>
      <div className="filters">
        <select value={type} onChange={e => setType(e.target.value)}>
          <option value="">All types</option>
          {["exec","open","connect","clone","unlink","canary_hit"].map(t =>
            <option key={t} value={t}>{t}</option>
          )}
        </select>
        <input placeholder="Filter process..." value={comm}
               onChange={e => setComm(e.target.value)} />
        <label>Min score:
          <input type="range" min={0} max={100} step={5}
                 value={min} onChange={e => setMin(Number(e.target.value))} />
          <span>{min}</span>
        </label>
      </div>
      <table>
        <thead>
          <tr>
            <th>Time</th><th>PID</th><th>Process</th>
            <th>Type</th><th>Score</th><th>File / Addr</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={i} className={e.alert ? "row-alert" : e.score >= 30 ? "row-warn" : ""}>
              <td className="mono">{String(e.received_at).slice(11, 19)}</td>
              <td className="mono">{e.pid}</td>
              <td className="mono">{e.comm}</td>
              <td><span className={`tag tag-${e.type}`}>{e.type}</span></td>
              <td>
                <span className={`score ${e.score >= 60 ? "score-high" :
                                          e.score >= 30 ? "score-med" : "score-low"}`}>
                  {e.score}
                </span>
              </td>
              <td className="mono small">
                {e.file ?? (e.daddr ? `${e.daddr}:${e.dport}` : "—")}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


function ChainPanel() {
  const { data } = useFetch("/chains");
  const chains   = data?.chains ?? [];
  const severity = data?.highest_severity ?? "none";

  const color = {
    critical: "#ff4444",
    high:     "#ffaa00",
    medium:   "#00cfff",
    low:      "#00ff88",
    none:     "#4a5568",
  };

  return (
    <div className="panel" style={{borderColor: color[severity] || "#1e2535"}}>
      <h2>⛓ Attack Chains
        <span className="count">{chains.length}</span>
        {severity !== "none" && (
          <span style={{marginLeft:8, color: color[severity],
                        fontSize:11, fontWeight:700}}>
            {severity.toUpperCase()}
          </span>
        )}
      </h2>
      {chains.length === 0
        ? <div className="empty">No active attack chains</div>
        : chains.map((c, i) => (
          <div key={i} style={{
            border: `1px solid ${color[c.severity]}22`,
            borderLeft: `3px solid ${color[c.severity]}`,
            borderRadius: 6, padding: "10px 12px", marginBottom: 8,
            background: "#0d1018",
          }}>
            <div style={{display:"flex", justifyContent:"space-between", marginBottom:6}}>
              <span style={{color:"#fff", fontWeight:600, fontFamily:"monospace"}}>
                [{c.chain_id}]
              </span>
              <span style={{color: color[c.severity], fontWeight:700, fontSize:11}}>
                {c.severity.toUpperCase()}
              </span>
            </div>
            <div style={{color:"#00cfff", fontSize:12, marginBottom:4}}>
              Stage: {c.current_stage}
              {c.escalating && <span style={{color:"#ff4444", marginLeft:8}}>⚠ ESCALATING</span>}
            </div>
            <div style={{color:"#4a5568", fontSize:11, marginBottom:4}}>
              {c.event_count} events · {c.duration_s}s duration
            </div>
            <div style={{display:"flex", gap:6, flexWrap:"wrap"}}>
              {c.stages.map((s,j) => (
                <span key={j} style={{
                  background:"#151a27", color:"#c8d0e0",
                  padding:"2px 8px", borderRadius:10, fontSize:10,
                }}>
                  {s}
                </span>
              ))}
            </div>
            <div style={{marginTop:6, fontSize:11, color:"#4a5568"}}>
              Techniques: {c.techniques.join(", ")}
            </div>
          </div>
        ))
      }
    </div>
  );
}

export default function App() {
  return (
    <div className="app">
      <header className="header">
        <div className="logo">
          <span className="logo-ghost">◈</span>
          <span className="logo-text">Ghost IT</span>
          <span className="logo-sub">Autonomous Digital Immune System</span>
        </div>
        <div className="header-right">
          <span className="live-dot" />
          <span className="live-label">LIVE</span>
        </div>
      </header>

      <StatsBar />

      <div className="grid-2">
        <TopProcesses />
        <AlertFeed />
      </div>

      <ChainPanel />

      <EventFeed />
    </div>
  );
}
