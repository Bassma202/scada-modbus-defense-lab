"""AETHER Observatory & Industrial Operations Web Dashboard (FastAPI)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

from aether.process import PROFILES, ProcessState


def create_app(evidence_path: str | Path = "evidence/aether_experiment_results.json") -> FastAPI:
    ev_file = Path(evidence_path)
    state_obs = ProcessState(profile="observatory")
    state_obs.step_physics()
    state_ind = ProcessState(profile="generic_industrial")
    state_ind.step_physics()
    states = {"observatory": state_obs, "generic_industrial": state_ind}

    app = FastAPI(title="AETHER — Industrial & Cyber-Physical Systems Security Engineering", version="2.0.0")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "healthy", "service": "aether-ics", "version": "2.0.0"}

    @app.get("/api/telemetry")
    def telemetry(profile: str = Query(default="observatory")) -> dict[str, Any]:
        st = states.get(profile, state_obs)
        return {"simulated_process": True, "telemetry": st.snapshot(), "limits": PROFILES.get(st.profile)}

    @app.get("/api/evidence")
    def evidence() -> dict[str, Any]:
        if ev_file.exists():
            return json.loads(ev_file.read_text(encoding="utf-8"))
        return {"status": "Run scripts/run_aether_experiments.py to generate live experimental evidence."}

    @app.get("/", response_class=HTMLResponse)
    def dashboard(profile: str = Query(default="observatory")) -> str:
        st = states.get(profile, state_obs)
        snap = st.snapshot()
        ev = evidence()
        tiers = ev.get("three_tier_comparison", {})
        lat = ev.get("latency_benchmark_ms", {})
        sur = ev.get("suricata_live_capture", {})
        tier_rows = "".join(
            f"<tr><td><strong>{k}</strong></td><td>{v.get('authorized_telemetry_ok')}</td>"
            f"<td>{v.get('overspeed_blocked')}</td><td>{v.get('unsafe_pump_trip_blocked')}</td></tr>"
            for k, v in tiers.items()
        ) or "<tr><td colspan='4'>No experiment results loaded yet.</td></tr>"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AETHER — Industrial &amp; Cyber-Physical Security</title>
<style>
  :root {{ --navy:#111B2B; --slate:#1C2B40; --steel:#778898; --brass:#B19A70; --ivory:#EAE5DA; --bg:#0E1522; --panel:#162235; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:var(--bg); color:var(--ivory); }}
  header {{ background:var(--navy); padding:22px 32px; border-bottom:2px solid var(--brass); display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; }}
  header h1 {{ font-size:20px; letter-spacing:1.4px; }}
  header p {{ font-size:12px; color:#A3B2C2; margin-top:4px; }}
  .tabs a {{ color:var(--ivory); text-decoration:none; font-size:12px; padding:6px 12px; border:1px solid #304561; margin-left:6px; }}
  .tabs a.active {{ background:var(--brass); color:#111B2B; font-weight:600; border-color:var(--brass); }}
  main {{ max-width:1160px; margin:24px auto; padding:0 24px 40px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(195px,1fr)); gap:14px; margin-bottom:22px; }}
  .card {{ background:var(--panel); border:1px solid #263954; padding:16px; }}
  .label {{ font-size:11px; text-transform:uppercase; letter-spacing:0.8px; color:var(--steel); }}
  .val {{ font-size:22px; font-weight:700; color:var(--ivory); margin-top:6px; }}
  .sub {{ font-size:12px; color:var(--brass); margin-top:4px; }}
  section {{ background:var(--panel); border:1px solid #263954; padding:18px 20px; margin-bottom:20px; }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:0.9px; color:var(--brass); border-bottom:1px solid #263954; padding-bottom:6px; margin-bottom:12px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #22344D; }}
  th {{ font-size:11px; text-transform:uppercase; color:var(--steel); }}
</style>
</head>
<body>
  <header>
    <div>
      <h1>AETHER — Industrial &amp; Cyber-Physical Security Engineering</h1>
      <p>{snap['profile_name']} · Process-Aware Modbus TCP Zero-Trust Gateway</p>
    </div>
    <div class="tabs">
      <a class="{'active' if snap['profile']=='observatory' else ''}" href="/?profile=observatory">Observatory Profile</a>
      <a class="{'active' if snap['profile']=='generic_industrial' else ''}" href="/?profile=generic_industrial">Generic Industrial Profile</a>
    </div>
  </header>
  <main>
    <div class="grid">
      <div class="card"><div class="label">Simulated Pump Speed</div><div class="val">{snap['target_rpm']} RPM</div><div class="sub">Mode: {snap['operating_mode']}</div></div>
      <div class="card"><div class="label">Coolant Pressure / Temp</div><div class="val">{snap['pressure_psi']} PSI · {snap['temperature_c']} °C</div><div class="sub">Flow: {snap['flow_lpm']} L/min</div></div>
      <div class="card"><div class="label">Measured Gateway p95 Latency</div><div class="val">{lat.get('p95_ms', 'N/A')} ms</div><div class="sub">p50: {lat.get('p50_ms', 'N/A')} ms · n={lat.get('sample_size', 0)}</div></div>
      <div class="card"><div class="label">Suricata Live Alerts</div><div class="val">{sur.get('alerts_triggered', 'Pending')}</div><div class="sub">{sur.get('suricata_version', 'Run live PCAP validation')}</div></div>
    </div>
    <section>
      <h2>3-Tier Defense Comparison (Real TCP Laboratory Experiments)</h2>
      <table>
        <thead><tr><th>Architecture Tier</th><th>Authorized Telemetry</th><th>Overspeed Blocked</th><th>Unsafe Pump Trip Blocked</th></tr></thead>
        <tbody>{tier_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""

    return app


app = create_app()
