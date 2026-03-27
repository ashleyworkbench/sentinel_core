import sys, json, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import streamlit.components.v1 as components
from utils import page_setup, nav_bar, get_img_b64, get_motion_js
from engine import run_live_ids, run_sim_ids

page_setup("Intrusion Detection")

# ── session state ─────────────────────────────────────────────────────────────
for key, default in [
    ("scan_ids",         None),
    ("auto_refresh",     False),
    ("refresh_interval", 15),
    ("last_refresh",     0.0),
    ("session_totals",   {"conns": 0, "normal": 0, "threats": 0, "suspicious": 0, "scans": 0}),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ── controls ──────────────────────────────────────────────────────────────────
col_scan, col_sim, col_auto, col_interval, col_export = st.columns([1, 1.4, 1, 1, 2])

with col_scan:
    run_now = st.button("🔍 Scan Live", key="ids_run")

with col_sim:
    run_sim = st.button("🧪 Test on Preset Model", key="ids_sim")

with col_auto:
    st.session_state.auto_refresh = st.toggle(
        "⟳ Auto", value=st.session_state.auto_refresh, key="ids_auto")

with col_interval:
    st.session_state.refresh_interval = st.selectbox(
        "Interval", [10, 15, 30, 60],
        index=[10, 15, 30, 60].index(st.session_state.refresh_interval),
        key="ids_interval", label_visibility="collapsed")

# ── trigger scan ──────────────────────────────────────────────────────────────
now      = time.time()
auto_due = (st.session_state.auto_refresh and
            (now - st.session_state.last_refresh) >= st.session_state.refresh_interval)

if run_sim:
    with st.spinner("Running simulation on KDD dataset…"):
        result = run_sim_ids(n=30)
    st.session_state.scan_ids     = result
    st.session_state.last_refresh = time.time()
    t = st.session_state.session_totals
    t["conns"]      += result["stats"]["total"]
    t["normal"]     += result["stats"]["normal"]
    t["threats"]    += result["stats"]["threat"]
    t["suspicious"] += result["stats"]["suspicious"]
    t["scans"]      += 1

elif run_now or auto_due:
    with st.spinner("Scanning live network connections…"):
        result = run_live_ids()
    st.session_state.scan_ids     = result
    st.session_state.last_refresh = time.time()
    t = st.session_state.session_totals
    t["conns"]      += result["stats"]["total"]
    t["normal"]     += result["stats"]["normal"]
    t["threats"]    += result["stats"]["threat"]
    t["suspicious"] += result["stats"]["suspicious"]
    t["scans"]      += 1

data   = st.session_state.scan_ids

# nav after data is available so risk can be derived
_ids_risk = 0
if data:
    _t = data["stats"]["threat"]; _s = data["stats"]["suspicious"]; _tot = max(data["stats"]["total"],1)
    _ids_risk = min(int((_t * 1.0 + _s * 0.4) / _tot * 100), 100)
nav_bar("intrusion", risk_score=_ids_risk)
events = data["events"] if data else []
stats  = data["stats"]  if data else {
    "total": 0, "normal": 0, "threat": 0, "suspicious": 0,
    "bytes_sent_mb": 0, "bytes_recv_mb": 0, "bandwidth_gbps": 0,
    "established": 0, "listening": 0, "accuracy": None,
    "cat_counts": {"Normal": 0, "Warning": 0, "Suspicious": 0, "Threat": 0},
    "mode": "live",
}
top_services  = data.get("top_services",  []) if data else []
top_protocols = data.get("top_protocols", []) if data else []
totals        = st.session_state.session_totals
scan_mode     = stats.get("mode", "live")

total_e      = stats["total"]
normal_n     = stats["normal"]
threat_n     = stats["threat"]
suspicious_n = stats["suspicious"]
bw           = stats["bandwidth_gbps"]
cats         = stats["cat_counts"]
sent_mb      = stats.get("bytes_sent_mb", 0)
recv_mb      = stats.get("bytes_recv_mb", 0)
estab        = stats.get("established", 0)
listen       = stats.get("listening", 0)
accuracy     = stats.get("accuracy")

# ── export ────────────────────────────────────────────────────────────────────
with col_export:
    if data:
        export_obj = {
            "scan_time":      data["scan_time"],
            "mode":           scan_mode,
            "stats":          stats,
            "session_totals": totals,
            "top_ports":      top_services,
            "top_processes":  top_protocols,
            "events": [
                {k: e[k] for k in
                 ("conn_id", "process", "pid", "local_port", "remote_ip",
                  "remote_port", "status", "protocol", "service",
                  "prediction", "category", "confidence", "threat_desc")}
                for e in events
            ],
        }
        st.download_button("📥 Export", json.dumps(export_obj, indent=2),
                           "sentinel_ids_report.json", "application/json",
                           key="ids_export_btn")

# ── countdown ─────────────────────────────────────────────────────────────────
if st.session_state.auto_refresh and data:
    elapsed   = time.time() - st.session_state.last_refresh
    remaining = max(0, int(st.session_state.refresh_interval - elapsed))
    st.caption(f"⟳ Next refresh in {remaining}s · scan #{totals['scans']}")

# ── header labels ─────────────────────────────────────────────────────────────
mode_label = "Simulation · KDD Dataset" if scan_mode == "simulation" else "Live · psutil"
acc_label  = f" · {accuracy}% model accuracy" if accuracy else ""
sub_lbl = (f"{mode_label} · {total_e} connections · {data['scan_time']}s{acc_label}"
           if data else "Live connection scanner · click Scan Live or Test on Preset Model")

badge_sim = ('<span style="font-size:0.72rem;font-weight:600;padding:3px 10px;border-radius:20px;'
             'background:rgba(168,85,247,0.15);color:#d8b4fe;border:1px solid rgba(168,85,247,0.3);">🧪 SIMULATION</span>')
badge_live = ('<span style="font-size:0.72rem;font-weight:600;padding:3px 10px;border-radius:20px;'
              'background:rgba(99,102,241,0.15);color:#a5b4fc;border:1px solid rgba(99,102,241,0.3);">IDS ACTIVE</span>')
badge_idle = ('<span style="font-size:0.72rem;font-weight:600;padding:3px 10px;border-radius:20px;'
              'background:rgba(100,116,139,0.1);color:#64748b;border:1px solid rgba(100,116,139,0.2);">○ AWAITING</span>')
badge = badge_sim if scan_mode == "simulation" and data else (badge_live if data else badge_idle)

attack_ratio = (threat_n + suspicious_n) / max(total_e, 1)

# ── category breakdown bars ───────────────────────────────────────────────────
cat_meta = {
    "Threat":     ("#ef4444", "🚨"),
    "Suspicious": ("#eab308", "🔍"),
    "Warning":    ("#f97316", "⚠️"),
}
cat_bars_html = ""
for cat, (color, icon) in cat_meta.items():
    count = cats.get(cat, 0)
    pct   = round(count / max(total_e, 1) * 100)
    cat_bars_html += f"""
    <div style="margin-bottom:10px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span>{icon}</span>
          <span style="font-size:0.78rem;font-weight:600;color:#e2e8f0;">{cat}</span>
        </div>
        <span style="font-size:0.75rem;font-weight:700;color:{color};">{count}</span>
      </div>
      <div style="height:6px;border-radius:4px;background:rgba(255,255,255,0.08);overflow:hidden;">
        <div style="width:{pct}%;height:100%;background:{color};border-radius:4px;transition:width 0.8s;"></div>
      </div>
    </div>"""

# ── top offending ports + processes ──────────────────────────────────────────
def _top_bar(name, attacks, total, color):
    pct = round(attacks / max(total, 1) * 100)
    return (f'<div style="margin-bottom:10px;">'
            f'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;">'
            f'<span style="font-size:0.75rem;font-weight:600;color:#e2e8f0;">{name}</span>'
            f'<span style="font-size:0.7rem;font-weight:700;color:{color};">{attacks} flagged</span></div>'
            f'<div style="height:5px;border-radius:3px;background:rgba(255,255,255,0.08);overflow:hidden;">'
            f'<div style="width:{pct}%;height:100%;background:{color};border-radius:3px;"></div></div></div>')

_svc_colors  = ["#ef4444", "#f97316", "#eab308", "#8b5cf6", "#06b6d4"]
_proc_colors = ["#f43f5e", "#a78bfa", "#34d399", "#fb923c", "#60a5fa"]

top_svc_html = "".join(
    _top_bar(s["name"], s["attacks"], s["total"], _svc_colors[i % len(_svc_colors)])
    for i, s in enumerate(top_services)
) if top_services else '<div style="color:#64748b;font-size:0.78rem;padding:12px 0;text-align:center;">No flagged ports yet</div>'

top_proc_html = "".join(
    _top_bar(p["name"], p["attacks"], p["total"], _proc_colors[i % len(_proc_colors)])
    for i, p in enumerate(top_protocols)
) if top_protocols else '<div style="color:#64748b;font-size:0.78rem;padding:12px 0;text-align:center;">No flagged processes yet</div>'

# ── connection cards ──────────────────────────────────────────────────────────
def _build_cards(evs, mode):
    html = ""
    for idx, ev in enumerate(evs):
        color     = ev["color"]
        conf_pct  = ev["confidence"]
        bar_color = {"Threat": "#ef4444", "Suspicious": "#eab308",
                     "Warning": "#f97316"}.get(ev["prediction"], "#16a34a")
        cid_safe  = ev["conn_id"].replace("-", "_")
        status_col = {"ESTABLISHED": "#4ade80", "LISTEN": "#60a5fa",
                      "CLOSE_WAIT": "#f97316", "SYN_SENT": "#eab308",
                      "SF": "#4ade80", "S0": "#f97316", "REJ": "#ef4444",
                      "RSTO": "#f97316", "SH": "#eab308"}.get(ev["status"], "#94a3b8")
        flags_html = "".join(
            f'<div style="font-size:0.7rem;color:#fbbf24;margin-top:4px;">⚑ {f}</div>'
            for f in ev.get("all_flags", []))

        # stagger delay capped at 0.6s
        entrance_delay = min(idx * 0.055, 0.6)

        # pulse ring only on Threat cards
        is_threat = ev["prediction"] == "Threat"
        pulse_style = (
            f'--threat-color:{color};animation:cardSlideIn 0.4s cubic-bezier(0.22,1,0.36,1) {entrance_delay:.2f}s both, '
            f'threatPulseRing 2.2s ease-in-out {entrance_delay + 0.5:.2f}s 3;'
        ) if is_threat else (
            f'animation:cardSlideIn 0.4s cubic-bezier(0.22,1,0.36,1) {entrance_delay:.2f}s both;'
        )

        # sim mode shows src/dst bytes; live mode shows ports
        if mode == "simulation":
            detail_row = (
                f'<div style="font-size:0.72rem;"><span style="color:#64748b;">Protocol</span> '
                f'<strong style="color:#e2e8f0;">{ev["protocol"]}</strong></div>'
                f'<div style="font-size:0.72rem;"><span style="color:#64748b;">Service</span> '
                f'<strong style="color:#e2e8f0;">{ev["service"]}</strong></div>'
                f'<div style="font-size:0.72rem;"><span style="color:#64748b;">Flag</span> '
                f'<strong style="color:{status_col};">{ev["status"]}</strong></div>'
                f'<div style="font-size:0.72rem;"><span style="color:#64748b;">Data sent</span> '
                f'<strong style="color:#e2e8f0;">{ev["src_bytes"]:,} B</strong></div>'
                f'<div style="font-size:0.72rem;"><span style="color:#64748b;">Data received</span> '
                f'<strong style="color:#e2e8f0;">{ev["dst_bytes"]:,} B</strong></div>'
            )
            kdd_badge = (
                f'<span style="font-size:0.65rem;padding:1px 7px;border-radius:8px;'
                f'background:rgba(168,85,247,0.1);color:#d8b4fe;border:1px solid rgba(168,85,247,0.2);">'
                f'KDD: {ev.get("kdd_category","")}</span>'
            )
        else:
            detail_row = (
                f'<div style="font-size:0.72rem;"><span style="color:#64748b;">Process</span> '
                f'<strong style="color:#e2e8f0;">{ev["process"]}</strong>'
                f'<span style="color:#475569;font-size:0.65rem;"> (pid {ev["pid"]})</span></div>'
                f'<div style="font-size:0.72rem;"><span style="color:#64748b;">Proto</span> '
                f'<strong style="color:#e2e8f0;">{ev["protocol"].upper()}</strong></div>'
                f'<div style="font-size:0.72rem;"><span style="color:#64748b;">Service</span> '
                f'<strong style="color:#e2e8f0;">{ev["service"]}</strong></div>'
                f'<div style="font-size:0.72rem;"><span style="color:#64748b;">Local</span> '
                f'<strong style="color:#e2e8f0;">:{ev["local_port"]}</strong></div>'
                f'<div style="font-size:0.72rem;"><span style="color:#64748b;">Remote</span> '
                f'<strong style="color:#e2e8f0;">{ev["remote_ip"]}:{ev["remote_port"]}</strong></div>'
            )
            kdd_badge = ""

        html += f"""
    <div style="border-left:4px solid {color};
      background:{'rgba(239,68,68,0.08)' if ev['prediction']=='Threat' else 'rgba(234,179,8,0.05)' if ev['prediction']=='Suspicious' else 'rgba(249,115,22,0.04)' if ev['prediction']=='Warning' else 'rgba(255,255,255,0.03)'};
      border-radius:0 12px 12px 0;padding:12px 16px;margin-bottom:10px;
      box-shadow:0 2px 8px rgba(0,0,0,0.2);transition:transform 0.15s,box-shadow 0.15s;
      {pulse_style}"
      onmouseover="this.style.transform='translateX(4px)';this.style.boxShadow='0 4px 16px rgba(0,0,0,0.3)'"
      onmouseout="this.style.transform='';this.style.boxShadow='0 2px 8px rgba(0,0,0,0.2)'">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:1.1rem;">{ev['icon']}</span>
          <span style="font-size:0.82rem;font-weight:700;color:{color};">{ev['prediction']}</span>
          <span style="font-size:0.7rem;font-weight:600;padding:2px 8px;border-radius:10px;
            background:rgba(255,255,255,0.08);color:#94a3b8;">{ev['category']}</span>
          {kdd_badge}
        </div>
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="font-size:0.68rem;color:#64748b;font-family:monospace;">{ev['conn_id']}</span>
          <span style="font-size:0.68rem;font-weight:600;color:{status_col};
            padding:1px 7px;border-radius:8px;background:rgba(255,255,255,0.05);">{ev['status']}</span>
        </div>
      </div>
      <div style="display:flex;gap:14px;margin-bottom:8px;flex-wrap:wrap;">{detail_row}</div>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
        <span style="font-size:0.68rem;color:#64748b;white-space:nowrap;">Confidence</span>
        <div style="flex:1;height:5px;border-radius:4px;background:rgba(255,255,255,0.08);overflow:hidden;">
          <div style="width:{conf_pct}%;height:100%;background:{bar_color};border-radius:4px;"></div>
        </div>
        <span style="font-size:0.72rem;font-weight:700;color:{bar_color};min-width:38px;">{conf_pct}%</span>
      </div>
      <div style="font-size:0.7rem;color:#94a3b8;margin-bottom:4px;">{ev['threat_desc']}</div>
      {flags_html}
      <div style="margin-top:8px;">
        <button onclick="toggleExplain('{cid_safe}')"
          style="font-size:0.7rem;font-weight:600;color:#2dd4bf;background:rgba(45,212,191,0.08);
          border:1px solid rgba(45,212,191,0.2);border-radius:8px;padding:4px 10px;cursor:pointer;">
          💬 What does this mean?
        </button>
        <div id="explain_{cid_safe}" style="display:none;margin-top:8px;padding:12px;
          background:rgba(45,212,191,0.05);border:1px solid rgba(45,212,191,0.15);border-radius:10px;">
          <div style="font-size:0.75rem;color:#cbd5e1;line-height:1.7;">{ev['plain_english']}</div>
        </div>
      </div>
    </div>"""
    return html

cards_html = _build_cards(events, scan_mode)
no_cards   = "" if cards_html else """
  <div style="padding:48px;text-align:center;color:#64748b;font-size:0.85rem;">
    No data yet — click 🔍 Scan Live or 🧪 Test on Preset Model
  </div>"""

# ── session totals HTML ───────────────────────────────────────────────────────
sess_html = f"""
<div style="display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap;">
  <div style="flex:1;min-width:100px;padding:12px 16px;border-radius:12px;
    background:rgba(45,212,191,0.06);border:1px solid rgba(45,212,191,0.15);text-align:center;">
    <div style="font-size:1.1rem;font-weight:700;color:#2dd4bf;">{totals['scans']}</div>
    <div style="font-size:0.68rem;color:#64748b;margin-top:2px;">Scans This Session</div>
  </div>
  <div style="flex:1;min-width:100px;padding:12px 16px;border-radius:12px;
    background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.15);text-align:center;">
    <div style="font-size:1.1rem;font-weight:700;color:#a5b4fc;">{totals['conns']}</div>
    <div style="font-size:0.68rem;color:#64748b;margin-top:2px;">Connections Seen</div>
  </div>
  <div style="flex:1;min-width:100px;padding:12px 16px;border-radius:12px;
    background:rgba(74,222,128,0.06);border:1px solid rgba(74,222,128,0.15);text-align:center;">
    <div style="font-size:1.1rem;font-weight:700;color:#4ade80;">{totals['normal']}</div>
    <div style="font-size:0.68rem;color:#64748b;margin-top:2px;">Normal (total)</div>
  </div>
  <div style="flex:1;min-width:100px;padding:12px 16px;border-radius:12px;
    background:rgba(234,179,8,0.06);border:1px solid rgba(234,179,8,0.15);text-align:center;">
    <div style="font-size:1.1rem;font-weight:700;color:#fbbf24;">{totals['suspicious']}</div>
    <div style="font-size:0.68rem;color:#64748b;margin-top:2px;">Suspicious (total)</div>
  </div>
  <div style="flex:1;min-width:100px;padding:12px 16px;border-radius:12px;
    background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.15);text-align:center;">
    <div style="font-size:1.1rem;font-weight:700;color:#f87171;">{totals['threats']}</div>
    <div style="font-size:0.68rem;color:#64748b;margin-top:2px;">Threats (total)</div>
  </div>
</div>"""

# ── sim mode banner ───────────────────────────────────────────────────────────
sim_banner = ""
if scan_mode == "simulation":
    acc_txt = f" · Model accuracy on this sample: {accuracy}%" if accuracy else ""
    sim_banner = f"""
<div style="margin-bottom:20px;padding:14px 18px;border-radius:12px;
  background:rgba(168,85,247,0.08);border:1px solid rgba(168,85,247,0.2);">
  <div style="display:flex;align-items:center;gap:8px;">
    <span style="font-size:1rem;">🧪</span>
    <span style="font-size:0.82rem;font-weight:600;color:#d8b4fe;">Simulation Mode</span>
    <span style="font-size:0.75rem;color:#94a3b8;margin-left:4px;">{acc_txt}</span>
  </div>
  <div style="font-size:0.72rem;color:#94a3b8;margin-top:6px;line-height:1.5;">
    This is a demonstration using real attack data from a cybersecurity research dataset (KDD Cup).
    It shows how the system would classify different types of harmful network activity.
    The connections shown are not from your computer — they are pre-recorded examples.
  </div>
</div>"""

img = get_img_b64()
img_data_uri = f"data:image/jpeg;base64,{img}"

# risk-reactive blob colors
if _ids_risk >= 70:
    _blob1a="rgba(239,68,68,0.18)";  _blob1b="rgba(249,115,22,0.12)"
    _blob2a="rgba(239,68,68,0.10)";  _blob2b="rgba(249,115,22,0.08)"
elif _ids_risk >= 40:
    _blob1a="rgba(249,115,22,0.15)"; _blob1b="rgba(234,179,8,0.10)"
    _blob2a="rgba(249,115,22,0.08)"; _blob2b="rgba(234,179,8,0.06)"
elif _ids_risk > 0:
    _blob1a="rgba(234,179,8,0.12)";  _blob1b="rgba(99,102,241,0.08)"
    _blob2a="rgba(99,102,241,0.08)"; _blob2b="rgba(234,179,8,0.06)"
else:
    _blob1a="rgba(20,184,166,0.12)"; _blob1b="rgba(99,102,241,0.08)"
    _blob2a="rgba(99,102,241,0.08)"; _blob2b="rgba(20,184,166,0.06)"

# ── main HTML ─────────────────────────────────────────────────────────────────
html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"/>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:'Inter',-apple-system,sans-serif;
  min-height:100vh;overflow-x:hidden;}}
body::before{{content:'';position:fixed;inset:0;z-index:-1;
  background:url('{img_data_uri}') center/cover no-repeat;
  animation:kenBurns 20s ease-in-out infinite alternate;transform-origin:center center;}}
@keyframes kenBurns{{0%{{transform:scale(1.0);}}100%{{transform:scale(1.06);}}}}
body::after{{content:'';position:fixed;inset:0;
  background:linear-gradient(135deg,rgba(15,23,42,0.93) 0%,rgba(30,27,75,0.90) 50%,rgba(15,23,42,0.93) 100%);
  z-index:0;pointer-events:none;}}
.mesh-bg{{position:fixed;top:-200px;right:-200px;width:700px;height:700px;border-radius:50%;
  background:radial-gradient(circle at 30% 30%,var(--blob1-a) 0%,var(--blob1-b) 40%,transparent 70%);
  animation:meshDrift 12s ease-in-out infinite alternate;pointer-events:none;z-index:0;}}
.mesh-bg2{{position:fixed;bottom:-150px;left:-150px;width:500px;height:500px;border-radius:50%;
  background:radial-gradient(circle,var(--blob2-a) 0%,var(--blob2-b) 50%,transparent 70%);
  animation:meshDrift 16s ease-in-out infinite alternate-reverse;pointer-events:none;z-index:0;}}
@keyframes meshDrift{{0%{{transform:translate(0,0) scale(1);}}100%{{transform:translate(30px,40px) scale(1.08);}}}}
.main{{position:relative;z-index:1;padding:28px 32px;
  animation:pageFadeIn 0.2s ease both;}}
@keyframes pageFadeIn{{from{{opacity:0;}}to{{opacity:1;}}}}
.glass-card{{backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);
  border-radius:18px;box-shadow:0 4px 24px rgba(0,0,0,0.3);padding:22px;
  transition:transform 0.25s,box-shadow 0.25s;}}
.glass-card:hover{{transform:translateY(-3px);box-shadow:0 12px 40px rgba(0,0,0,0.4);}}
.stat-pill{{backdrop-filter:blur(16px);background:rgba(255,255,255,0.05);
  border:1px solid rgba(255,255,255,0.1);border-radius:14px;
  box-shadow:0 4px 24px rgba(0,0,0,0.3);padding:14px 20px;
  display:flex;align-items:center;gap:12px;flex:1;min-width:120px;
  transition:transform 0.25s,box-shadow 0.25s;}}
.stat-pill:hover{{transform:translateY(-3px);
  box-shadow:0 0 20px var(--pill-glow,rgba(45,212,191,0.25));}}
@keyframes statusPulse{{0%,100%{{box-shadow:0 0 0 0 rgba(20,184,166,0.5);}}50%{{box-shadow:0 0 0 6px rgba(20,184,166,0);}}}}
@keyframes suspBlink{{0%{{opacity:1;}}100%{{opacity:0.3;}}}}
@keyframes blockedPulse{{0%{{transform:scale(1);}}100%{{transform:scale(1.5);}}}}
@keyframes cardSlideIn{{from{{opacity:0;transform:translateX(-14px)}}to{{opacity:1;transform:translateX(0)}}}}
@keyframes threatPulseRing{{
  0%{{box-shadow:inset 4px 0 0 0 var(--threat-color,#ef4444), 0 0 0 0 var(--threat-color,#ef4444);}}
  50%{{box-shadow:inset 4px 0 0 0 var(--threat-color,#ef4444), 0 0 0 8px rgba(0,0,0,0);}}
  100%{{box-shadow:inset 4px 0 0 0 var(--threat-color,#ef4444), 0 0 0 0 rgba(0,0,0,0);}}
}}
@keyframes counterUp{{from{{opacity:0;transform:translateY(6px)}}to{{opacity:1;transform:translateY(0)}}}}
</style></head><body style="--blob1-a:{_blob1a};--blob1-b:{_blob1b};--blob2-a:{_blob2a};--blob2-b:{_blob2b};">
<div class="mesh-bg"></div><div class="mesh-bg2"></div>
<div class="main">

  <!-- header -->
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
    <div>
      <h1 style="font-size:1.5rem;font-weight:700;color:#f1f5f9;letter-spacing:-0.4px;">📡 Intrusion Detection System</h1>
      <div style="font-size:0.82rem;color:#94a3b8;margin-top:3px;">{sub_lbl}</div>
    </div>
    {badge}
  </div>

  {sim_banner}

  <!-- session totals -->
  {sess_html}

  <!-- per-scan stat pills -->
  <div style="display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap;">
    <div class="stat-pill" style="--pill-glow:rgba(241,245,249,0.2);">
      <div style="font-size:1.5rem;">🔗</div>
      <div><div class="counter" data-val="{total_e}" style="font-size:1.25rem;font-weight:700;color:#f1f5f9;">{total_e}</div>
        <div style="font-size:0.72rem;color:#94a3b8;">Connections</div></div>
    </div>
    <div class="stat-pill" style="--pill-glow:rgba(74,222,128,0.3);">
      <div style="font-size:1.5rem;">✅</div>
      <div><div class="counter" data-val="{normal_n}" style="font-size:1.25rem;font-weight:700;color:#4ade80;">{normal_n}</div>
        <div style="font-size:0.72rem;color:#94a3b8;">Normal</div></div>
    </div>
    <div class="stat-pill" style="--pill-glow:rgba(251,191,36,0.3);">
      <div style="font-size:1.5rem;">🔍</div>
      <div><div class="counter" data-val="{suspicious_n}" style="font-size:1.25rem;font-weight:700;color:#fbbf24;">{suspicious_n}</div>
        <div style="font-size:0.72rem;color:#94a3b8;">Suspicious</div></div>
    </div>
    <div class="stat-pill" style="--pill-glow:rgba(248,113,113,0.3);">
      <div style="font-size:1.5rem;">🚨</div>
      <div><div class="counter" data-val="{threat_n}" style="font-size:1.25rem;font-weight:700;color:#f87171;">{threat_n}</div>
        <div style="font-size:0.72rem;color:#94a3b8;">Threats</div></div>
    </div>
    <div class="stat-pill" style="--pill-glow:rgba(74,222,128,0.3);">
      <div style="font-size:1.5rem;">🟢</div>
      <div><div class="counter" data-val="{estab}" style="font-size:1.25rem;font-weight:700;color:#4ade80;">{estab}</div>
        <div style="font-size:0.72rem;color:#94a3b8;">Established</div></div>
    </div>
    <div class="stat-pill" style="--pill-glow:rgba(96,165,250,0.3);">
      <div style="font-size:1.5rem;">👂</div>
      <div><div class="counter" data-val="{listen}" style="font-size:1.25rem;font-weight:700;color:#60a5fa;">{listen}</div>
        <div style="font-size:0.72rem;color:#94a3b8;">Listening</div></div>
    </div>
    <div class="stat-pill" style="--pill-glow:rgba(241,245,249,0.15);">
      <div style="font-size:1.5rem;">📡</div>
      <div><div class="counter" data-val="{int(recv_mb)}" style="font-size:1.25rem;font-weight:700;color:#f1f5f9;">{recv_mb:,}</div>
        <div style="font-size:0.72rem;color:#94a3b8;">MB Received</div></div>
    </div>
  </div>

  <!-- waveform + breakdown -->
  <div style="display:grid;grid-template-columns:1fr 280px;gap:20px;margin-bottom:20px;">
    <div class="glass-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
        <div style="font-size:0.9rem;font-weight:700;color:#f1f5f9;">
          {'Simulated Traffic Stream' if scan_mode == 'simulation' else 'Live Connection Activity'}
        </div>
        <div style="display:flex;align-items:center;gap:6px;font-size:0.72rem;color:#64748b;">
          <div style="width:7px;height:7px;border-radius:50%;background:#14b8a6;
            animation:statusPulse 2s ease-in-out infinite;"></div>
          {total_e} connections
        </div>
      </div>
      <div style="position:relative;height:130px;border-radius:12px;overflow:hidden;
        background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);">
        <svg id="waveformSvg" width="100%" height="130" preserveAspectRatio="none"
          style="position:absolute;top:0;left:0;">
          <path id="wave1" fill="none" stroke="rgba(20,184,166,0.6)"  stroke-width="2.5"/>
          <path id="wave2" fill="none" stroke="rgba(139,92,246,0.5)"  stroke-width="2"/>
          <path id="wave3" fill="none" stroke="rgba(239,68,68,0.45)"  stroke-width="2"/>
          <path id="wave1fill" fill="rgba(20,184,166,0.07)"/>
          <path id="wave2fill" fill="rgba(139,92,246,0.05)"/>
          <path id="wave3fill" fill="rgba(239,68,68,0.04)"/>
        </svg>
      </div>
      <div style="display:flex;gap:16px;margin-top:10px;">
        <div style="display:flex;align-items:center;gap:5px;font-size:0.7rem;color:#94a3b8;">
          <div style="width:14px;height:2.5px;background:rgba(20,184,166,0.8);border-radius:2px;"></div>Normal
        </div>
        <div style="display:flex;align-items:center;gap:5px;font-size:0.7rem;color:#94a3b8;">
          <div style="width:14px;height:2px;background:rgba(139,92,246,0.8);border-radius:2px;"></div>Suspicious
        </div>
        <div style="display:flex;align-items:center;gap:5px;font-size:0.7rem;color:#94a3b8;">
          <div style="width:14px;height:2px;background:rgba(239,68,68,0.8);border-radius:2px;"></div>Threat
        </div>
      </div>
    </div>
    <div class="glass-card">
      <div style="font-size:0.9rem;font-weight:700;color:#f1f5f9;margin-bottom:16px;">Threat Breakdown</div>
      {cat_bars_html if cat_bars_html else '<div style="color:#64748b;font-size:0.82rem;padding:20px 0;text-align:center;">Run a scan to see breakdown</div>'}
      <div style="margin-top:12px;padding-top:12px;border-top:1px solid rgba(255,255,255,0.06);">
        <div style="display:flex;justify-content:space-between;font-size:0.72rem;color:#94a3b8;">
          <span>Clean connections</span>
          <span style="font-weight:700;color:#4ade80;">{normal_n}</span>
        </div>
      </div>
    </div>
  </div>

  <!-- top offending ports + processes -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">
    <div class="glass-card">
      <div style="font-size:0.9rem;font-weight:700;color:#2dd4bf;margin-bottom:14px;">
        {'🌐 Top Flagged Services' if scan_mode == 'simulation' else '🔌 Top Flagged Ports / Services'}
      </div>
      {top_svc_html}
    </div>
    <div class="glass-card">
      <div style="font-size:0.9rem;font-weight:700;color:#2dd4bf;margin-bottom:14px;">
        {'📶 Top Flagged Protocols' if scan_mode == 'simulation' else '⚙️ Top Flagged Processes'}
      </div>
      {top_proc_html}
    </div>
  </div>

  <!-- flow mini-cards + connection feed -->
  <div style="display:grid;grid-template-columns:200px 1fr;gap:20px;">
    <div style="display:flex;flex-direction:column;gap:12px;">
      <div class="glass-card" style="padding:14px;background:rgba(22,163,74,0.06);border:1px solid rgba(22,163,74,0.2);">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:8px;">
          <div style="width:7px;height:7px;border-radius:50%;background:#16a34a;animation:statusPulse 2s ease-in-out infinite;"></div>
          <span style="font-size:0.8rem;font-weight:600;color:#f1f5f9;">Normal</span>
          <span style="margin-left:auto;font-size:0.68rem;color:#4ade80;font-weight:600;">{normal_n}</span>
        </div>
        <svg width="100%" height="26" id="waveAuth"><path id="authPath" fill="none" stroke="#16a34a" stroke-width="2"/></svg>
      </div>
      <div class="glass-card" style="padding:14px;background:rgba(234,179,8,0.06);border:1px solid rgba(234,179,8,0.2);">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:8px;">
          <div style="width:7px;height:7px;border-radius:50%;background:#eab308;animation:suspBlink 0.7s ease-in-out infinite alternate;"></div>
          <span style="font-size:0.8rem;font-weight:600;color:#f1f5f9;">Suspicious</span>
          <span style="margin-left:auto;font-size:0.68rem;color:#fbbf24;font-weight:600;">{suspicious_n}</span>
        </div>
        <svg width="100%" height="26" id="waveSusp"><path id="suspPath" fill="none" stroke="#eab308" stroke-width="2"/></svg>
      </div>
      <div class="glass-card" style="padding:14px;background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.2);">
        <div style="display:flex;align-items:center;gap:7px;margin-bottom:8px;">
          <div style="width:7px;height:7px;border-radius:50%;background:#ef4444;animation:blockedPulse 0.4s ease-in-out infinite alternate;"></div>
          <span style="font-size:0.8rem;font-weight:600;color:#f1f5f9;">Threats</span>
          <span style="margin-left:auto;font-size:0.68rem;color:#f87171;font-weight:600;">{threat_n}</span>
        </div>
        <svg width="100%" height="26" id="waveBlock"><path id="blockPath" fill="none" stroke="#ef4444" stroke-width="2"/></svg>
      </div>
    </div>

    <div class="glass-card">
      <div style="font-size:0.78rem;font-weight:600;color:#64748b;letter-spacing:0.5px;margin-bottom:14px;">
        {'SIMULATION FEED' if scan_mode == 'simulation' else 'LIVE CONNECTION FEED'} — {total_e} entries
      </div>
      {cards_html}{no_cards}
    </div>
  </div>

</div>
<script>
const ATTACK_RATIO = {attack_ratio};
let t=0, ft=0;

function toggleExplain(id) {{
  const el = document.getElementById('explain_' + id);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}}

// number counters
(function() {{
  function easeOut(t) {{ return 1 - Math.pow(1-t, 3); }}
  document.querySelectorAll('.counter').forEach(function(el) {{
    var target = parseInt(el.getAttribute('data-val'), 10) || 0;
    if (target === 0) return;
    var duration = 650, start = null;
    function step(ts) {{
      if (!start) start = ts;
      var p = Math.min((ts - start) / duration, 1);
      el.textContent = Math.round(easeOut(p) * target);
      if (p < 1) requestAnimationFrame(step);
      else el.textContent = target;
    }}
    requestAnimationFrame(step);
  }});
}})();

function buildWave(svgEl, pathEl, fillEl, amp, freq, speed, phase, yBase, H) {{
  const W = svgEl.getBoundingClientRect().width || svgEl.parentElement.getBoundingClientRect().width || 600;
  let d = `M 0 ${{yBase}}`, df = `M 0 ${{H}}`;
  for (let x = 0; x <= W; x += 3) {{
    const y = yBase + amp * Math.sin((x/W)*freq*Math.PI*2 + t*speed + phase);
    d += ` L ${{x}} ${{y}}`; df += ` L ${{x}} ${{y}}`;
  }}
  df += ` L ${{W}} ${{H}} Z`;
  pathEl.setAttribute('d', d);
  if (fillEl) fillEl.setAttribute('d', df);
}}
function animateMain() {{
  t += 0.018;
  const svg = document.getElementById('waveformSvg');
  buildWave(svg, document.getElementById('wave1'), document.getElementById('wave1fill'),
    10 + 18*(1-ATTACK_RATIO), 2.2, 0.8, 0, 65, 130);
  buildWave(svg, document.getElementById('wave2'), document.getElementById('wave2fill'),
    12 + 8*ATTACK_RATIO, 3.8, 1.6, 1.2, 65, 130);
  buildWave(svg, document.getElementById('wave3'), document.getElementById('wave3fill'),
    6 + 28*ATTACK_RATIO, 5.5, 2.8, 2.5, 65, 130);
  requestAnimationFrame(animateMain);
}}

function buildFlow(svgEl, pathEl, type) {{
  const W = svgEl.getBoundingClientRect().width || svgEl.parentElement.getBoundingClientRect().width || 180;
  const H = 26, mid = H/2;
  let d = `M 0 ${{mid}}`;
  for (let x = 0; x <= W; x += 2) {{
    let y;
    if (type==='auth') {{
      y = mid + 7*Math.sin((x/W)*3*Math.PI + ft*1.0);
    }} else if (type==='susp') {{
      y = mid + 6*Math.sin((x/W)*5*Math.PI + ft*1.8) + (Math.random()-0.5)*2;
    }} else {{
      const pos = ((x/W*4 + ft*2.2) % 1);
      if      (pos < 0.04) y = mid - 16*Math.sin(pos/0.04*Math.PI);
      else if (pos < 0.07) y = mid + 9*Math.sin((pos-0.04)/0.03*Math.PI);
      else if (pos < 0.10) y = mid - 7*Math.sin((pos-0.07)/0.03*Math.PI);
      else                 y = mid + Math.sin(pos*18*Math.PI)*Math.exp(-(pos-0.10)*18);
    }}
    d += ` L ${{x}} ${{y}}`;
  }}
  pathEl.setAttribute('d', d);
}}
function animateFlows() {{
  ft += 0.022;
  buildFlow(document.getElementById('waveAuth'),  document.getElementById('authPath'),  'auth');
  buildFlow(document.getElementById('waveSusp'),  document.getElementById('suspPath'),  'susp');
  buildFlow(document.getElementById('waveBlock'), document.getElementById('blockPath'), 'block');
  requestAnimationFrame(animateFlows);
}}

// ResizeObserver: start animations only once SVGs have real dimensions
(function() {{
  const mainSvg = document.getElementById('waveformSvg');
  if (!mainSvg) {{ animateMain(); animateFlows(); return; }}
  const ro = new ResizeObserver(function(entries) {{
    for (const e of entries) {{
      if (e.contentRect.width > 0) {{
        ro.disconnect();
        animateMain();
        animateFlows();
        return;
      }}
    }}
  }});
  ro.observe(mainSvg.parentElement || mainSvg);
  setTimeout(function() {{ animateMain(); animateFlows(); }}, 300);
}})();
</script>
{get_motion_js(tilt_selector=".glass-card:not([style*='border-left'])", gsap_selector=".glass-card,.stat-pill")}
</body></html>"""

components.html(html, height=1320, scrolling=True)

# ── auto-refresh rerun ────────────────────────────────────────────────────────
if st.session_state.auto_refresh:
    elapsed   = time.time() - st.session_state.last_refresh
    remaining = max(0.5, st.session_state.refresh_interval - elapsed)
    time.sleep(min(remaining, 1.0))
    st.rerun()
