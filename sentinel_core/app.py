import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st
import streamlit.components.v1 as components
from utils import page_setup, nav_bar, get_img_b64, BASE, get_motion_js
from engine import (run_vuln_scan, run_live_ids,
                    compute_risk_score, get_correlation_alerts,
                    get_process_deep_dive)

page_setup("Overview")
# nav_bar called after risk_score is computed below

# ── session state ─────────────────────────────────────────────────────────────
for key, default in [
    ("scan_vuln",      None),
    ("scan_ids",       None),
    ("prev_ids_conns", set()),   # conn_ids from last scan for delta
    ("new_conn_ids",   set()),   # connections that appeared this scan
    ("gone_conn_ids",  set()),   # connections that disappeared
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ── controls ──────────────────────────────────────────────────────────────────
col_btn, col_ids_btn, col_sp = st.columns([1, 1.3, 5])

with col_btn:
    if st.button("⚡ Full Scan", key="overview_scan"):
        with st.spinner("Running full system scan…"):
            st.session_state.scan_vuln = run_vuln_scan(limit_sw=20, cves_per_sw=2)
            prev = st.session_state.prev_ids_conns
            result = run_live_ids()
            curr   = {e["conn_id"] for e in result["events"]}
            st.session_state.new_conn_ids  = curr - prev
            st.session_state.gone_conn_ids = prev - curr
            st.session_state.prev_ids_conns = curr
            st.session_state.scan_ids = result

with col_ids_btn:
    if st.button("🔄 Refresh Connections", key="overview_ids"):
        with st.spinner("Scanning connections…"):
            prev   = st.session_state.prev_ids_conns
            result = run_live_ids()
            curr   = {e["conn_id"] for e in result["events"]}
            st.session_state.new_conn_ids   = curr - prev
            st.session_state.gone_conn_ids  = prev - curr
            st.session_state.prev_ids_conns = curr
            st.session_state.scan_ids = result

vd   = st.session_state.scan_vuln
id_  = st.session_state.scan_ids
new_conns  = st.session_state.new_conn_ids
gone_conns = st.session_state.gone_conn_ids

# ── derived values ────────────────────────────────────────────────────────────
vuln_summary  = vd["summary"]   if vd  else {"critical":0,"high":0,"medium":0,"low":0,"total":0}
ids_stats     = id_["stats"]    if id_ else {"total":0,"normal":0,"threat":0,"suspicious":0}
risk_score    = compute_risk_score(vuln_summary, ids_stats) if (vd or id_) else 0
corr_alerts   = get_correlation_alerts(vd, id_) if (vd and id_) else []

nav_bar("overview", risk_score=risk_score)

total_vulns   = vuln_summary["total"]
critical_n    = vuln_summary["critical"]
high_n        = vuln_summary["high"]
medium_n      = vuln_summary["medium"]
threat_n      = ids_stats.get("threat", 0)
suspicious_n  = ids_stats.get("suspicious", 0)
normal_n      = ids_stats.get("normal", 0)
total_conns   = ids_stats.get("total", 0)
scan_time_lbl = f"{vd['scan_time']}s" if vd else "—"

# risk gauge colour
if risk_score >= 70:
    gauge_color = "#ef4444"; gauge_label = "High Risk"; gauge_bg = "rgba(239,68,68,0.1)"
elif risk_score >= 40:
    gauge_color = "#f97316"; gauge_label = "Moderate"; gauge_bg = "rgba(249,115,22,0.1)"
elif risk_score > 0:
    gauge_color = "#eab308"; gauge_label = "Low Risk"; gauge_bg = "rgba(234,179,8,0.1)"
else:
    gauge_color = "#64748b"; gauge_label = "No Data"; gauge_bg = "rgba(100,116,139,0.08)"

# full circular gauge: needle rotates from -135° (0) to +135° (100)
needle_deg = round(-135 + (risk_score / 100) * 270, 1)
# arc: circumference of r=54 circle = 339.3, 270° = 75% of circle
gauge_full_c = 339.3
gauge_full_dash = round(risk_score / 100 * gauge_full_c * 0.75, 1)

# ── vuln donut ────────────────────────────────────────────────────────────────
C = 376.99
tot = max(total_vulns, 1)
c_arc = round(C * critical_n / tot, 1)
h_arc = round(C * high_n     / tot, 1)
m_arc = round(C * medium_n   / tot, 1)
h_off = -c_arc
m_off = -(c_arc + h_arc)

# ── top vulns ─────────────────────────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": ("#f87171","rgba(239,68,68,0.08)","rgba(239,68,68,0.2)"),
    "HIGH":     ("#fb923c","rgba(249,115,22,0.08)","rgba(249,115,22,0.2)"),
    "MEDIUM":   ("#fbbf24","rgba(245,158,11,0.08)","rgba(245,158,11,0.2)"),
    "LOW":      ("#4ade80","rgba(34,197,94,0.08)","rgba(34,197,94,0.2)"),
}
top_vulns = vd["results"][:4] if vd and vd["results"] else []
vuln_rows_html = ""
for v in top_vulns:
    sev = v.get("severity","MEDIUM")
    c, bg, border = SEV_COLOR.get(sev, ("#64748b","rgba(100,116,139,0.04)","rgba(100,116,139,0.15)"))
    is_win = "windows" in v["software"].lower() or "microsoft" in v["software"].lower()
    win_btn = (
        '<a href="ms-settings:windowsupdate" style="font-size:0.65rem;font-weight:600;'
        'color:#60a5fa;background:rgba(96,165,250,0.1);border:1px solid rgba(96,165,250,0.2);'
        'border-radius:6px;padding:2px 7px;text-decoration:none;white-space:nowrap;">🪟 Update</a>'
        if is_win else ""
    )
    fav_url = v.get("favicon_url", "")
    if fav_url:
        icon_html = (
            f'<img src="{fav_url}" width="22" height="22" '
            f'style="border-radius:5px;object-fit:contain;background:rgba(255,255,255,0.08);padding:2px;flex-shrink:0;" '
            f'onerror="this.style.display=\'none\';this.nextElementSibling.style.display=\'flex\';" />'
            f'<div style="display:none;width:22px;height:22px;border-radius:5px;flex-shrink:0;'
            f'background:rgba(45,212,191,0.15);color:#2dd4bf;font-size:0.65rem;font-weight:700;'
            f'align-items:center;justify-content:center;">{v["software"][0].upper()}</div>'
        )
    else:
        icon_html = (
            f'<div style="width:22px;height:22px;border-radius:5px;flex-shrink:0;'
            f'background:rgba(45,212,191,0.15);color:#2dd4bf;font-size:0.65rem;font-weight:700;'
            f'display:flex;align-items:center;justify-content:center;">{v["software"][0].upper()}</div>'
        )
    vuln_rows_html += f"""
    <div style="padding:10px 14px;display:flex;align-items:center;gap:12px;
      background:{bg};border:1px solid {border};border-radius:12px;margin-bottom:6px;">
      <div style="flex-shrink:0;display:flex;align-items:center;">{icon_html}</div>
      <div style="flex:1;min-width:0;">
        <div style="font-size:0.8rem;font-weight:600;color:#f1f5f9;white-space:nowrap;
          overflow:hidden;text-overflow:ellipsis;">{v['software']}</div>
        <div style="font-size:0.68rem;color:#64748b;">{v['cve']}</div>
      </div>
      <span style="font-size:0.68rem;font-weight:700;padding:2px 8px;border-radius:20px;
        background:rgba(0,0,0,0.2);color:{c};white-space:nowrap;">{sev}</span>
      {win_btn}
    </div>"""

no_vuln_html = "" if vuln_rows_html else (
    '<div style="padding:24px;text-align:center;color:#64748b;font-size:0.8rem;">'
    'Run ⚡ Full Scan to load vulnerability data</div>')

# ── IDS connection feed with delta ────────────────────────────────────────────
ids_events = id_["events"][:8] if id_ else []
ids_feed_html = ""
for ev in ids_events:
    is_new  = ev["conn_id"] in new_conns
    color   = ev["color"]
    bc      = {"Threat":"#ef4444","Suspicious":"#eab308","Warning":"#f97316"}.get(ev["prediction"],"#16a34a")
    new_tag = ('<span style="font-size:0.6rem;font-weight:700;padding:1px 6px;border-radius:6px;'
               'background:rgba(45,212,191,0.15);color:#2dd4bf;border:1px solid rgba(45,212,191,0.3);'
               'animation:newPulse 1s ease-in-out 3;" class="new-badge-pop">NEW</span>' if is_new else "")
    ids_feed_html += f"""
    <div style="border-left:3px solid {color};background:rgba(255,255,255,0.03);
      border-radius:0 10px 10px 0;padding:9px 12px;margin-bottom:7px;
      {'animation:slideIn 0.4s ease;' if is_new else ''}">
      <div style="display:flex;align-items:center;gap:7px;margin-bottom:4px;">
        <span style="font-size:0.95rem;">{ev['icon']}</span>
        <span style="font-size:0.78rem;font-weight:700;color:{color};">{ev['prediction']}</span>
        <span style="font-size:0.65rem;padding:1px 6px;border-radius:8px;
          background:rgba(255,255,255,0.07);color:#94a3b8;">{ev['category']}</span>
        {new_tag}
        <span style="margin-left:auto;font-size:0.65rem;color:#475569;font-family:monospace;">{ev['conn_id']}</span>
      </div>
      <div style="display:flex;gap:10px;font-size:0.68rem;flex-wrap:wrap;">
        <span><span style="color:#64748b;">proc</span> <strong style="color:#e2e8f0;">{ev['process']}</strong></span>
        <span><span style="color:#64748b;">svc</span> <strong style="color:#e2e8f0;">{ev['service']}</strong></span>
        <span style="color:{bc};font-weight:600;">{ev['confidence']}%</span>
      </div>
    </div>"""

no_ids_html = "" if ids_feed_html else (
    '<div style="padding:24px;text-align:center;color:#64748b;font-size:0.8rem;">'
    'Run ⚡ Full Scan or 🔄 Refresh Connections</div>')

# delta summary badge
delta_html = ""
if new_conns or gone_conns:
    delta_html = (
        f'<div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;">'
        f'{"".join(f"""<span style="font-size:0.68rem;font-weight:600;padding:2px 8px;border-radius:8px;background:rgba(45,212,191,0.1);color:#2dd4bf;border:1px solid rgba(45,212,191,0.2);">+{len(new_conns)} new</span>""" if new_conns else [])}'
        f'{"".join(f"""<span style="font-size:0.68rem;font-weight:600;padding:2px 8px;border-radius:8px;background:rgba(100,116,139,0.1);color:#64748b;border:1px solid rgba(100,116,139,0.2);">{len(gone_conns)} closed</span>""" if gone_conns else [])}'
        f'</div>'
    )

# ── correlation alerts HTML ───────────────────────────────────────────────────
corr_html = ""
for i, alert in enumerate(corr_alerts):
    sev_color = "#ef4444" if alert["severity"] == "critical" else "#f97316"
    sev_bg    = "rgba(239,68,68,0.07)" if alert["severity"] == "critical" else "rgba(249,115,22,0.07)"
    sev_border= "rgba(239,68,68,0.2)"  if alert["severity"] == "critical" else "rgba(249,115,22,0.2)"
    win_btn   = ""
    if alert.get("is_windows"):
        win_btn = (
            '<a href="ms-settings:windowsupdate" '
            'style="display:inline-block;margin-top:8px;font-size:0.7rem;font-weight:600;'
            'color:#60a5fa;background:rgba(96,165,250,0.1);border:1px solid rgba(96,165,250,0.25);'
            'border-radius:8px;padding:4px 12px;text-decoration:none;">🪟 Open Windows Update</a>'
        )
    delay = f"{i * 0.09:.2f}s"
    corr_html += f"""
    <div style="padding:14px 16px;background:{sev_bg};border:1px solid {sev_border};
      border-radius:12px;margin-bottom:10px;animation:springBounce 0.55s cubic-bezier(0.34,1.56,0.64,1) {delay} both;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
        <span style="font-size:1rem;">{alert['icon']}</span>
        <span style="font-size:0.8rem;font-weight:700;color:{sev_color};">{alert['title']}</span>
      </div>
      <div style="font-size:0.72rem;color:#cbd5e1;line-height:1.6;">{alert['detail']}</div>
      {win_btn}
    </div>"""

no_corr_html = "" if corr_html else (
    '<div style="padding:24px;text-align:center;color:#64748b;font-size:0.8rem;">'
    'Run both scans to see cross-feature alerts</div>')

# ── process deep dive (top flagged process) ───────────────────────────────────
top_proc_name = ""
if id_ and id_["events"]:
    flagged = [e for e in id_["events"] if e["prediction"] != "Normal"]
    if flagged:
        from collections import Counter
        top_proc_name = Counter(e["process"] for e in flagged).most_common(1)[0][0]

proc_dive_html = ""
if top_proc_name:
    dive = get_process_deep_dive(top_proc_name)
    for p in dive.get("processes", [])[:3]:
        trust_badge = (
            '<span style="font-size:0.62rem;padding:1px 6px;border-radius:6px;'
            'background:rgba(74,222,128,0.1);color:#4ade80;border:1px solid rgba(74,222,128,0.2);">Trusted</span>'
            if p["is_trusted"] else
            '<span style="font-size:0.62rem;padding:1px 6px;border-radius:6px;'
            'background:rgba(239,68,68,0.1);color:#f87171;border:1px solid rgba(239,68,68,0.2);">Unknown</span>'
        )
        exe_short = p["exe"][-40:] if len(p["exe"]) > 40 else p["exe"]
        proc_dive_html += f"""
        <div style="padding:12px 14px;background:rgba(255,255,255,0.03);
          border:1px solid rgba(255,255,255,0.08);border-radius:12px;margin-bottom:8px;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
            <span style="font-size:0.82rem;font-weight:700;color:#f1f5f9;">{p['name']}</span>
            <span style="font-size:0.65rem;color:#64748b;">PID {p['pid']}</span>
            {trust_badge}
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:8px;">
            <div style="text-align:center;padding:8px;background:rgba(255,255,255,0.03);border-radius:8px;">
              <div style="font-size:1rem;font-weight:700;color:#a5b4fc;">{p['cpu']}%</div>
              <div style="font-size:0.62rem;color:#64748b;">CPU</div>
            </div>
            <div style="text-align:center;padding:8px;background:rgba(255,255,255,0.03);border-radius:8px;">
              <div style="font-size:1rem;font-weight:700;color:#34d399;">{p['mem_mb']} MB</div>
              <div style="font-size:0.62rem;color:#64748b;">Memory</div>
            </div>
            <div style="text-align:center;padding:8px;background:rgba(255,255,255,0.03);border-radius:8px;">
              <div style="font-size:1rem;font-weight:700;color:#f97316;">{p['conn_count']}</div>
              <div style="font-size:0.62rem;color:#64748b;">Connections</div>
            </div>
          </div>
          <div style="font-size:0.65rem;color:#475569;font-family:monospace;
            overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">📁 {exe_short}</div>
        </div>"""

if not proc_dive_html:
    proc_dive_html = (
        '<div style="padding:24px;text-align:center;color:#64748b;font-size:0.8rem;">'
        'Scan connections to see process details</div>')

# risk-reactive blob colors
if risk_score >= 70:
    _blob1a = "rgba(239,68,68,0.18)";  _blob1b = "rgba(249,115,22,0.12)"
    _blob2a = "rgba(239,68,68,0.10)";  _blob2b = "rgba(249,115,22,0.08)"
elif risk_score >= 40:
    _blob1a = "rgba(249,115,22,0.15)"; _blob1b = "rgba(234,179,8,0.10)"
    _blob2a = "rgba(249,115,22,0.08)"; _blob2b = "rgba(234,179,8,0.06)"
elif risk_score > 0:
    _blob1a = "rgba(234,179,8,0.12)";  _blob1b = "rgba(99,102,241,0.08)"
    _blob2a = "rgba(99,102,241,0.08)"; _blob2b = "rgba(234,179,8,0.06)"
else:
    _blob1a = "rgba(20,184,166,0.12)"; _blob1b = "rgba(99,102,241,0.08)"
    _blob2a = "rgba(99,102,241,0.08)"; _blob2b = "rgba(20,184,166,0.06)"

img = get_img_b64()
img_data_uri = f"data:image/jpeg;base64,{img}"

# ── simulation banner ─────────────────────────────────────────────────────────
sim_banner = ""
if id_ and id_["stats"].get("mode") == "simulation":
    acc = id_["stats"].get("accuracy", 0)
    sim_banner = f"""
    <div style="padding:10px 16px;background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.25);
      border-radius:12px;margin-bottom:16px;display:flex;align-items:center;gap:10px;">
      <span style="font-size:1rem;">🧪</span>
      <span style="font-size:0.75rem;color:#a5b4fc;font-weight:600;">
        Simulation Mode — KDD dataset · Model accuracy {acc}% on this sample
      </span>
    </div>"""

# ── main HTML ─────────────────────────────────────────────────────────────────
html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{
    font-family:'Inter',sans-serif;
    min-height:100vh;color:#f1f5f9;
    overflow-x:hidden;
  }}
  body::before{{
    content:'';
    position:fixed;inset:0;z-index:-1;
    background:url('{img_data_uri}') center/cover no-repeat;
    animation:kenBurns 20s ease-in-out infinite alternate;
    transform-origin:center center;
  }}
  @keyframes kenBurns{{
    0%  {{transform:scale(1.0);}}
    100%{{transform:scale(1.06);}}
  }}
  .overlay{{
    min-height:100vh;
    background:linear-gradient(135deg,rgba(15,23,42,0.95) 0%,rgba(30,27,75,0.92) 50%,rgba(15,23,42,0.95) 100%);
    padding:24px 20px 40px;
    transition:opacity 0.2s ease;
    animation:pageFadeIn 0.2s ease both;
  }}
  @keyframes pageFadeIn{{from{{opacity:0;}}to{{opacity:1;}}}}
  .page-title{{font-size:1.4rem;font-weight:700;color:#f1f5f9;margin-bottom:4px;}}
  .page-sub{{font-size:0.78rem;color:#64748b;margin-bottom:20px;}}

  /* mesh blobs — risk-reactive colors via CSS vars */
  .mesh-bg{{position:fixed;top:-200px;right:-200px;width:700px;height:700px;border-radius:50%;
    background:radial-gradient(circle at 30% 30%,var(--blob1-a) 0%,var(--blob1-b) 40%,transparent 70%);
    animation:meshDrift 12s ease-in-out infinite alternate;pointer-events:none;z-index:0;}}
  .mesh-bg2{{position:fixed;bottom:-150px;left:-150px;width:500px;height:500px;border-radius:50%;
    background:radial-gradient(circle,var(--blob2-a) 0%,var(--blob2-b) 50%,transparent 70%);
    animation:meshDrift 16s ease-in-out infinite alternate-reverse;pointer-events:none;z-index:0;}}
  @keyframes meshDrift{{0%{{transform:translate(0,0) scale(1);}}100%{{transform:translate(30px,40px) scale(1.08);}}}}

  /* gauge */
  .gauge-wrap{{
    display:flex;flex-direction:column;align-items:center;
    padding:16px 16px 12px;
    background:rgba(255,255,255,0.04);
    border:1px solid rgba(255,255,255,0.08);
    border-radius:16px;margin-bottom:16px;
  }}  .gauge-label{{font-size:0.7rem;color:#64748b;margin-bottom:8px;letter-spacing:.05em;text-transform:uppercase;}}
  .gauge-score{{font-size:2.2rem;font-weight:800;margin-top:-10px;}}
  .gauge-status{{font-size:0.75rem;font-weight:600;margin-top:2px;}}

  /* stat pills */
  .pills{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;}}
  .pill{{
    flex:1;min-width:80px;
    padding:10px 12px;text-align:center;
    background:rgba(255,255,255,0.04);
    border:1px solid rgba(255,255,255,0.08);
    border-radius:12px;
    transition:transform 0.2s,box-shadow 0.2s,background 0.2s;
    cursor:default;
  }}
  .pill:hover{{
    transform:translateY(-3px);
    background:rgba(255,255,255,0.07);
    box-shadow:0 0 18px var(--pill-glow,rgba(45,212,191,0.25));
  }}
  .pill-val{{font-size:1.3rem;font-weight:700;}}
  .pill-lbl{{font-size:0.62rem;color:#64748b;margin-top:2px;}}

  /* grid */
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;}}
  @media(max-width:600px){{.grid{{grid-template-columns:1fr;}}}}

  /* cards */
  .card{{
    background:rgba(255,255,255,0.04);
    border:1px solid rgba(255,255,255,0.08);
    border-radius:16px;padding:16px;overflow:hidden;
  }}
  .card-title{{
    font-size:0.72rem;font-weight:700;color:#2dd4bf;
    text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px;
  }}

  /* donut */
  .donut-row{{display:flex;align-items:center;gap:16px;margin-bottom:12px;}}
  .donut-legend{{display:flex;flex-direction:column;gap:5px;}}
  .legend-item{{display:flex;align-items:center;gap:6px;font-size:0.7rem;color:#cbd5e1;}}
  .legend-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0;}}

  /* section */
  .section{{
    background:rgba(255,255,255,0.04);
    border:1px solid rgba(255,255,255,0.08);
    border-radius:16px;padding:16px;margin-bottom:14px;
  }}

  /* animations */
  @keyframes slideIn{{from{{opacity:0;transform:translateX(-8px)}}to{{opacity:1;transform:translateX(0)}}}}
  @keyframes newPulse{{0%,100%{{opacity:1}}50%{{opacity:0.4}}}}
  @keyframes waveAnim{{0%{{transform:scaleY(0.3)}}50%{{transform:scaleY(1)}}100%{{transform:scaleY(0.3)}}}}
  @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:0.5}}}}
  @keyframes fadeInUp{{from{{opacity:0;transform:translateY(16px)}}to{{opacity:1;transform:translateY(0)}}}}
  .fade-in{{animation:fadeInUp 0.5s ease both;}}
  .fade-in-1{{animation:fadeInUp 0.5s 0.05s ease both;}}
  .fade-in-2{{animation:fadeInUp 0.5s 0.12s ease both;}}
  .fade-in-3{{animation:fadeInUp 0.5s 0.20s ease both;}}
  .fade-in-4{{animation:fadeInUp 0.5s 0.28s ease both;}}

  /* gauge arc animation */
  @keyframes gaugeArcFill{{
    from{{stroke-dasharray:0 {gauge_full_c};}}
    to{{stroke-dasharray:{gauge_full_dash} {gauge_full_c};}}
  }}
  @keyframes needleSpin{{
    from{{transform:rotate(-135deg);}}
    to{{transform:rotate({needle_deg}deg);}}
  }}
  .gauge-arc{{animation:gaugeArcFill 1.1s cubic-bezier(0.22,1,0.36,1) 0.2s both;}}

  /* NEW badge pop */
  @keyframes newBadgePop{{
    0%{{transform:scale(0);opacity:0;}}
    60%{{transform:scale(1.25);opacity:1;}}
    100%{{transform:scale(1);opacity:1;}}
  }}
  .new-badge-pop{{animation:newBadgePop 0.4s cubic-bezier(0.34,1.56,0.64,1) both;}}

  /* correlation alert spring bounce */
  @keyframes springBounce{{
    0%{{opacity:0;transform:translateY(-14px) scale(0.95);}}
    60%{{opacity:1;transform:translateY(4px) scale(1.01);}}
    80%{{transform:translateY(-2px) scale(0.99);}}
    100%{{opacity:1;transform:translateY(0) scale(1);}}
  }}
  .spring-bounce{{animation:springBounce 0.55s cubic-bezier(0.34,1.56,0.64,1) both;}}

  /* pulse ring on threat items */
  @keyframes pulseRing{{
    0%{{box-shadow:0 0 0 0 rgba(239,68,68,0.5);}}
    70%{{box-shadow:0 0 0 8px rgba(239,68,68,0);}}
    100%{{box-shadow:0 0 0 0 rgba(239,68,68,0);}}
  }}

  /* waveform */
  .wave{{display:flex;align-items:center;gap:3px;height:28px;}}
  .wave-bar{{
    width:3px;border-radius:2px;
    background:linear-gradient(to top,#2dd4bf,#818cf8);
    animation:waveAnim 1.2s ease-in-out infinite;
  }}

  /* scan time */
  .scan-meta{{font-size:0.65rem;color:#475569;margin-top:10px;text-align:right;}}
</style>
</head>
<body style="--blob1-a:{_blob1a};--blob1-b:{_blob1b};--blob2-a:{_blob2a};--blob2-b:{_blob2b};">
<div class="mesh-bg"></div><div class="mesh-bg2"></div>
<div class="overlay">

  <div class="page-title fade-in">🛡 Sentinel Overview</div>
  <div class="page-sub fade-in">Real-time system security dashboard</div>

  {sim_banner}

  <!-- GAUGE + PILLS ROW -->
  <div class="fade-in-1" style="display:grid;grid-template-columns:minmax(160px,200px) 1fr;gap:14px;margin-bottom:14px;align-items:start;">

    <!-- Gauge -->
    <div class="gauge-wrap">
      <div class="gauge-label">Risk Score</div>
      <svg width="140" height="140" viewBox="0 0 140 140">
        <!-- track arc 270° starting from 135° -->
        <circle cx="70" cy="70" r="54"
          fill="none" stroke="rgba(255,255,255,0.07)" stroke-width="12"
          stroke-dasharray="{round(gauge_full_c*0.75,1)} {gauge_full_c}"
          stroke-dashoffset="{round(-gauge_full_c*0.375,1)}"
          stroke-linecap="round"/>
        <!-- fill arc animated -->
        <circle cx="70" cy="70" r="54"
          fill="none" stroke="{gauge_color}" stroke-width="12"
          stroke-dasharray="0 {gauge_full_c}"
          stroke-dashoffset="{round(-gauge_full_c*0.375,1)}"
          stroke-linecap="round"
          id="gaugeArc"
          style="filter:drop-shadow(0 0 6px {gauge_color});
            animation:gaugeArcFill 1.1s cubic-bezier(0.22,1,0.36,1) 0.2s forwards;"/>
        <!-- needle -->
        <g id="gaugeNeedle" style="transform-origin:70px 70px;
          transform:rotate({needle_deg}deg);
          animation:needleSpin 1.1s cubic-bezier(0.22,1,0.36,1) 0.2s both;">
          <line x1="70" y1="70" x2="70" y2="26"
            stroke="{gauge_color}" stroke-width="2.5" stroke-linecap="round"
            style="filter:drop-shadow(0 0 4px {gauge_color});"/>
          <circle cx="70" cy="70" r="5" fill="{gauge_color}"
            style="filter:drop-shadow(0 0 6px {gauge_color});"/>
          <circle cx="70" cy="70" r="2.5" fill="#0f172a"/>
        </g>
        <!-- score text -->
        <text x="70" y="95" text-anchor="middle"
          font-size="22" font-weight="800" fill="{gauge_color}"
          font-family="Inter,sans-serif">{risk_score}</text>
        <!-- tick marks -->
        <g stroke="rgba(255,255,255,0.15)" stroke-width="1.5">
          <line x1="70" y1="18" x2="70" y2="24" transform="rotate(-135 70 70)"/>
          <line x1="70" y1="18" x2="70" y2="24" transform="rotate(-90 70 70)"/>
          <line x1="70" y1="18" x2="70" y2="24" transform="rotate(-45 70 70)"/>
          <line x1="70" y1="18" x2="70" y2="24" transform="rotate(0 70 70)"/>
          <line x1="70" y1="18" x2="70" y2="24" transform="rotate(45 70 70)"/>
          <line x1="70" y1="18" x2="70" y2="24" transform="rotate(90 70 70)"/>
          <line x1="70" y1="18" x2="70" y2="24" transform="rotate(135 70 70)"/>
        </g>
      </svg>
      <div class="gauge-score" style="color:{gauge_color};display:none;">{risk_score}</div>
      <div class="gauge-status" style="color:{gauge_color};">{gauge_label}</div>
      <div style="font-size:0.62rem;color:#475569;margin-top:4px;">Scan time: {scan_time_lbl}</div>
    </div>

    <!-- Pills -->
    <div>
      <div class="pills">
        <div class="pill" style="--pill-glow:rgba(248,113,113,0.3);">
          <div class="pill-val counter" data-val="{critical_n}" style="color:#f87171;">{critical_n}</div>
          <div class="pill-lbl">Critical</div>
        </div>
        <div class="pill" style="--pill-glow:rgba(251,146,60,0.3);">
          <div class="pill-val counter" data-val="{high_n}" style="color:#fb923c;">{high_n}</div>
          <div class="pill-lbl">High</div>
        </div>
        <div class="pill" style="--pill-glow:rgba(251,191,36,0.3);">
          <div class="pill-val counter" data-val="{medium_n}" style="color:#fbbf24;">{medium_n}</div>
          <div class="pill-lbl">Medium</div>
        </div>
        <div class="pill" style="--pill-glow:rgba(239,68,68,0.3);">
          <div class="pill-val counter" data-val="{threat_n}" style="color:#ef4444;">{threat_n}</div>
          <div class="pill-lbl">Threats</div>
        </div>
        <div class="pill" style="--pill-glow:rgba(234,179,8,0.3);">
          <div class="pill-val counter" data-val="{suspicious_n}" style="color:#eab308;">{suspicious_n}</div>
          <div class="pill-lbl">Suspicious</div>
        </div>
        <div class="pill" style="--pill-glow:rgba(74,222,128,0.3);">
          <div class="pill-val counter" data-val="{normal_n}" style="color:#4ade80;">{normal_n}</div>
          <div class="pill-lbl">Normal</div>
        </div>
      </div>

      <!-- waveform -->
      <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;
        background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:12px;">
        <div class="wave" id="wave"></div>
        <span style="font-size:0.72rem;color:#94a3b8;">
          {total_conns} connections monitored &nbsp;·&nbsp;
          {ids_stats.get('established',0)} established &nbsp;·&nbsp;
          {ids_stats.get('listening',0)} listening
        </span>
      </div>
    </div>
  </div>

  <!-- MAIN GRID -->
  <div class="grid fade-in-2">

    <!-- LEFT: Vuln donut + top vulns -->
    <div class="card">
      <div class="card-title">🔍 Vulnerability Summary</div>

      <!-- donut -->
      <div class="donut-row">
        <svg width="90" height="90" viewBox="0 0 90 90">
          <circle cx="45" cy="45" r="30" fill="none"
            stroke="rgba(255,255,255,0.06)" stroke-width="14"/>
          <!-- low (remainder) -->
          <circle cx="45" cy="45" r="30" fill="none"
            stroke="#4ade80" stroke-width="14"
            stroke-dasharray="{C} {C}"
            stroke-dashoffset="0"
            transform="rotate(-90 45 45)"/>
          <!-- medium -->
          <circle cx="45" cy="45" r="30" fill="none"
            stroke="#fbbf24" stroke-width="14"
            stroke-dasharray="{m_arc} {C}"
            stroke-dashoffset="{m_off}"
            transform="rotate(-90 45 45)"/>
          <!-- high -->
          <circle cx="45" cy="45" r="30" fill="none"
            stroke="#fb923c" stroke-width="14"
            stroke-dasharray="{h_arc} {C}"
            stroke-dashoffset="{h_off}"
            transform="rotate(-90 45 45)"/>
          <!-- critical -->
          <circle cx="45" cy="45" r="30" fill="none"
            stroke="#f87171" stroke-width="14"
            stroke-dasharray="{c_arc} {C}"
            stroke-dashoffset="0"
            transform="rotate(-90 45 45)"/>
          <text x="45" y="49" text-anchor="middle"
            font-size="14" font-weight="700" fill="#f1f5f9"
            font-family="Inter,sans-serif">{total_vulns}</text>
        </svg>
        <div class="donut-legend">
          <div class="legend-item"><div class="legend-dot" style="background:#f87171;"></div>Critical ({critical_n})</div>
          <div class="legend-item"><div class="legend-dot" style="background:#fb923c;"></div>High ({high_n})</div>
          <div class="legend-item"><div class="legend-dot" style="background:#fbbf24;"></div>Medium ({medium_n})</div>
          <div class="legend-item"><div class="legend-dot" style="background:#4ade80;"></div>Low / Other</div>
        </div>
      </div>

      <!-- top vulns list -->
      {vuln_rows_html}
      {no_vuln_html}
    </div>

    <!-- RIGHT: IDS feed -->
    <div class="card">
      <div class="card-title">🌐 Connection Feed</div>
      {delta_html}
      {ids_feed_html}
      {no_ids_html}
    </div>

  </div>

  <!-- CORRELATION ALERTS -->
  <div class="section fade-in-3">
    <div class="card-title">⚡ Cross-Feature Alerts</div>
    {corr_html}
    {no_corr_html}
  </div>

  <!-- PROCESS DEEP DIVE -->
  <div class="section fade-in-4">
    <div class="card-title">🔬 Top Flagged Process</div>
    {"<div style='font-size:0.72rem;color:#64748b;margin-bottom:10px;'>Most active suspicious process from last IDS scan</div>" if top_proc_name else ""}
    {proc_dive_html}
  </div>

</div>

<script>
// waveform
(function(){{
  var w = document.getElementById('wave');
  if(!w) return;
  var bars = 18;
  for(var i=0;i<bars;i++){{
    var b = document.createElement('div');
    b.className = 'wave-bar';
    var h = 8 + Math.random()*18;
    b.style.height = h+'px';
    b.style.animationDelay = (i*0.07)+'s';
    b.style.animationDuration = (0.9+Math.random()*0.6)+'s';
    w.appendChild(b);
  }}
}})();

// number counters
(function(){{
  function easeOut(t){{ return 1 - Math.pow(1-t, 3); }}
  var els = document.querySelectorAll('.counter');
  els.forEach(function(el){{
    var target = parseInt(el.getAttribute('data-val'), 10) || 0;
    if(target === 0) return;
    var duration = 600, start = null;
    function step(ts){{
      if(!start) start = ts;
      var progress = Math.min((ts - start) / duration, 1);
      el.textContent = Math.round(easeOut(progress) * target);
      if(progress < 1) requestAnimationFrame(step);
      else el.textContent = target;
    }}
    requestAnimationFrame(step);
  }});
}})();
</script>
{get_motion_js(tilt_selector=".card", gsap_selector=".card,.section")}
</body>
</html>
"""

components.html(html, height=1100, scrolling=True)
