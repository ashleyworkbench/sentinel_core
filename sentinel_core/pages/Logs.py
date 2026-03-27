import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import streamlit.components.v1 as components
from utils import page_setup, nav_bar, get_img_b64
from engine import run_port_scan

page_setup("Port Exposure")

if "scan_ports" not in st.session_state:
    st.session_state.scan_ports = None

col_btn, _ = st.columns([1, 7])
with col_btn:
    if st.button("🔍 Scan Now", key="port_scan_btn"):
        with st.spinner("Checking your open doors..."):
            st.session_state.scan_ports = run_port_scan(socket_verify=True)

pd = st.session_state.scan_ports

_port_risk = 0
if pd:
    _port_risk = min((pd["critical_n"] * 30 + pd["high_n"] * 15 + pd["medium_n"] * 5), 100)
nav_bar("logs", risk_score=_port_risk)
ports_list = pd["ports"] if pd else []

attention = [p for p in ports_list if p["severity"] in ("CRITICAL","HIGH","MEDIUM")
             and p["status"] in ("exposed","blocked")]
reference = [p for p in ports_list if p not in attention]

total_listening = pd["total_listening"] if pd else 0
total_reachable = pd["total_reachable"] if pd else 0
critical_n      = pd["critical_n"]      if pd else 0
high_n          = pd["high_n"]          if pd else 0
medium_n        = pd["medium_n"]        if pd else 0
scan_time       = f"{pd['scan_time']}s" if pd else "---"

page_height = max(900, len(attention) * 220 + len(reference) * 44 + 680)
page_height = min(page_height, 4000)

# hero banner
if pd:
    risky_count = critical_n + high_n + medium_n
    if critical_n > 0:
        hc="#ef4444"; hbg="rgba(239,68,68,0.09)"; hbd="rgba(239,68,68,0.28)"; hi="🚨"
        ht=f"{total_reachable} open doors found — {risky_count} need your attention"
        hs="Some of these open connections could let an outsider into your computer."
    elif high_n > 0:
        hc="#f97316"; hbg="rgba(249,115,22,0.09)"; hbd="rgba(249,115,22,0.28)"; hi="⚠️"
        ht=f"{total_reachable} open doors found — {risky_count} worth reviewing"
        hs="Nothing critically dangerous, but a few connections are unusual and worth a look."
    elif medium_n > 0:
        hc="#eab308"; hbg="rgba(234,179,8,0.09)"; hbd="rgba(234,179,8,0.28)"; hi="📋"
        ht=f"{total_reachable} open doors found — {risky_count} to keep an eye on"
        hs="Low risk overall. A few connections are a bit unusual but not immediately dangerous."
    else:
        hc="#4ade80"; hbg="rgba(74,222,128,0.07)"; hbd="rgba(74,222,128,0.22)"; hi="✅"
        ht=f"{total_reachable} open doors found — all look normal"
        hs="No dangerous or unusual connections found. Your device looks clean."

    hero_html = (
        f'<div style="padding:22px 24px;background:{hbg};border:1px solid {hbd};border-radius:16px;margin-bottom:20px;">'
        f'<div style="display:flex;align-items:flex-start;gap:14px;">'
        f'<span style="font-size:1.8rem;line-height:1;flex-shrink:0;">{hi}</span>'
        f'<div style="flex:1;">'
        f'<div style="font-size:1.1rem;font-weight:800;color:{hc};line-height:1.3;margin-bottom:6px;">{ht}</div>'
        f'<div style="font-size:0.78rem;color:#94a3b8;line-height:1.6;margin-bottom:16px;">{hs}</div>'
        f'<div style="display:flex;gap:20px;flex-wrap:wrap;align-items:flex-end;">'
        f'<div style="text-align:center;"><div class="counter" data-val="{total_listening}" style="font-size:1.4rem;font-weight:800;color:#f1f5f9;">{total_listening}</div><div style="font-size:0.62rem;color:#64748b;">Listening</div></div>'
        f'<div style="width:1px;background:rgba(255,255,255,0.08);height:32px;"></div>'
        f'<div style="text-align:center;"><div class="counter" data-val="{total_reachable}" style="font-size:1.4rem;font-weight:800;color:#60a5fa;">{total_reachable}</div><div style="font-size:0.62rem;color:#64748b;">Reachable</div></div>'
        f'<div style="width:1px;background:rgba(255,255,255,0.08);height:32px;"></div>'
        f'<div style="text-align:center;"><div class="counter" data-val="{critical_n}" style="font-size:1.4rem;font-weight:800;color:#f87171;">{critical_n}</div><div style="font-size:0.62rem;color:#64748b;">Critical</div></div>'
        f'<div style="width:1px;background:rgba(255,255,255,0.08);height:32px;"></div>'
        f'<div style="text-align:center;"><div class="counter" data-val="{high_n}" style="font-size:1.4rem;font-weight:800;color:#fb923c;">{high_n}</div><div style="font-size:0.62rem;color:#64748b;">High</div></div>'
        f'<div style="width:1px;background:rgba(255,255,255,0.08);height:32px;"></div>'
        f'<div style="text-align:center;"><div class="counter" data-val="{medium_n}" style="font-size:1.4rem;font-weight:800;color:#fbbf24;">{medium_n}</div><div style="font-size:0.62rem;color:#64748b;">Medium</div></div>'
        f'<div style="margin-left:auto;"><div style="font-size:0.62rem;color:#475569;">scanned in {scan_time}</div></div>'
        f'</div></div></div></div>'
    )
else:
    hero_html = ""

SEV_COLOR = {
    "CRITICAL": ("#f87171","rgba(239,68,68,0.08)","rgba(239,68,68,0.22)"),
    "HIGH":     ("#fb923c","rgba(249,115,22,0.08)","rgba(249,115,22,0.22)"),
    "MEDIUM":   ("#fbbf24","rgba(245,158,11,0.08)","rgba(245,158,11,0.22)"),
    "LOW":      ("#94a3b8","rgba(100,116,139,0.05)","rgba(100,116,139,0.15)"),
    "INFO":     ("#60a5fa","rgba(96,165,250,0.06)","rgba(96,165,250,0.18)"),
    "SAFE":     ("#4ade80","rgba(34,197,94,0.04)","rgba(34,197,94,0.12)"),
}

# attention cards with door-open entrance animation
attention_html = ""
for idx, p in enumerate(attention):
    sev = p["severity"]
    c, bg, border = SEV_COLOR.get(sev, SEV_COLOR["INFO"])
    reach_badge = (
        f'<span style="font-size:0.65rem;font-weight:700;padding:3px 10px;border-radius:20px;'
        f'background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3);">⚡ Open to outside</span>'
        if p["reachable"] else
        f'<span style="font-size:0.65rem;font-weight:600;padding:3px 10px;border-radius:20px;'
        f'background:rgba(100,116,139,0.12);color:#94a3b8;border:1px solid rgba(100,116,139,0.22);">🛡 Firewall blocking</span>'
    )
    sev_badge = (
        f'<span style="font-size:0.65rem;font-weight:700;padding:3px 10px;border-radius:20px;'
        f'background:rgba(0,0,0,0.3);color:{c};">{sev}</span>'
    )
    door_delay = min(idx * 0.08, 0.64)
    # signal-strength bars: CRITICAL=4, HIGH=3, MEDIUM=2, LOW/INFO=1
    _sig_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 1, "SAFE": 0}
    _sig_n = _sig_map.get(sev, 1)
    _sig_bars = ""
    for _b in range(4):
        _bh = 6 + _b * 4
        _bc = c if _b < _sig_n else "rgba(255,255,255,0.1)"
        _glow = ("filter:drop-shadow(0 0 3px " + c + ");") if _b < _sig_n else ""
        _sig_bars += ('<div style="width:6px;height:' + str(_bh) + 'px;border-radius:2px;'
                      'background:' + _bc + ';align-self:flex-end;' + _glow + '"></div>')
    _signal_meter = ('<div style="display:flex;align-items:flex-end;gap:3px;margin-left:auto;"'
                     ' title="Exposure: ' + sev + '">' + _sig_bars + '</div>')
    attention_html += (
        f'<div class="attention-card" style="padding:18px 20px;background:{bg};border:1px solid {border};border-radius:14px;margin-bottom:12px;'
        f'animation:doorOpen 0.5s cubic-bezier(0.22,1,0.36,1) {door_delay:.2f}s both;">'
        f'<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px;">'
        f'<span style="font-size:1rem;font-weight:800;color:{c};font-family:monospace;background:rgba(0,0,0,0.3);padding:3px 10px;border-radius:8px;">:{p["port"]}</span>'
        f'<span style="font-size:0.88rem;font-weight:700;color:#f1f5f9;">{p["label"]}</span>'
        + f'{reach_badge}{sev_badge}' + _signal_meter +
        f'</div>'
        f'<div style="font-size:0.72rem;color:#64748b;margin-bottom:14px;">Owned by &nbsp;<strong style="color:#f1f5f9;font-size:0.78rem;">{p["process"]}</strong></div>'
        f'<div style="padding:14px 16px;background:rgba(0,0,0,0.35);border-radius:10px;border-left:3px solid {c};">'
        f'<div style="font-size:0.65rem;font-weight:700;color:#2dd4bf;margin-bottom:6px;text-transform:uppercase;letter-spacing:.07em;">What does this mean?</div>'
        f'<div style="font-size:0.75rem;color:#cbd5e1;line-height:1.75;">{p["attacker_view"]}</div>'
        f'</div></div>'
    )

no_attention_html = ("" if attention_html else
    '<div style="padding:28px;text-align:center;color:#4ade80;font-size:0.82rem;">✅ No risky ports found — your device looks clean</div>')

# reference rows grouped by status
from collections import defaultdict as _dd
ref_groups = _dd(list)
for p in reference:
    grp = ("🔵 Reachable (safe)" if p["reachable"]
           else ("🟢 Normal system port" if p["status"] == "expected" else "⚪ Internal only"))
    ref_groups[grp].append(p)

ref_sections_html = ""
for grp_label, grp_ports in ref_groups.items():
    rows = ""
    for i, p in enumerate(grp_ports):
        sev = p["severity"]
        c   = SEV_COLOR.get(sev, SEV_COLOR["SAFE"])[0]
        row_bg = "rgba(255,255,255,0.02)" if i % 2 == 0 else "transparent"
        rows += (
            f'<div style="display:flex;align-items:center;gap:14px;padding:8px 12px;background:{row_bg};border-radius:8px;"'
            f' onmouseover="this.style.background=\'rgba(255,255,255,0.05)\'"'
            f' onmouseout="this.style.background=\'{row_bg}\'">'
            f'<span style="font-size:0.78rem;font-weight:700;color:{c};font-family:monospace;min-width:52px;">:{p["port"]}</span>'
            f'<span style="font-size:0.75rem;color:#94a3b8;flex:1;">{p["label"]}</span>'
            f'<span style="font-size:0.68rem;color:#475569;">{p["process"]}</span>'
            f'</div>'
        )
    grp_id = grp_label.replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
    ref_sections_html += (
        f'<div style="margin-bottom:8px;">'
        f'<div onclick="toggleRefGrp(\'{grp_id}\')" style="display:flex;align-items:center;gap:8px;'
        f'padding:7px 12px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);'
        f'border-radius:10px;cursor:pointer;margin-bottom:4px;">'
        f'<span style="font-size:0.75rem;font-weight:600;color:#94a3b8;">{grp_label}</span>'
        f'<span style="font-size:0.68rem;color:#475569;background:rgba(255,255,255,0.05);padding:1px 7px;border-radius:8px;">{len(grp_ports)}</span>'
        f'<span id="arr_{grp_id}" style="margin-left:auto;font-size:0.7rem;color:#475569;">▾</span>'
        f'</div>'
        f'<div id="grp_{grp_id}">{rows}</div>'
        f'</div>'
    )

no_ref_html = ("" if ref_sections_html else
    '<div style="padding:20px;text-align:center;color:#475569;font-size:0.75rem;">Run a scan to see all ports</div>')

empty_html = ("" if pd else
    '<div style="padding:60px 24px;text-align:center;">'
    '<div style="font-size:3rem;margin-bottom:18px;">🔌</div>'
    '<div style="font-size:1.05rem;font-weight:700;color:#f1f5f9;margin-bottom:10px;">See what\'s open on your device</div>'
    '<div style="font-size:0.78rem;color:#64748b;max-width:380px;margin:0 auto;line-height:1.8;">'
    'This scan checks every open connection on your computer and tells you which ones '
    'an outsider could actually reach — like checking which doors in your house are unlocked from the outside.'
    '</div></div>')

attn_label = (f'<span style="font-size:0.68rem;color:#475569;font-weight:400;margin-left:6px;">({len(attention)})</span>' if pd else "")
ref_label  = (f'<span style="font-size:0.68rem;color:#475569;font-weight:400;margin-left:6px;">({len(reference)} — no action needed)</span>' if pd else "")

sections_html = ""
if pd:
    sections_html = (
        '<div class="fade-in-2" style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.11);'
        'border-radius:16px;padding:18px 20px;margin-bottom:14px;">'
        '<div style="font-size:0.7rem;font-weight:700;color:#2dd4bf;text-transform:uppercase;'
        'letter-spacing:.07em;margin-bottom:14px;display:flex;align-items:center;">'
        f'🚨 Needs Your Attention {attn_label}</div>'
        f'{attention_html}{no_attention_html}'
        '</div>'
        '<div class="fade-in-3" style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);'
        'border-radius:16px;padding:16px 18px;margin-bottom:14px;">'
        '<div style="font-size:0.7rem;font-weight:700;color:#2dd4bf;text-transform:uppercase;'
        'letter-spacing:.07em;margin-bottom:8px;display:flex;align-items:center;">'
        f'📋 All Other Ports {ref_label}</div>'
        '<div style="font-size:0.7rem;color:#475569;margin-bottom:12px;">Grouped by reachability — you can ignore these</div>'
        f'{ref_sections_html}{no_ref_html}'
        '</div>'
    )

img = get_img_b64()
img_data_uri = f"data:image/jpeg;base64,{img}"

html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{
    font-family:'Inter',sans-serif;
    background:url('{img_data_uri}') center/cover no-repeat fixed;
    min-height:100vh;color:#f1f5f9;
  }}
  .mesh-bg{{position:fixed;top:-200px;right:-200px;width:700px;height:700px;border-radius:50%;
    background:radial-gradient(circle at 30% 30%,rgba(20,184,166,0.12) 0%,rgba(99,102,241,0.08) 40%,transparent 70%);
    animation:meshDrift 12s ease-in-out infinite alternate;pointer-events:none;z-index:0;}}
  .mesh-bg2{{position:fixed;bottom:-150px;left:-150px;width:500px;height:500px;border-radius:50%;
    background:radial-gradient(circle,rgba(99,102,241,0.08) 0%,rgba(20,184,166,0.06) 50%,transparent 70%);
    animation:meshDrift 16s ease-in-out infinite alternate-reverse;pointer-events:none;z-index:0;}}
  @keyframes meshDrift{{0%{{transform:translate(0,0) scale(1);}}100%{{transform:translate(30px,40px) scale(1.08);}}}}
  @keyframes fadeInUp{{from{{opacity:0;transform:translateY(16px)}}to{{opacity:1;transform:translateY(0)}}}}
  @keyframes doorOpen{{
    0%{{opacity:0;transform:perspective(600px) rotateX(-12deg) translateY(10px);}}
    60%{{opacity:1;transform:perspective(600px) rotateX(2deg) translateY(-2px);}}
    100%{{opacity:1;transform:perspective(600px) rotateX(0deg) translateY(0);}}
  }}
  .fade-in{{animation:fadeInUp 0.5s ease both;}}
  .fade-in-1{{animation:fadeInUp 0.5s 0.08s ease both;}}
  .fade-in-2{{animation:fadeInUp 0.5s 0.16s ease both;}}
  .fade-in-3{{animation:fadeInUp 0.5s 0.24s ease both;}}
  .overlay{{
    position:relative;z-index:1;min-height:100vh;
    background:linear-gradient(135deg,rgba(15,23,42,0.95) 0%,rgba(30,27,75,0.92) 50%,rgba(15,23,42,0.95) 100%);
    padding:24px 22px 48px;
  }}
</style>
</head>
<body>
<div class="mesh-bg"></div><div class="mesh-bg2"></div>
<div class="overlay">
  <div class="fade-in" style="font-size:1.35rem;font-weight:700;color:#f1f5f9;margin-bottom:3px;">🔌 Port Exposure</div>
  <div class="fade-in" style="font-size:0.75rem;color:#475569;margin-bottom:20px;">
    Which doors on your computer are open — and which ones an outsider can actually walk through
  </div>
  <div class="fade-in-1">{empty_html}</div>
  <div class="fade-in-1">{hero_html}</div>
  {sections_html}
</div>
<script>
function toggleRefGrp(id) {{
  var el = document.getElementById('grp_' + id);
  var arr = document.getElementById('arr_' + id);
  if (!el) return;
  var hidden = el.style.display === 'none';
  el.style.display = hidden ? 'block' : 'none';
  if (arr) arr.textContent = hidden ? '▾' : '▸';
}}
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
</script>
</body>
</html>"""

components.html(html, height=page_height, scrolling=True)
