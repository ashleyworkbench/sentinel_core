from pathlib import Path
import base64
import streamlit as st

BASE = Path(__file__).parent

_IMG_B64_CACHE: str = ""

def get_img_b64() -> str:
    global _IMG_B64_CACHE
    if not _IMG_B64_CACHE:
        img_path = BASE / "images" / "ui.jpeg"
        _IMG_B64_CACHE = base64.b64encode(img_path.read_bytes()).decode()
    return _IMG_B64_CACHE

# ── SVG icon set (#16) ────────────────────────────────────────────────────────
SVG_ICONS = {
    "shield": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    "warning": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    "lock": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>',
    "globe": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>',
    "alert": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    "cpu": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>',
    "activity": '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>',
    "siren": '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L8 6H4v4l-2 2v4h20v-4l-2-2V6h-4L12 2z"/><line x1="12" y1="10" x2="12" y2="14"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>',
}

def svg_icon(name: str, color: str = "currentColor", size: int = 16) -> str:
    """Return an inline SVG icon string with given color and size."""
    raw = SVG_ICONS.get(name, SVG_ICONS["alert"])
    return raw.replace('width="16"', f'width="{size}"').replace('height="16"', f'height="{size}"').replace('stroke="currentColor"', f'stroke="{color}"')

# ── Known app favicon map (#17) ───────────────────────────────────────────────
_FAVICON_MAP = {
    "chrome":       "https://www.google.com/favicon.ico",
    "firefox":      "https://www.mozilla.org/favicon.ico",
    "msedge":       "https://www.microsoft.com/favicon.ico",
    "edge":         "https://www.microsoft.com/favicon.ico",
    "code":         "https://code.visualstudio.com/favicon.ico",
    "vscode":       "https://code.visualstudio.com/favicon.ico",
    "spotify":      "https://open.spotify.com/favicon.ico",
    "discord":      "https://discord.com/favicon.ico",
    "slack":        "https://slack.com/favicon.ico",
    "zoom":         "https://zoom.us/favicon.ico",
    "teams":        "https://teams.microsoft.com/favicon.ico",
    "steam":        "https://store.steampowered.com/favicon.ico",
    "python":       "https://www.python.org/favicon.ico",
    "node":         "https://nodejs.org/favicon.ico",
    "git":          "https://git-scm.com/favicon.ico",
    "docker":       "https://www.docker.com/favicon.ico",
    "postman":      "https://www.postman.com/favicon.ico",
    "figma":        "https://www.figma.com/favicon.ico",
    "notion":       "https://www.notion.so/favicon.ico",
    "obsidian":     "https://obsidian.md/favicon.ico",
    "vlc":          "https://www.videolan.org/favicon.ico",
    "brave":        "https://brave.com/favicon.ico",
    "opera":        "https://www.opera.com/favicon.ico",
    "vivaldi":      "https://vivaldi.com/favicon.ico",
    "1password":    "https://1password.com/favicon.ico",
    "bitwarden":    "https://bitwarden.com/favicon.ico",
}

def get_favicon_img(process_name: str) -> str:
    """Return an <img> tag for a known app, or empty string."""
    key = process_name.lower().replace(".exe", "").replace(" ", "")
    for app, url in _FAVICON_MAP.items():
        if app in key:
            return f'<img src="{url}" width="16" height="16" style="border-radius:3px;vertical-align:middle;margin-right:4px;" onerror="this.style.display=\'none\'">'
    return ""

def page_setup(title: str):
    st.set_page_config(
        page_title=f"{title} · Sentinel Core",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
        #MainMenu, header, footer { visibility: hidden; }
        .block-container { padding: 0 !important; max-width: 100% !important; }
        section[data-testid="stSidebar"] { display: none; }
        [data-testid="stAppViewContainer"] { background: #0f172a; }

        /* ── Streamlit button → glassmorphic style ── */
        .stButton > button {
            background: rgba(45,212,191,0.08) !important;
            border: 1px solid rgba(45,212,191,0.25) !important;
            color: #2dd4bf !important;
            border-radius: 10px !important;
            font-family: 'Inter', sans-serif !important;
            font-size: 0.8rem !important;
            font-weight: 600 !important;
            padding: 6px 16px !important;
            transition: all 0.2s ease !important;
            position: relative !important;
            overflow: hidden !important;
        }
        .stButton > button:hover {
            background: rgba(45,212,191,0.16) !important;
            border-color: rgba(45,212,191,0.45) !important;
            color: #f1f5f9 !important;
            transform: translateY(-1px) !important;
            box-shadow: 0 4px 16px rgba(45,212,191,0.15) !important;
        }
        .stButton > button:active {
            transform: translateY(0) !important;
        }
        .stButton > button::after {
            content: '' !important;
            position: absolute !important;
            inset: 0 !important;
            background: radial-gradient(circle at center, rgba(45,212,191,0.35) 0%, transparent 70%) !important;
            transform: scale(0) !important;
            opacity: 0 !important;
            border-radius: 10px !important;
            transition: transform 0.5s ease, opacity 0.5s ease !important;
        }
        .stButton > button:active::after {
            transform: scale(2.5) !important;
            opacity: 1 !important;
            transition: transform 0s, opacity 0s !important;
        }
        /* download button */
        .stDownloadButton > button {
            background: rgba(96,165,250,0.08) !important;
            border: 1px solid rgba(96,165,250,0.25) !important;
            color: #60a5fa !important;
            border-radius: 10px !important;
            font-family: 'Inter', sans-serif !important;
            font-size: 0.8rem !important;
            font-weight: 600 !important;
            padding: 6px 16px !important;
            transition: all 0.2s ease !important;
        }
        .stDownloadButton > button:hover {
            background: rgba(96,165,250,0.16) !important;
            border-color: rgba(96,165,250,0.45) !important;
            color: #f1f5f9 !important;
        }
        .stToggle label { color: #94a3b8 !important; font-size: 0.8rem !important; }
        .stSelectbox > div > div {
            background: rgba(255,255,255,0.05) !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
            color: #f1f5f9 !important;
            border-radius: 8px !important;
        }
        .stSpinner > div { border-top-color: #2dd4bf !important; }
        .stCaption { color: #475569 !important; font-size: 0.72rem !important; }

        /* ── Skeleton loader ── */
        @keyframes skeletonShimmer {
            0%   { background-position: -400px 0; }
            100% { background-position: 400px 0; }
        }
        .skeleton-line {
            height: 14px; border-radius: 6px; margin-bottom: 10px;
            background: linear-gradient(90deg,
                rgba(255,255,255,0.04) 25%,
                rgba(255,255,255,0.10) 50%,
                rgba(255,255,255,0.04) 75%);
            background-size: 800px 100%;
            animation: skeletonShimmer 1.4s ease-in-out infinite;
        }
        .skeleton-card {
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 14px; padding: 18px; margin-bottom: 12px;
        }
        .skeleton-title { height: 18px; width: 40%; border-radius: 6px; margin-bottom: 14px;
            background: linear-gradient(90deg,
                rgba(255,255,255,0.06) 25%,
                rgba(255,255,255,0.12) 50%,
                rgba(255,255,255,0.06) 75%);
            background-size: 800px 100%;
            animation: skeletonShimmer 1.4s ease-in-out infinite;
        }

        /* ── Page transition cross-fade ── */
        .overlay, [data-testid="stAppViewContainer"] > div {
            animation: pageFadeIn 0.2s ease both;
        }
        @keyframes pageFadeIn {
            from { opacity: 0; }
            to   { opacity: 1; }
        }

        /* ── Ken Burns background zoom ── */
        @keyframes kenBurns {
            0%   { transform: scale(1.0); }
            100% { transform: scale(1.06); }
        }

        /* ── Scan progress bar ── */
        #sentinel-progress-bar {
            position: fixed;
            top: 0; left: 0;
            height: 3px;
            width: 0%;
            background: linear-gradient(90deg, #2dd4bf, #818cf8, #2dd4bf);
            background-size: 200% 100%;
            z-index: 9999;
            border-radius: 0 2px 2px 0;
            box-shadow: 0 0 10px rgba(45,212,191,0.6);
            transition: width 0.1s linear;
            animation: progressShimmer 1.5s linear infinite;
            display: none;
        }
        @keyframes progressShimmer {
            0%   { background-position: 200% 0; }
            100% { background-position: -200% 0; }
        }
    </style>
    """, unsafe_allow_html=True)


def get_skeleton_html(n_cards: int = 3) -> str:
    """Returns a pulsing skeleton placeholder HTML for use inside iframes while scanning."""
    cards = ""
    for i in range(n_cards):
        w1 = 30 + (i * 17) % 40
        w2 = 50 + (i * 13) % 35
        cards += f"""
        <div class="skeleton-card">
            <div class="skeleton-title" style="width:{w1}%;"></div>
            <div class="skeleton-line" style="width:100%;"></div>
            <div class="skeleton-line" style="width:{w2}%;"></div>
            <div class="skeleton-line" style="width:80%;"></div>
        </div>"""
    return f"""
    <style>
    @keyframes skeletonShimmer{{
        0%{{background-position:-400px 0;}}100%{{background-position:400px 0;}}
    }}
    .skeleton-card{{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);
        border-radius:14px;padding:18px;margin-bottom:12px;}}
    .skeleton-title,.skeleton-line{{border-radius:6px;margin-bottom:10px;
        background:linear-gradient(90deg,rgba(255,255,255,0.04) 25%,rgba(255,255,255,0.10) 50%,rgba(255,255,255,0.04) 75%);
        background-size:800px 100%;animation:skeletonShimmer 1.4s ease-in-out infinite;}}
    .skeleton-title{{height:18px;}}
    .skeleton-line{{height:12px;}}
    </style>
    <div style="padding:20px;">{cards}</div>"""


def get_motion_js(tilt_selector: str = ".sw-card", gsap_selector: str = ".sw-card") -> str:
    """
    Returns the full motion JS block:
    - Particle field (canvas, floating dots + connecting lines)
    - Card 3D tilt on mousemove
    - GSAP staggered entrance
    - Glowing border sweep on hover (CSS injected)
    - Radar sweep line (injected into .gauge-wrap if present)
    """
    return f"""
<canvas id="particleCanvas" style="position:fixed;top:0;left:0;width:100%;height:100%;
  z-index:0;pointer-events:none;opacity:0.55;"></canvas>

<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js"></script>
<script>
// ── Particle field ────────────────────────────────────────────────────────────
(function(){{
  var canvas = document.getElementById('particleCanvas');
  if(!canvas) return;
  var ctx = canvas.getContext('2d');
  function resize(){{
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
  }}
  resize();
  window.addEventListener('resize', resize);

  var N = 55;
  var dots = [];
  for(var i=0;i<N;i++){{
    dots.push({{
      x:  Math.random() * canvas.width,
      y:  Math.random() * canvas.height,
      vx: (Math.random()-0.5)*0.35,
      vy: (Math.random()-0.5)*0.35,
      r:  Math.random()*1.8+0.6
    }});
  }}

  function drawParticles(){{
    ctx.clearRect(0,0,canvas.width,canvas.height);
    for(var i=0;i<dots.length;i++){{
      var d=dots[i];
      d.x+=d.vx; d.y+=d.vy;
      if(d.x<0||d.x>canvas.width)  d.vx*=-1;
      if(d.y<0||d.y>canvas.height) d.vy*=-1;
      ctx.beginPath();
      ctx.arc(d.x,d.y,d.r,0,Math.PI*2);
      ctx.fillStyle='rgba(45,212,191,0.55)';
      ctx.fill();
    }}
    for(var i=0;i<dots.length;i++){{
      for(var j=i+1;j<dots.length;j++){{
        var dx=dots[i].x-dots[j].x, dy=dots[i].y-dots[j].y;
        var dist=Math.sqrt(dx*dx+dy*dy);
        if(dist<110){{
          ctx.beginPath();
          ctx.moveTo(dots[i].x,dots[i].y);
          ctx.lineTo(dots[j].x,dots[j].y);
          ctx.strokeStyle='rgba(45,212,191,'+(0.12*(1-dist/110))+')';
          ctx.lineWidth=0.5;
          ctx.stroke();
        }}
      }}
    }}
    requestAnimationFrame(drawParticles);
  }}
  drawParticles();
}})();

// ── Card 3D tilt ──────────────────────────────────────────────────────────────
(function(){{
  document.querySelectorAll('{tilt_selector}').forEach(function(card){{
    card.style.transition='transform 0.1s ease,box-shadow 0.1s ease';
    card.addEventListener('mousemove',function(e){{
      var r=card.getBoundingClientRect();
      var x=(e.clientX-r.left)/r.width -0.5;
      var y=(e.clientY-r.top) /r.height-0.5;
      card.style.transform='perspective(700px) rotateY('+(x*4)+'deg) rotateX('+(-y*4)+'deg) translateZ(3px)';
    }});
    card.addEventListener('mouseleave',function(){{
      card.style.transition='transform 0.6s cubic-bezier(0.34,1.56,0.64,1),box-shadow 0.6s ease';
      card.style.transform='perspective(700px) rotateY(0deg) rotateX(0deg) translateZ(0px)';
    }});
  }});
}})();

// ── GSAP staggered entrance ───────────────────────────────────────────────────
(function(){{
  if(typeof gsap==='undefined') return;
  gsap.from('{gsap_selector}',{{
    opacity:0, y:28, stagger:0.07,
    duration:0.55, ease:'power3.out',
    clearProps:'all'
  }});
  // stat pills float
  gsap.to('.stat-pill,.pill',{{
    y:-3, duration:2.2, ease:'sine.inOut',
    yoyo:true, repeat:-1, stagger:0.25
  }});
}})();

// ── Radar sweep on gauge ──────────────────────────────────────────────────────
(function(){{
  var wrap = document.querySelector('.gauge-wrap');
  if(!wrap) return;
  wrap.style.position='relative';
  wrap.style.overflow='hidden';
  var sweep = document.createElement('div');
  sweep.style.cssText=(
    'position:absolute;top:0;left:0;width:100%;height:3px;'
    +'background:linear-gradient(90deg,transparent,rgba(45,212,191,0.7),transparent);'
    +'animation:radarSweep 2.4s linear infinite;pointer-events:none;'
  );
  var style=document.createElement('style');
  style.textContent='@keyframes radarSweep{{0%{{top:0;opacity:0.8;}}100%{{top:100%;opacity:0;}}}}';
  document.head.appendChild(style);
  wrap.appendChild(sweep);
}})();
</script>

<style>
/* ── Glowing border sweep on hover ── */
@keyframes borderGlow {{
  0%   {{ box-shadow: 0 0 0 0 rgba(45,212,191,0); border-color: rgba(255,255,255,0.1); }}
  50%  {{ box-shadow: 0 0 20px 2px rgba(45,212,191,0.2); border-color: rgba(45,212,191,0.5); }}
  100% {{ box-shadow: 0 0 0 0 rgba(45,212,191,0); border-color: rgba(255,255,255,0.1); }}
}}
{tilt_selector}:hover {{
  animation: borderGlow 1.8s ease-in-out infinite !important;
}}
/* ensure cards sit above particle canvas */
.main, .overlay {{ position:relative; z-index:1; }}
.glass-card, .sw-card, .stat-pill, .pill, .card, .section {{
  position:relative; z-index:1;
}}
</style>
"""


def nav_bar(active: str, risk_score: int = 0):
    pages = {
        "Overview":             "/",
        "Vulnerability":        "/Vulnerability",
        "Intrusion Detection":  "/Intrusion_Detection",
        "Port Exposure":        "/Logs",
    }
    label_to_key = {
        "Overview": "overview",
        "Vulnerability": "vulnerability",
        "Intrusion Detection": "intrusion",
        "Port Exposure": "logs",
    }
    links_html = ""
    for label, href in pages.items():
        key = label_to_key[label]
        cls = "nav-active" if key == active else ""
        links_html += f'<a href="{href}" target="_self" class="{cls}">{label}</a>'

    if risk_score >= 70:
        dot_color = "#ef4444"; status_text = "High Risk Detected"
        dot_anim = "sdotAlert 0.6s ease-in-out infinite alternate"
    elif risk_score >= 40:
        dot_color = "#f97316"; status_text = "Moderate Risk"
        dot_anim = "sdotPulse 1.5s ease-in-out infinite"
    elif risk_score > 0:
        dot_color = "#eab308"; status_text = "Low Risk"
        dot_anim = "sdotPulse 2s ease-in-out infinite"
    else:
        dot_color = "#14b8a6"; status_text = "System Optimal"
        dot_anim = "sdotPulse 2s ease-in-out infinite"

    st.markdown(f"""
    <style>
    .sentinel-nav {{
        position: sticky; top: 0; z-index: 999;
        backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
        background: rgba(15,23,42,0.88);
        border-bottom: 1px solid rgba(45,212,191,0.15);
        box-shadow: 0 2px 24px rgba(0,0,0,0.4);
        padding: 0 32px; height: 60px;
        display: flex; align-items: center; justify-content: space-between;
    }}
    .sentinel-brand {{
        font-weight: 700; font-size: 1.1rem; color: #f1f5f9;
        text-decoration: none; display: flex; align-items: center; gap: 8px;
        letter-spacing: -0.3px;
    }}
    .sentinel-links {{ display: flex; gap: 4px; }}
    .sentinel-links a {{
        padding: 6px 16px; border-radius: 8px;
        font-size: 0.8rem; font-weight: 500;
        color: #64748b; text-decoration: none; transition: all 0.2s;
        border: 1px solid transparent;
    }}
    .sentinel-links a:hover {{
        background: rgba(45,212,191,0.08);
        border-color: rgba(45,212,191,0.2);
        color: #2dd4bf;
    }}
    .sentinel-links a.nav-active {{
        background: rgba(45,212,191,0.12);
        border-color: rgba(45,212,191,0.3);
        color: #2dd4bf; font-weight: 700;
    }}
    .sentinel-status {{
        display: flex; align-items: center; gap: 6px;
        font-size: 0.75rem; color: #64748b; font-weight: 500;
    }}
    .sentinel-dot {{
        width: 8px; height: 8px; border-radius: 50%;
        background: {dot_color};
        animation: {dot_anim};
        flex-shrink: 0;
    }}
    @keyframes sdotPulse {{
        0%,100% {{ box-shadow: 0 0 0 0 {dot_color}80; }}
        50%      {{ box-shadow: 0 0 0 5px {dot_color}00; }}
    }}
    @keyframes sdotAlert {{
        0%   {{ opacity: 1; box-shadow: 0 0 0 0 {dot_color}80; }}
        100% {{ opacity: 0.4; box-shadow: 0 0 0 6px {dot_color}00; }}
    }}
    </style>
    <div class="sentinel-nav">
        <a class="sentinel-brand" href="/" target="_self">🛡️ Sentinel Core</a>
        <div class="sentinel-links">{links_html}</div>
        <div class="sentinel-status">
            <div class="sentinel-dot"></div>
            <span style="color:{dot_color};">{status_text}</span>
        </div>
    </div>
    <script>
    (function() {{
        var links = document.querySelectorAll('.sentinel-links a, .sentinel-brand');
        links.forEach(function(a) {{
            a.addEventListener('click', function(e) {{
                e.preventDefault();
                window.location.href = a.getAttribute('href');
            }});
        }});
    }})();
    </script>
    """, unsafe_allow_html=True)
