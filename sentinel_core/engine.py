"""
Sentinel Core – Data Engine
Single source of truth for all scan data.
"""
import re, pickle, platform, subprocess, json, time
from pathlib import Path
from typing import Dict, List

import pandas as pd

BASE = Path(__file__).parent

# ── model loader ──────────────────────────────────────────────────────────────
def _load(path):
    try:
        import joblib
        return joblib.load(path)
    except Exception:
        with open(path, "rb") as f:
            return pickle.load(f)

# ── software icon map (emoji fallback) ───────────────────────────────────────
_ICON_MAP = {
    "chrome":"🌐","google chrome":"🌐","chromium":"🌐",
    "firefox":"🦊","mozilla":"🦊",
    "edge":"🌐","microsoft edge":"🌐",
    "python":"🐍","anaconda":"🐍","conda":"🐍",
    "node":"📦","nodejs":"📦","npm":"📦",
    "java":"☕","jdk":"☕","jre":"☕","openjdk":"☕",
    "docker":"🐳","kubernetes":"☸️",
    "mysql":"🗄️","postgresql":"🐘","sqlite":"🗄️","mongodb":"🍃",
    "apache":"🌐","nginx":"🌐","iis":"🌐",
    "openssl":"🔐","openssh":"🔑",
    "git":"🔧","github":"🔧",
    "vscode":"💻","visual studio":"💻",
    "zoom":"📹","teams":"📹","slack":"💬",
    "7-zip":"🗜️","winrar":"🗜️","winzip":"🗜️",
    "vlc":"🎬","obs":"🎬",
    "office":"📄","word":"📄","excel":"📊","powerpoint":"📊",
    "adobe":"🎨","photoshop":"🎨","acrobat":"📄",
    "antivirus":"🛡️","malwarebytes":"🛡️","avast":"🛡️","kaspersky":"🛡️",
    "windows":"🪟","microsoft":"🪟",
    "skype":"📞","discord":"💬",
    "steam":"🎮","epic":"🎮",
}

# ── real favicon URLs for known apps ─────────────────────────────────────────
# Maps lowercase keyword → domain whose favicon to fetch
_APP_FAVICON_DOMAINS = {
    "google chrome":    "chrome.google.com",
    "chromium":         "chromium.org",
    "firefox":          "firefox.com",
    "mozilla":          "mozilla.org",
    "microsoft edge":   "microsoft.com",
    "edge":             "microsoft.com",
    "python":           "python.org",
    "anaconda":         "anaconda.com",
    "nodejs":           "nodejs.org",
    "node":             "nodejs.org",
    "java":             "java.com",
    "openjdk":          "openjdk.org",
    "docker":           "docker.com",
    "mysql":            "mysql.com",
    "postgresql":       "postgresql.org",
    "mongodb":          "mongodb.com",
    "sqlite":           "sqlite.org",
    "apache":           "apache.org",
    "nginx":            "nginx.org",
    "openssl":          "openssl.org",
    "openssh":          "openssh.com",
    "git":              "git-scm.com",
    "github":           "github.com",
    "visual studio code": "code.visualstudio.com",
    "vscode":           "code.visualstudio.com",
    "visual studio":    "visualstudio.com",
    "zoom":             "zoom.us",
    "microsoft teams":  "microsoft.com",
    "teams":            "microsoft.com",
    "slack":            "slack.com",
    "discord":          "discord.com",
    "7-zip":            "7-zip.org",
    "winrar":           "win-rar.com",
    "vlc":              "videolan.org",
    "obs":              "obsproject.com",
    "microsoft office": "microsoft.com",
    "word":             "microsoft.com",
    "excel":            "microsoft.com",
    "powerpoint":       "microsoft.com",
    "adobe":            "adobe.com",
    "photoshop":        "adobe.com",
    "acrobat":          "adobe.com",
    "malwarebytes":     "malwarebytes.com",
    "avast":            "avast.com",
    "kaspersky":        "kaspersky.com",
    "windows":          "microsoft.com",
    "skype":            "skype.com",
    "steam":            "steampowered.com",
    "epic games":       "epicgames.com",
    "notepad++":        "notepad-plus-plus.org",
    "putty":            "putty.org",
    "filezilla":        "filezilla-project.org",
    "wireshark":        "wireshark.org",
    "virtualbox":       "virtualbox.org",
    "vmware":           "vmware.com",
    "7zip":             "7-zip.org",
    "winzip":           "winzip.com",
    "dropbox":          "dropbox.com",
    "onedrive":         "microsoft.com",
    "google drive":     "drive.google.com",
    "spotify":          "spotify.com",
    "itunes":           "apple.com",
    "whatsapp":         "whatsapp.com",
    "telegram":         "telegram.org",
    "signal":           "signal.org",
    "brave":            "brave.com",
    "opera":            "opera.com",
    "tor":              "torproject.org",
    "curl":             "curl.se",
    "wget":             "gnu.org",
    "powershell":       "microsoft.com",
    "wsl":              "microsoft.com",
    "hyper-v":          "microsoft.com",
}

def get_app_favicon_domain(name: str) -> str:
    """Return the favicon domain for a known app name, or empty string."""
    n = name.lower()
    # try longest match first
    for key in sorted(_APP_FAVICON_DOMAINS, key=len, reverse=True):
        if key in n:
            return _APP_FAVICON_DOMAINS[key]
    return ""

def get_favicon_url(name: str, size: int = 32) -> str:
    """Return a Google favicon API URL for the app, or empty string if unknown."""
    domain = get_app_favicon_domain(name)
    if not domain:
        return ""
    return f"https://www.google.com/s2/favicons?domain={domain}&sz={size}"

def get_software_icon(name: str) -> str:
    n = name.lower()
    for key, icon in _ICON_MAP.items():
        if key in n:
            return icon
    return "📦"

# ── vuln type extractor ───────────────────────────────────────────────────────
_VULN_PATTERNS = [
    (r"remote code exec|rce",                    "Remote Code Execution"),
    (r"sql injection|sqli",                      "SQL Injection"),
    (r"buffer overflow|stack overflow|heap",     "Buffer Overflow"),
    (r"privilege escal|privesc",                 "Privilege Escalation"),
    (r"cross.site script|xss",                   "Cross-Site Scripting"),
    (r"path traversal|directory traversal",      "Path Traversal"),
    (r"denial.of.service|dos\b",                 "Denial of Service"),
    (r"memory corruption|use.after.free",        "Memory Corruption"),
    (r"information disclosure|info leak",        "Information Disclosure"),
    (r"authentication bypass|auth bypass",       "Auth Bypass"),
    (r"command injection|cmd injection",         "Command Injection"),
    (r"deserialization",                         "Deserialization"),
    (r"ssrf",                                    "SSRF"),
    (r"xxe",                                     "XXE Injection"),
    (r"open redirect",                           "Open Redirect"),
    (r"integer overflow",                        "Integer Overflow"),
    (r"null pointer|null dereference",           "Null Dereference"),
    (r"race condition",                          "Race Condition"),
    (r"cryptograph|weak cipher|weak hash",       "Weak Cryptography"),
    (r"improper input|input validation",         "Input Validation"),
]

def extract_vuln_type(desc: str) -> str:
    d = desc.lower()
    for pattern, label in _VULN_PATTERNS:
        if re.search(pattern, d):
            return label
    return "Security Vulnerability"

# ── vulnerability ML ──────────────────────────────────────────────────────────
_vuln_model = _tfidf = _label_encoder = None

def _get_vuln_models():
    global _vuln_model, _tfidf, _label_encoder
    if _vuln_model is None:
        _vuln_model    = _load(BASE / "vuln_model.pkl")
        _tfidf         = _load(BASE / "tfidf.pkl")
        _label_encoder = _load(BASE / "label_encoder.pkl")
    return _vuln_model, _tfidf, _label_encoder

def clean_text(t: str) -> str:
    t = re.sub(r"[^a-z0-9\s]+", " ", (t or "").lower())
    return re.sub(r"\s+", " ", t).strip()

def predict_severity(desc: str) -> str:
    m, tf, le = _get_vuln_models()
    cleaned = clean_text(desc)
    if not cleaned:
        return "MEDIUM"
    X = tf.transform([cleaned])
    pred = m.predict(X)[0]
    try:
        label = str(le.inverse_transform([pred])[0]).upper()
    except Exception:
        label = str(pred).upper()
    return label if label in ("CRITICAL","HIGH","MEDIUM","LOW") else "MEDIUM"

# ── NVD ───────────────────────────────────────────────────────────────────────
_nvd_entries: List[Dict] = []
_nvd_index:   Dict[str, List[int]] = {}
_nvd_loaded   = False

# ── NVD API v2 (free, no key needed for basic rate) ──────────────────────────
_NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_API_CACHE: Dict[str, List[Dict]] = {}   # keyword → results, in-memory only

def _fetch_nvd_api(keyword: str, results_per_page: int = 5) -> List[Dict]:
    """Query NVD REST API v2 for CVEs matching keyword. Returns list of {id, description}."""
    if keyword in _NVD_API_CACHE:
        return _NVD_API_CACHE[keyword]
    try:
        import urllib.request, urllib.parse, json as _json
        params = urllib.parse.urlencode({
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
        })
        url = f"{_NVD_API_BASE}?{params}"
        req = urllib.request.Request(url, headers={"User-Agent": "SentinelCore/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = _json.loads(resp.read().decode())
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve    = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc   = next((d.get("value", "") for d in cve.get("descriptions", [])
                           if d.get("lang") == "en"), "")
            if cve_id and desc:
                results.append({"id": cve_id, "description": desc})
        _NVD_API_CACHE[keyword] = results
        return results
    except Exception:
        _NVD_API_CACHE[keyword] = []
        return []

def _ensure_nvd():
    global _nvd_entries, _nvd_index, _nvd_loaded
    if _nvd_loaded:
        return
    nvd_dir    = BASE / "nvd_data"
    cache_path = nvd_dir / "nvd_cache.pkl"
    # 1. try pre-built cache
    if cache_path.exists():
        try:
            cached = _load(str(cache_path))
            _nvd_entries = cached.get("entries", [])
            _nvd_index   = cached.get("index", {})
            _nvd_loaded  = True
            return
        except Exception:
            pass
    # 2. try parsing local JSON files
    json_files = list(nvd_dir.glob("*.json")) if nvd_dir.exists() else []
    if json_files:
        try:
            import ijson
        except ImportError:
            _nvd_loaded = True
            return
        entries, index = [], {}
        for jf in sorted(json_files):
            with open(jf, "rb") as f:
                try:
                    for item in ijson.items(f, "vulnerabilities.item"):
                        cve    = (item or {}).get("cve") or {}
                        cve_id = cve.get("id", "")
                        desc   = next((d.get("value","") for d in cve.get("descriptions",[])
                                       if d.get("lang")=="en"), "")
                        if not cve_id or not desc:
                            continue
                        desc_lc = desc.lower()
                        idx = len(entries)
                        entries.append({"id": cve_id, "desc": desc, "desc_lc": desc_lc})
                        for tok in set(re.findall(r"[a-z0-9]{4,}", desc_lc))[:40]:
                            b = index.setdefault(tok, [])
                            if len(b) < 2000:
                                b.append(idx)
                except Exception:
                    continue
        _nvd_entries, _nvd_index = entries, index
        try:
            import joblib
            nvd_dir.mkdir(exist_ok=True)
            joblib.dump({"entries": entries, "index": index}, str(cache_path))
        except Exception:
            pass
    # 3. no local data — will fall back to live API in search_cves()
    _nvd_loaded = True

def search_cves(name: str, top_k: int = 3) -> List[Dict]:
    _ensure_nvd()
    # if local index is populated, use it
    if _nvd_entries:
        tokens = re.findall(r"[a-z0-9]{4,}", name.lower())
        if not tokens:
            return []
        cands: Dict[int,int] = {}
        for tok in tokens[:6]:
            for idx in _nvd_index.get(tok, [])[:2000]:
                cands[idx] = cands.get(idx, 0) + 1
        name_lc = name.lower()
        scored = sorted(cands.items(),
                        key=lambda x: x[1] + (2 if name_lc in _nvd_entries[x[0]]["desc_lc"] else 0),
                        reverse=True)
        return [{"id": _nvd_entries[i]["id"], "description": _nvd_entries[i]["desc"]}
                for i, _ in scored[:top_k]]
    # fallback: live NVD API
    return _fetch_nvd_api(name, results_per_page=top_k)

# ── installed software ────────────────────────────────────────────────────────
def _safe_run(cmd, timeout=20):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout, text=True)
        return 0, out
    except subprocess.CalledProcessError as e:
        return e.returncode, (e.output or "")
    except Exception as e:
        return 1, str(e)

def get_installed_software(limit: int = 20) -> List[Dict]:
    if platform.system().lower() != "windows":
        return []
    ps = (
        r'$p=@("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",'
        r'"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",'
        r'"HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*");'
        r'Get-ItemProperty $p -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName}|'
        r'Select-Object DisplayName,DisplayVersion|Sort-Object DisplayName|'
        f'Select-Object -First {limit}|ConvertTo-Json -Depth 2'
    )
    code, out = _safe_run(
        ["powershell","-NoProfile","-ExecutionPolicy","Bypass","-Command", ps], timeout=25)
    if code != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
        if isinstance(data, dict): data = [data]
        return [{"name": str(x.get("DisplayName","")), "version": str(x.get("DisplayVersion",""))}
                for x in data if x.get("DisplayName")]
    except Exception:
        return []

# ── CVSS map ──────────────────────────────────────────────────────────────────
_SEV_CVSS = {"CRITICAL": 9.5, "HIGH": 7.8, "MEDIUM": 5.5, "LOW": 2.5}
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# ── risk score ────────────────────────────────────────────────────────────────
def compute_risk_score(vuln_summary: Dict, ids_stats: Dict) -> int:
    """0–100 overall system risk score combining vuln + IDS data."""
    total_v = max(vuln_summary.get("total", 0), 1)
    vuln_score = (
        vuln_summary.get("critical", 0) * 10 +
        vuln_summary.get("high", 0)     * 6  +
        vuln_summary.get("medium", 0)   * 3
    )
    vuln_score = min(vuln_score / total_v * 10, 60)

    total_p   = max(ids_stats.get("total", 1), 1)
    threat_n  = ids_stats.get("threat", ids_stats.get("attack", 0))
    susp_n    = ids_stats.get("suspicious", 0)
    ids_score = ((threat_n * 1.0 + susp_n * 0.4) / total_p) * 40

    return min(int(vuln_score + ids_score), 100)


def get_correlation_alerts(vuln_data: Dict, ids_data: Dict) -> List[Dict]:
    """
    Cross-references vuln scan + IDS scan to find meaningful combined alerts.
    Returns list of alert dicts with title, detail, severity, icon.
    """
    alerts = []
    if not vuln_data or not ids_data:
        return alerts

    ids_events  = ids_data.get("events", [])
    vuln_groups = vuln_data.get("grouped", [])

    # Build set of active process names from IDS (lowercased)
    active_procs = {e["process"].lower() for e in ids_events if e["prediction"] != "Normal"}
    active_services = {e["service"].lower() for e in ids_events if e["prediction"] != "Normal"}

    for sw in vuln_groups:
        name_lc  = sw["name"].lower()
        worst    = sw["worst"]
        # Check if any IDS flagged process/service name overlaps with this software
        matched_proc = any(
            (p in name_lc or name_lc in p)
            for p in active_procs | active_services
            if len(p) > 3
        )
        if matched_proc and worst in ("CRITICAL", "HIGH"):
            cve_ids = ", ".join(c["cve"] for c in sw["cves"][:2])
            alerts.append({
                "icon":     "🔴",
                "severity": "critical",
                "title":    f"{sw['name']} — active connection + unpatched vulnerability",
                "detail":   (f"This app has an active suspicious network connection AND "
                             f"a {worst} severity vulnerability ({cve_ids}). "
                             f"This combination could allow an attacker to exploit it right now."),
                "software": sw["name"],
                "cves":     [c["cve"] for c in sw["cves"]],
                "is_windows": "windows" in name_lc or "microsoft" in name_lc,
            })

    # Alert: many threats + critical vulns = elevated overall risk
    threat_n = ids_data["stats"].get("threat", 0)
    crit_n   = vuln_data["summary"].get("critical", 0)
    if threat_n >= 2 and crit_n >= 2:
        alerts.append({
            "icon":     "⚠️",
            "severity": "high",
            "title":    f"{threat_n} active threats + {crit_n} critical vulnerabilities",
            "detail":   ("Your system currently has multiple active threat connections "
                         "and multiple critical unpatched vulnerabilities. "
                         "Your attack surface is elevated — consider running Windows Update now."),
            "software": None,
            "cves":     [],
            "is_windows": True,
        })

    return alerts[:5]  # cap at 5


def get_process_deep_dive(proc_name: str) -> Dict:
    """
    Returns real-time info about a running process: CPU, memory, path, connections.
    """
    try:
        import psutil
        results = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info",
                                          "exe", "status", "create_time"]):
            try:
                if proc_name.lower() in proc.info["name"].lower():
                    conns = proc.net_connections(kind="inet")
                    results.append({
                        "pid":        proc.info["pid"],
                        "name":       proc.info["name"],
                        "cpu":        round(proc.info["cpu_percent"] or 0, 1),
                        "mem_mb":     round((proc.info["memory_info"].rss or 0) / 1_048_576, 1),
                        "exe":        proc.info["exe"] or "unknown",
                        "status":     proc.info["status"],
                        "conn_count": len(conns),
                        "is_trusted": proc.info["name"].lower() in {
                            "svchost.exe","lsass.exe","services.exe","wininit.exe",
                            "winlogon.exe","system","explorer.exe","taskhostw.exe",
                        },
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return {"processes": results, "available": True}
    except Exception:
        return {"processes": [], "available": False}

# ── software-level risk score (0-100) ────────────────────────────────────────
def _sw_risk(cves: List[Dict]) -> int:
    """Per-software risk 0-100, normalized by number of CVEs found."""
    if not cves:
        return 0
    weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 4}
    raw = sum(weights.get(c["severity"], 10) for c in cves)
    # normalize: max possible = len(cves) * 40 (all critical)
    max_possible = len(cves) * 40
    return min(int(raw / max_possible * 100), 100)

# ── remediation action ────────────────────────────────────────────────────────
def _remediation(sev: str, vuln_type: str) -> str:
    if sev == "CRITICAL":
        return "Patch immediately or isolate system"
    if sev == "HIGH":
        return "Update to latest version ASAP"
    if vuln_type in ("Remote Code Execution","Buffer Overflow","Privilege Escalation"):
        return "Apply vendor patch or disable feature"
    if sev == "MEDIUM":
        return "Schedule update in next maintenance window"
    return "Monitor and update when convenient"

# ── plain English impact ──────────────────────────────────────────────────────
_VULN_PLAIN_ENGLISH = {
    "Remote Code Execution":  "An attacker could run malicious code on your computer without you doing anything.",
    "SQL Injection":          "An attacker could read, modify, or delete data stored by this software.",
    "Buffer Overflow":        "A crafted input could crash this software or let an attacker take control of it.",
    "Privilege Escalation":   "An attacker with basic access could gain full admin control of your system.",
    "Cross-Site Scripting":   "Malicious scripts could run in your browser and steal your session or data.",
    "Path Traversal":         "An attacker could access files on your system that this software shouldn't touch.",
    "Denial of Service":      "An attacker could crash or freeze this software, making it stop working.",
    "Memory Corruption":      "A bug in memory handling could let an attacker crash or hijack this software.",
    "Information Disclosure": "This software could leak sensitive data — like passwords or personal files — to an attacker.",
    "Auth Bypass":            "An attacker could skip the login check and access protected features without a password.",
    "Command Injection":      "An attacker could trick this software into running system commands on your machine.",
    "Deserialization":        "Malformed data sent to this software could let an attacker execute code remotely.",
    "SSRF":                   "An attacker could use this software to make requests to internal systems on your network.",
    "XXE Injection":          "Malicious XML input could expose files from your system or internal network.",
    "Open Redirect":          "This software could be used to silently redirect you to a malicious website.",
    "Integer Overflow":       "A numeric bug could cause unexpected behaviour, potentially leading to a crash or exploit.",
    "Null Dereference":       "A bug could crash this software unexpectedly when handling certain inputs.",
    "Race Condition":         "Timing issues in this software could be exploited to corrupt data or gain access.",
    "Weak Cryptography":      "This software uses outdated encryption that attackers can break to read protected data.",
    "Input Validation":       "This software doesn't properly check inputs, which could let attackers manipulate it.",
    "Security Vulnerability": "A security flaw in this software could be exploited by an attacker.",
}

def plain_english_impact(vuln_type: str) -> str:
    return _VULN_PLAIN_ENGLISH.get(vuln_type, _VULN_PLAIN_ENGLISH["Security Vulnerability"])

# ── fix urgency ───────────────────────────────────────────────────────────────
def get_fix_urgency(severity: str, patch_available: bool) -> Dict:
    """Returns urgency label, color, and icon based on severity + patch status."""
    if severity == "CRITICAL" and patch_available:
        return {"label": "Fix Now",   "color": "#dc2626", "bg": "rgba(220,38,38,0.1)",   "icon": "🚨"}
    if severity == "CRITICAL" and not patch_available:
        return {"label": "Fix Now",   "color": "#dc2626", "bg": "rgba(220,38,38,0.1)",   "icon": "🚨"}
    if severity == "HIGH" and patch_available:
        return {"label": "Fix Soon",  "color": "#ea580c", "bg": "rgba(234,88,12,0.1)",   "icon": "⚠️"}
    if severity == "HIGH" and not patch_available:
        return {"label": "Fix Now",   "color": "#dc2626", "bg": "rgba(220,38,38,0.1)",   "icon": "🚨"}
    if severity == "MEDIUM":
        return {"label": "Fix Soon",  "color": "#d97706", "bg": "rgba(217,119,6,0.1)",   "icon": "📋"}
    return     {"label": "Monitor",   "color": "#16a34a", "bg": "rgba(22,163,74,0.1)",   "icon": "👁️"}

# ── exposure score ────────────────────────────────────────────────────────────
_HIGH_EXPOSURE = [
    "chrome","firefox","edge","browser","opera","safari",
    "zoom","teams","skype","discord","slack","whatsapp","telegram",
    "outlook","thunderbird","mail",
    "office","word","excel","powerpoint","libreoffice",
    "adobe","acrobat","reader",
    "steam","epic","game","launcher",
]
_LOW_EXPOSURE = [
    "driver","codec","runtime","redistributable","framework",
    "vcredist","directx","openal","dotnet",".net","visual c++",
    "7-zip","winrar","winzip","archiver",
    "antivirus","malwarebytes","avast","kaspersky","defender",
]

def get_exposure_level(software_name: str) -> Dict:
    n = software_name.lower()
    for kw in _HIGH_EXPOSURE:
        if kw in n:
            return {"level": "High",   "color": "#dc2626", "bg": "rgba(220,38,38,0.08)",  "icon": "🔓", "reason": "Runs in foreground, handles untrusted content daily"}
    for kw in _LOW_EXPOSURE:
        if kw in n:
            return {"level": "Low",    "color": "#16a34a", "bg": "rgba(22,163,74,0.08)",  "icon": "🔒", "reason": "Background component, limited direct user interaction"}
    return         {"level": "Medium", "color": "#d97706", "bg": "rgba(217,119,6,0.08)",  "icon": "🔐", "reason": "Moderate exposure — used occasionally or indirectly"}

# ── fix steps ─────────────────────────────────────────────────────────────────
_FIX_STEPS_BY_TYPE = {
    "Remote Code Execution": [
        "Open your software updater or the app's built-in update menu",
        "Install the latest available version immediately",
        "If no update exists, consider uninstalling until a patch is released",
        "Check the vendor's security advisory page for workarounds",
    ],
    "Privilege Escalation": [
        "Update this software to the latest version",
        "Ensure you're not running this software as Administrator unless required",
        "Review which users on your system have access to this software",
        "Check vendor advisory for any configuration-based mitigations",
    ],
    "Buffer Overflow": [
        "Update to the latest version of this software",
        "Avoid opening untrusted files with this application until patched",
        "Enable Data Execution Prevention (DEP) in Windows Security settings",
        "Monitor vendor release notes for a security patch",
    ],
    "Information Disclosure": [
        "Update this software to close the data leak",
        "Review what sensitive data this software has access to",
        "Check if any credentials or files may have been exposed",
        "Consider revoking and rotating any passwords this software uses",
    ],
    "Denial of Service": [
        "Update to the latest version to get the stability fix",
        "If the software is a server, consider rate-limiting incoming connections",
        "Monitor the software for unexpected crashes or high CPU usage",
    ],
    "SQL Injection": [
        "Update this software — the vendor should have patched the input handling",
        "If this is a local app, avoid connecting it to untrusted data sources",
        "Check if any database credentials stored by this app need rotating",
    ],
    "Cross-Site Scripting": [
        "Update your browser or the affected web application",
        "Enable browser security features like XSS protection in settings",
        "Avoid visiting untrusted websites until the patch is applied",
    ],
    "Auth Bypass": [
        "Update immediately — authentication flaws are high priority",
        "Change any passwords associated with this software",
        "Review access logs for any suspicious login activity",
        "Enable multi-factor authentication if the software supports it",
    ],
    "Weak Cryptography": [
        "Update to the latest version which should use modern encryption",
        "Avoid transmitting sensitive data through this software until patched",
        "Check if any data encrypted by this software needs to be re-encrypted",
    ],
}

_FIX_STEPS_DEFAULT = [
    "Open Windows Settings → Windows Update and check for system updates",
    "Open the software and look for a built-in 'Check for Updates' option",
    "Visit the software vendor's website and download the latest version",
    "If no patch is available, consider disabling or uninstalling the software temporarily",
]

_FIX_STEPS_WINDOWS_UPDATE = [
    "Press Win + I to open Settings",
    "Go to Windows Update → Check for updates",
    "Install all available updates and restart if prompted",
    "Re-run this scan after updating to verify the issue is resolved",
]

def get_fix_steps(software_name: str, vuln_type: str) -> list:
    n = software_name.lower()
    if "windows" in n or "microsoft" in n:
        return _FIX_STEPS_WINDOWS_UPDATE
    steps = _FIX_STEPS_BY_TYPE.get(vuln_type)
    return steps if steps else _FIX_STEPS_DEFAULT

# ── CVE age ───────────────────────────────────────────────────────────────────
def get_cve_age(cve_id: str) -> Dict:
    """Extract year from CVE-YYYY-NNNNN and compute age."""
    m = re.match(r"CVE-(\d{4})-", cve_id)
    if not m:
        return {"year": None, "age": None, "label": "", "color": "#94a3b8"}
    year = int(m.group(1))
    age  = 2025 - year
    if age >= 5:
        return {"year": year, "age": age, "label": f"{age}yr old CVE", "color": "#dc2626"}
    if age >= 2:
        return {"year": year, "age": age, "label": f"{age}yr old CVE", "color": "#d97706"}
    return     {"year": year, "age": age, "label": f"{age}yr old CVE", "color": "#16a34a"}

# ── attack chain detection ────────────────────────────────────────────────────
# Pairs of vuln types that form a dangerous escalation chain
_CHAIN_PAIRS = [
    ({"Remote Code Execution", "Privilege Escalation"},
     "RCE + Privilege Escalation chain — attacker can run code AND gain admin control"),
    ({"Buffer Overflow", "Privilege Escalation"},
     "Buffer Overflow + Privilege Escalation chain — memory exploit can lead to full system takeover"),
    ({"Auth Bypass", "Remote Code Execution"},
     "Auth Bypass + RCE chain — attacker can skip login then execute code remotely"),
    ({"Auth Bypass", "Privilege Escalation"},
     "Auth Bypass + Privilege Escalation chain — unauthorized access can escalate to admin"),
    ({"Information Disclosure", "Auth Bypass"},
     "Info Leak + Auth Bypass chain — leaked credentials can enable authentication bypass"),
    ({"Command Injection", "Privilege Escalation"},
     "Command Injection + Privilege Escalation chain — injected commands can gain root access"),
    ({"Deserialization", "Remote Code Execution"},
     "Deserialization + RCE chain — malformed data can trigger remote code execution"),
    ({"Memory Corruption", "Remote Code Execution"},
     "Memory Corruption + RCE chain — memory bug can be weaponized for code execution"),
    ({"SQL Injection", "Information Disclosure"},
     "SQL Injection + Info Disclosure chain — database access can expose sensitive data"),
    ({"Path Traversal", "Information Disclosure"},
     "Path Traversal + Info Disclosure chain — file access can leak sensitive system data"),
]

def detect_attack_chains(cves: List[Dict]) -> List[str]:
    """Return list of chain warning strings for a software's CVE list."""
    types = {c["vuln_type"] for c in cves}
    warnings = []
    for pair, msg in _CHAIN_PAIRS:
        if pair.issubset(types):
            warnings.append(msg)
    return warnings

# ── software category ─────────────────────────────────────────────────────────
_SW_CATEGORIES = [
    ("🌐 Browsers",          ["chrome","firefox","edge","chromium","opera","browser","safari"]),
    ("💬 Communication",     ["zoom","teams","skype","discord","slack","whatsapp","telegram","outlook","thunderbird","mail"]),
    ("📄 Office & Docs",     ["office","word","excel","powerpoint","libreoffice","acrobat","adobe","reader","pdf"]),
    ("🛠 Dev Tools",         ["python","node","java","jdk","jre","git","vscode","visual studio","docker","anaconda","conda"]),
    ("🎮 Gaming",            ["steam","epic","game","launcher","origin","uplay","gog"]),
    ("🎬 Media",             ["vlc","obs","media","player","codec","spotify","itunes"]),
    ("🛡 Security",          ["antivirus","malwarebytes","avast","kaspersky","defender","bitdefender","norton"]),
    ("🗜 Utilities",         ["7-zip","winrar","winzip","archiver","ccleaner","everything","notepad"]),
    ("🪟 System & Runtime",  ["windows","microsoft","vcredist","directx","dotnet",".net","visual c++","runtime","redistributable","openssl","openssh"]),
    ("🗄 Databases",         ["mysql","postgresql","sqlite","mongodb","redis","oracle"]),
]

def get_software_category(name: str) -> str:
    n = name.lower()
    for cat, keywords in _SW_CATEGORIES:
        for kw in keywords:
            if kw in n:
                return cat
    return "📦 Other"

# ── risk score breakdown ──────────────────────────────────────────────────────
def get_risk_breakdown(summary: Dict, sw_count: int, cves_per_sw: int) -> Dict:
    """Returns per-factor contribution to the risk score with explanations."""
    critical = summary.get("critical", 0)
    high     = summary.get("high", 0)
    medium   = summary.get("medium", 0)
    total    = max(summary.get("total", 0), 1)
    max_possible = max(sw_count * cves_per_sw * 8, 1)

    c_pts = min(int(critical * 8 / max_possible * 100), 60)
    h_pts = min(int(high     * 4 / max_possible * 100), 30)
    m_pts = min(int(medium   * 1.5 / max_possible * 100), 10)

    patched   = summary.get("patched", 0)
    unpatched = total - patched

    return {
        "critical_pts": c_pts,
        "high_pts":     h_pts,
        "medium_pts":   m_pts,
        "critical_n":   critical,
        "high_n":       high,
        "medium_n":     medium,
        "unpatched_n":  unpatched,
        "total":        total,
    }

# ── PUBLIC: vulnerability scan ────────────────────────────────────────────────
def run_vuln_scan(limit_sw: int = 20, cves_per_sw: int = 2) -> Dict:
    t0       = time.time()
    software = get_installed_software(limit=limit_sw)
    results: List[Dict] = []
    # grouped by software (for vulnerability page cards)
    grouped: List[Dict] = []

    for sw in software:
        name, version = sw["name"], sw["version"]
        cves = search_cves(name, top_k=cves_per_sw)
        if not cves:
            continue
        sw_cves = []
        for cve in cves:
            desc      = cve["description"]
            sev       = predict_severity(desc)
            vuln_type = extract_vuln_type(desc)
            # patch availability: infer from description keywords
            patch_avail = not bool(re.search(
                r"no (patch|fix|update)|unpatched|zero.day|0.day|no known fix", desc.lower()))
            urgency   = get_fix_urgency(sev, patch_avail)
            entry = {
                "software":        name,
                "version":         version,
                "icon":            get_software_icon(name),
                "favicon_url":     get_favicon_url(name, size=32),
                "cve":             cve["id"],
                "description":     desc,
                "plain_impact":    plain_english_impact(vuln_type),
                "vuln_type":       vuln_type,
                "severity":        sev,
                "cvss":            _SEV_CVSS.get(sev, 5.5),
                "patch_available": patch_avail,
                "urgency":         urgency,
                "fix_steps":       get_fix_steps(name, vuln_type),
                "remediation":     _remediation(sev, vuln_type),
                "cve_age":         get_cve_age(cve["id"]),
            }
            results.append(entry)
            sw_cves.append(entry)

        # worst severity for this software
        worst = sorted(sw_cves, key=lambda x: _SEV_ORDER.get(x["severity"],4))[0]["severity"]
        exposure = get_exposure_level(name)
        chains   = detect_attack_chains(sw_cves)
        grouped.append({
            "name":        name,
            "version":     version,
            "icon":        get_software_icon(name),
            "favicon_url": get_favicon_url(name, size=32),
            "cves":        sw_cves,
            "worst":       worst,
            "risk":        _sw_risk(sw_cves),
            "exposure":    exposure,
            "chains":      chains,
            "category":    get_software_category(name),
        })

    # sort grouped: highest risk first
    grouped.sort(key=lambda g: -g["risk"])
    results.sort(key=lambda r: (_SEV_ORDER.get(r["severity"],4),))

    summary = {"critical":0,"high":0,"medium":0,"low":0,"total":len(results)}
    for r in results:
        k = r["severity"].lower()
        if k in summary:
            summary[k] += 1
    summary["patched"] = sum(1 for r in results if r["patch_available"])

    # overall system vuln risk score (0-100)
    # Formula: weighted by severity but normalized against apps scanned
    # so having many apps doesn't automatically mean high risk
    sw_count = max(len(software), 1)
    raw = (
        summary["critical"] * 8 +
        summary["high"]     * 4 +
        summary["medium"]   * 1.5
    )
    # normalize: divide by (apps * cves_per_sw) so score reflects
    # proportion of apps affected, not raw CVE count
    max_possible = sw_count * cves_per_sw * 8   # worst case: all critical
    risk_score = min(int(raw / max(max_possible, 1) * 100), 100)

    # top 3 for remediation queue (critical/high, no patch)
    remediation_queue = [r for r in results if r["severity"] in ("CRITICAL","HIGH")][:3]

    return {
        "results":           results,
        "grouped":           grouped,
        "summary":           summary,
        "risk_score":        risk_score,
        "risk_breakdown":    get_risk_breakdown(summary, sw_count, cves_per_sw),
        "remediation_queue": remediation_queue,
        "software_count":    len(software),
        "scan_time":         round(time.time() - t0, 1),
    }

# ── IDS ───────────────────────────────────────────────────────────────────────
_ids_model = _ids_preprocessor = _kdd_X = _kdd_y = _kdd_raw_labels = None

_KDD_COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
]

# KDD raw label → attack category
_ATTACK_CATEGORIES = {
    "normal":      "Normal",
    # DoS
    "back":"DoS","land":"DoS","neptune":"DoS","pod":"DoS","smurf":"DoS",
    "teardrop":"DoS","apache2":"DoS","udpstorm":"DoS","processtable":"DoS","mailbomb":"DoS",
    # Probe
    "ipsweep":"Probe","nmap":"Probe","portsweep":"Probe","satan":"Probe",
    "mscan":"Probe","saint":"Probe",
    # R2L
    "ftp_write":"R2L","guess_passwd":"R2L","imap":"R2L","multihop":"R2L",
    "phf":"R2L","spy":"R2L","warezclient":"R2L","warezmaster":"R2L",
    "sendmail":"R2L","named":"R2L","snmpgetattack":"R2L","snmpguess":"R2L",
    "xlock":"R2L","xsnoop":"R2L","httptunnel":"R2L",
    # U2R
    "buffer_overflow":"U2R","loadmodule":"U2R","perl":"U2R","rootkit":"U2R",
    "ps":"U2R","sqlattack":"U2R","xterm":"U2R",
}

_CATEGORY_META = {
    "Normal":  ("✅", "#16a34a", "Normal connection — nothing unusual here"),
    "Warning": ("⚠️", "#f97316", "Worth keeping an eye on — not necessarily harmful"),
    "Suspicious": ("🔍", "#eab308", "Unusual activity that may need attention"),
    "Threat":  ("🚨", "#ef4444", "Potentially harmful connection detected"),
}

# ── plain English explanations per category ───────────────────────────────────
_PLAIN_ENGLISH = {
    "Normal": (
        "This connection looks completely normal. Your app is talking to the internet "
        "or another program on your computer in the usual way. Nothing to worry about."
    ),
    "Warning": (
        "This connection is a little unusual but not necessarily dangerous. "
        "It could be a background app, a game, or a developer tool doing something "
        "out of the ordinary. Worth noting, but probably fine."
    ),
    "Suspicious": (
        "Something about this connection stands out. It might be an app trying to "
        "reach an unusual destination, or a program opening more connections than expected. "
        "If you don't recognise the app listed, it's worth investigating."
    ),
    "Threat": (
        "This connection matches a pattern commonly used by harmful software. "
        "It could be a program trying to secretly communicate with a remote server, "
        "or an attempt to access your computer without your permission. "
        "If you don't recognise the app listed, consider closing it."
    ),
}

# ── ports that are ONLY suspicious when connecting TO them from outside ───────
# These are ports no normal home PC app should be reaching out to remotely.
# We deliberately exclude ports that Windows uses internally (135, 139, 445, etc.)
_REMOTE_THREAT_PORTS: Dict[int, tuple] = {
    # Known backdoor / remote-access tool ports
    4444:  ("Threat",     "Your computer is connecting to a port commonly used by hacking tools to take remote control of a PC."),
    1337:  ("Threat",     "Your computer is connecting to a port associated with unauthorised remote access tools."),
    31337: ("Threat",     "Your computer is connecting to a port historically used by a well-known backdoor program."),
    12345: ("Threat",     "Your computer is connecting to a port used by a remote-access program that shouldn't be on a normal PC."),
    54321: ("Threat",     "Your computer is connecting to a port often used by programs that secretly open a back door."),
    # IRC botnet ports — no normal home app uses these
    6667:  ("Suspicious", "Your computer is connecting to a chat-network port that malicious software sometimes uses to receive instructions."),
    6668:  ("Suspicious", "Same as above — an unusual port that malware sometimes uses to communicate."),
    6669:  ("Suspicious", "Same as above — an unusual port that malware sometimes uses to communicate."),
    # Old insecure remote-access protocols — should never appear on a modern home PC
    23:    ("Suspicious", "Your computer is using an old, insecure way of connecting to another machine remotely. Modern apps don't use this."),
    512:   ("Suspicious", "Your computer is using a very old remote-access method that has known security problems."),
    513:   ("Suspicious", "Your computer is using a very old remote-access method that has known security problems."),
    # Amplification / abuse ports — no home app should reach these remotely
    11211: ("Threat",     "Your computer is connecting to a port that attackers use to flood other computers with traffic."),
    19:    ("Suspicious", "Your computer is connecting to a port that can be abused to send large amounts of unwanted traffic."),
}

# ── ports that are suspicious ONLY when listening and reachable externally ────
# Windows legitimately listens on 135/445/etc. internally — we don't flag those.
_LISTEN_THREAT_PORTS: Dict[int, tuple] = {
    4444:  ("Threat",     "Something on your computer is waiting for incoming connections on a port used by hacking tools."),
    1337:  ("Threat",     "Something on your computer is waiting for connections on a port associated with unauthorised access."),
    31337: ("Threat",     "Something on your computer is waiting for connections on a port used by a known backdoor program."),
    12345: ("Threat",     "Something on your computer is waiting for connections on a port used by a remote-access tool."),
    54321: ("Threat",     "Something on your computer is waiting for connections on a port often used by backdoor software."),
    2375:  ("Threat",     "Your computer is openly accepting connections to its container management system — this can give full control to anyone who connects."),
}

# ── ports considered safe everywhere (no flagging) ───────────────────────────
_SAFE_PORTS: set = {
    80, 443, 53, 22, 25, 587, 993, 995, 143, 110, 21, 8080, 8443,
    3389, 5900, 5985, 5986, 67, 68, 123, 389, 636,
    # Windows system ports — always normal internally
    135, 139, 445, 1433, 3306, 5432, 27017, 6379, 9200,
    # Common dev / app ports
    3000, 4000, 5000, 8000, 8888, 6006, 7000, 9000, 9090,
    # Windows dynamic / ephemeral range start
    49152,
}

# ── well-known port → friendly service name ───────────────────────────────────
_PORT_NAMES: Dict[int, str] = {
    80: "Web (HTTP)", 443: "Web (HTTPS)", 53: "DNS", 22: "SSH",
    25: "Email (SMTP)", 587: "Email (SMTP)", 993: "Email (IMAP)",
    995: "Email (POP3)", 143: "Email (IMAP)", 110: "Email (POP3)",
    21: "File Transfer (FTP)", 8080: "Web (alt)", 8443: "Web (HTTPS alt)",
    3389: "Remote Desktop", 5900: "Remote Desktop (VNC)",
    67: "Network Config (DHCP)", 68: "Network Config (DHCP)",
    123: "Time Sync (NTP)", 135: "Windows System", 139: "Windows File Sharing",
    445: "Windows File Sharing", 1433: "Database (SQL Server)",
    3306: "Database (MySQL)", 5432: "Database (PostgreSQL)",
    27017: "Database (MongoDB)", 6379: "Cache (Redis)",
    4444: "⚠ Hacking Tool Port", 1337: "⚠ Backdoor Port",
    31337: "⚠ Backdoor Port", 6667: "IRC / Botnet",
    23: "Old Remote Access (Telnet)", 2375: "Container Manager",
}

def _port_to_service(port: int) -> str:
    if port is None:
        return "Unknown"
    return _PORT_NAMES.get(port, f"Port {port}")

def _conn_to_proto(kind: str) -> str:
    return {"tcp4": "tcp", "tcp6": "tcp", "udp4": "udp",
            "udp6": "udp", "tcp": "tcp", "udp": "udp"}.get(kind, kind or "tcp")

# ── trusted system process names (Windows) ───────────────────────────────────
_TRUSTED_PROCS = {
    "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe",
    "system", "system idle process", "smss.exe", "csrss.exe", "explorer.exe",
    "taskhostw.exe", "spoolsv.exe", "searchindexer.exe", "audiodg.exe",
    "dwm.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe",
}

def _assess_connection(conn, proc_name: str, proc_conns: int) -> tuple:
    """
    Returns (category, short_label, plain_english, confidence, flag_messages)
    Conservative rules — only flag things that are genuinely unusual on a home PC.
    """
    rport  = conn.raddr.port if conn.raddr else None
    lport  = conn.laddr.port if conn.laddr else None
    rip    = conn.raddr.ip   if conn.raddr else None
    status = getattr(conn, "status", "")
    proc_lower = proc_name.lower()

    flags = []   # (flag_type, user_message, confidence_score)

    # ── Rule 1: connecting OUT to a known threat port ─────────────────────────
    # Only applies when there's an actual remote address (not just listening)
    if rport and rport in _REMOTE_THREAT_PORTS and status == "ESTABLISHED":
        cat, msg = _REMOTE_THREAT_PORTS[rport]
        flags.append((cat, msg, 88))

    # ── Rule 2: listening on a known threat port ──────────────────────────────
    # Only flag if it's NOT a trusted Windows system process
    if (lport and lport in _LISTEN_THREAT_PORTS
            and status == "LISTEN"
            and proc_lower not in _TRUSTED_PROCS):
        cat, msg = _LISTEN_THREAT_PORTS[lport]
        flags.append((cat, msg, 85))

    # ── Rule 3: very high connection count for a single non-browser process ───
    # Browsers legitimately open 50+ connections. Flag only non-browser processes.
    _browser_procs = {"chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
                      "brave.exe", "iexplore.exe", "chromium.exe"}
    if (proc_conns > 60
            and proc_lower not in _browser_procs
            and proc_lower not in _TRUSTED_PROCS):
        msg = (f"The app '{proc_name}' currently has {proc_conns} open connections. "
               f"That's unusually high for a non-browser app and could mean it's "
               f"sending a lot of data or scanning the network.")
        flags.append(("Suspicious", msg, 70))

    # ── Rule 4: connecting to a non-internet IP on a non-standard port ────────
    # Only flag if it's an ESTABLISHED connection to an internal IP on a port
    # that isn't in our safe list AND the process isn't a trusted system process.
    if (rip and rport
            and status == "ESTABLISHED"
            and rport not in _SAFE_PORTS
            and rport < 1024          # only flag well-known port range
            and proc_lower not in _TRUSTED_PROCS):
        is_private = (
            rip.startswith("10.") or
            rip.startswith("192.168.") or
            (rip.startswith("172.") and
             rip.count(".") >= 2 and
             16 <= int(rip.split(".")[1]) <= 31)
        )
        if is_private:
            msg = (f"'{proc_name}' is connected to another device on your local network "
                   f"({rip}) using an unusual channel. This is worth checking if you "
                   f"didn't set this up intentionally.")
            flags.append(("Warning", msg, 60))

    # ── No flags → Normal ─────────────────────────────────────────────────────
    if not flags:
        short = "Normal connection — nothing unusual"
        return ("Normal", short, _PLAIN_ENGLISH["Normal"], 97, [])

    # Pick the most serious flag
    _sev = {"Threat": 3, "Suspicious": 2, "Warning": 1}
    flags.sort(key=lambda x: (-_sev.get(x[0], 0), -x[2]))
    top = flags[0]
    category   = top[0]
    confidence = top[2]
    short_lbl  = top[1]
    plain      = _PLAIN_ENGLISH.get(category, _PLAIN_ENGLISH["Normal"])

    return (category, short_lbl, plain, confidence, [f[1] for f in flags])


# ── PUBLIC: live psutil-based IDS ─────────────────────────────────────────────
def run_live_ids() -> Dict:
    """
    Analyses real active network connections using psutil + rule-based detection.
    No ML model, no KDD data — 100% live system state.
    """
    import psutil
    t0 = time.time()

    # ── gather connections + process info ─────────────────────────────────────
    try:
        raw_conns = psutil.net_connections(kind="inet")
    except Exception:
        raw_conns = []

    # build pid → (process_name, conn_count)
    pid_counts: Dict[int, int] = {}
    for c in raw_conns:
        if c.pid:
            pid_counts[c.pid] = pid_counts.get(c.pid, 0) + 1

    pid_names: Dict[int, str] = {}
    for pid in pid_counts:
        try:
            pid_names[pid] = psutil.Process(pid).name()
        except Exception:
            pid_names[pid] = f"pid-{pid}"

    # ── network I/O snapshot ──────────────────────────────────────────────────
    io = psutil.net_io_counters()
    bytes_sent_mb = round(io.bytes_sent / 1_048_576, 1)
    bytes_recv_mb = round(io.bytes_recv / 1_048_576, 1)

    # ── assess each connection ────────────────────────────────────────────────
    events: List[Dict] = []
    cat_counts: Dict[str, int] = {"Normal": 0, "Warning": 0, "Suspicious": 0, "Threat": 0}

    for i, conn in enumerate(raw_conns):
        pid       = conn.pid or 0
        proc_name = pid_names.get(pid, "system")
        proc_conns = pid_counts.get(pid, 1)
        lport     = conn.laddr.port if conn.laddr else 0
        rport     = conn.raddr.port if conn.raddr else None
        rip       = conn.raddr.ip   if conn.raddr else "—"
        status    = getattr(conn, "status", "")
        proto     = _conn_to_proto(conn.type.name if hasattr(conn.type, "name") else str(conn.type))
        service   = _port_to_service(rport or lport)

        category, threat_desc, plain_en, confidence, all_flags = _assess_connection(
            conn, proc_name, proc_conns)

        is_attack = category != "Normal"
        icon, color, cat_desc = _CATEGORY_META.get(category, ("❓", "#64748b", "Unknown"))
        cat_counts[category] = cat_counts.get(category, 0) + 1

        events.append({
            "conn_id":      f"CONN-{i+1:03d}",
            "process":      proc_name,
            "pid":          pid,
            "local_port":   lport,
            "remote_ip":    rip,
            "remote_port":  rport or 0,
            "status":       status,
            "protocol":     proto,
            "service":      service,
            "prediction":   category,          # Normal / Warning / Suspicious / Threat
            "category":     category,
            "cat_desc":     cat_desc,
            "threat_desc":  threat_desc,
            "plain_english": plain_en,
            "all_flags":    all_flags,
            "icon":         icon,
            "color":        color,
            "confidence":   confidence,
        })

    normal_n     = sum(1 for e in events if e["prediction"] == "Normal")
    threat_n     = sum(1 for e in events if e["prediction"] == "Threat")
    suspicious_n = sum(1 for e in events if e["prediction"] in ("Suspicious", "Warning"))
    total_n      = len(events)

    # top offending processes / ports (by non-normal count)
    proc_attacks: Dict[str, int] = {}
    proc_total:   Dict[str, int] = {}
    port_attacks: Dict[str, int] = {}
    port_total:   Dict[str, int] = {}
    for e in events:
        p = e["process"]
        s = e["service"]
        proc_total[p] = proc_total.get(p, 0) + 1
        port_total[s] = port_total.get(s, 0) + 1
        if e["prediction"] != "Normal":
            proc_attacks[p] = proc_attacks.get(p, 0) + 1
            port_attacks[s] = port_attacks.get(s, 0) + 1

    top_services = sorted(
        [{"name": k, "attacks": v, "total": port_total[k]} for k, v in port_attacks.items()],
        key=lambda x: -x["attacks"])[:5]
    top_protocols = sorted(
        [{"name": k, "attacks": v, "total": proc_total[k]} for k, v in proc_attacks.items()],
        key=lambda x: -x["attacks"])[:5]

    bw = round(bytes_recv_mb / 1024, 2)

    stats = {
        "total":          total_n,
        "normal":         normal_n,
        "threat":         threat_n,
        "suspicious":     suspicious_n,
        "bytes_sent_mb":  bytes_sent_mb,
        "bytes_recv_mb":  bytes_recv_mb,
        "bandwidth_gbps": bw,
        "established":    sum(1 for c in raw_conns if getattr(c, "status", "") == "ESTABLISHED"),
        "listening":      sum(1 for c in raw_conns if getattr(c, "status", "") == "LISTEN"),
        "cat_counts":     cat_counts,
        "mode":           "live",
    }

    return {
        "events":        events,
        "stats":         stats,
        "top_services":  top_services,   # top offending ports/services
        "top_protocols": top_protocols,  # top offending processes
        "scan_time":     round(time.time() - t0, 2),
    }

# ── PUBLIC: KDD simulation IDS ────────────────────────────────────────────────
# Maps KDD attack categories → our user-friendly severity tiers
_KDD_TO_SEVERITY = {
    "Normal":  "Normal",
    "DoS":     "Threat",      # floods that crash services → Threat
    "Probe":   "Suspicious",  # scanning/recon → Suspicious
    "R2L":     "Threat",      # remote access attempts → Threat
    "U2R":     "Threat",      # privilege escalation → Threat
}

# Plain-English descriptions per KDD attack type (no jargon)
_KDD_PLAIN_ENGLISH = {
    "Normal": (
        "This looks like completely normal network activity. "
        "Nothing unusual was detected in this traffic sample."
    ),
    "DoS": (
        "This traffic pattern looks like an attempt to overwhelm a computer or server "
        "with so many requests that it stops responding. Think of it like someone "
        "repeatedly calling a phone line to keep it busy so no one else can get through."
    ),
    "Probe": (
        "This traffic looks like someone quietly checking what's running on a computer — "
        "like trying door handles to see which ones are unlocked. It's often the first "
        "step before a more serious attack."
    ),
    "R2L": (
        "This pattern suggests someone from outside is trying to get into a computer "
        "they shouldn't have access to — like trying different keys on a lock until "
        "one works, or sneaking in through a back door."
    ),
    "U2R": (
        "This looks like someone who already has limited access trying to gain full "
        "control of the computer — like a guest in a hotel trying to get a master key. "
        "This is one of the more serious attack types."
    ),
}

_KDD_THREAT_DESC = {
    "Normal":  "Normal traffic — no issues detected",
    "DoS":     "Traffic flood pattern — could be an attempt to crash a service",
    "Probe":   "Scanning activity — someone may be checking what's on this network",
    "R2L":     "Unauthorised access attempt from outside the network",
    "U2R":     "Attempt to gain full control of the system from a limited account",
}

def _get_ids_assets():
    global _ids_model, _ids_preprocessor, _kdd_X, _kdd_y, _kdd_raw_labels
    if _ids_model is None:
        import joblib
        _ids_model        = joblib.load(BASE / "ids_model.pkl")
        _ids_preprocessor = joblib.load(BASE / "preprocessor.pkl")
    if _kdd_X is None:
        df               = pd.read_csv(BASE / "KDDTest+.txt", names=_KDD_COLUMNS)
        _kdd_X           = df.drop(columns=["label", "difficulty"])
        _kdd_y           = df["label"].apply(lambda x: 0 if x == "normal" else 1)
        _kdd_raw_labels  = df["label"]
    return _ids_model, _ids_preprocessor, _kdd_X, _kdd_y, _kdd_raw_labels


def run_sim_ids(n: int = 30) -> Dict:
    """
    Runs the KDD-trained XGBoost model on a random sample of test data.
    Returns events in the same shape as run_live_ids so the UI is identical.
    """
    t0 = time.time()
    model, prep, X, y, raw_labels = _get_ids_assets()

    sample     = X.sample(n, random_state=int(time.time()) % 10000)
    true_bin   = y.loc[sample.index].values
    true_raw   = raw_labels.loc[sample.index].values
    processed  = prep.transform(sample)
    preds      = model.predict(processed)
    probas     = model.predict_proba(processed)

    events: List[Dict] = []
    cat_counts: Dict[str, int] = {"Normal": 0, "Warning": 0, "Suspicious": 0, "Threat": 0}

    for i, (idx, row) in enumerate(sample.iterrows()):
        pred        = int(preds[i])
        confidence  = round(float(max(probas[i])) * 100, 1)
        raw_lbl     = str(true_raw[i]).lower().strip()
        kdd_cat     = _ATTACK_CATEGORIES.get(raw_lbl, "Normal" if pred == 0 else "DoS")
        if pred == 0:
            kdd_cat = "Normal"

        severity    = _KDD_TO_SEVERITY.get(kdd_cat, "Suspicious")
        icon, color, cat_desc = _CATEGORY_META.get(severity, ("❓", "#64748b", "Unknown"))
        cat_counts[severity] = cat_counts.get(severity, 0) + 1

        # Build a human-readable "connection" from KDD features
        protocol = str(row["protocol_type"]).upper()
        service  = str(row["service"])
        flag     = str(row["flag"])
        src_b    = int(row["src_bytes"])
        dst_b    = int(row["dst_bytes"])

        threat_desc = _KDD_THREAT_DESC.get(kdd_cat, "Unknown pattern")
        plain_en    = _KDD_PLAIN_ENGLISH.get(kdd_cat, _KDD_PLAIN_ENGLISH["Normal"])

        events.append({
            "conn_id":       f"SIM-{i+1:03d}",
            "process":       f"{service} ({protocol})",
            "pid":           0,
            "local_port":    src_b,       # repurposed: show src_bytes as "local"
            "remote_ip":     "simulation",
            "remote_port":   dst_b,       # repurposed: show dst_bytes as "remote"
            "status":        flag,        # KDD flag field (SF, S0, REJ, etc.)
            "protocol":      protocol,
            "service":       service,
            "kdd_category":  kdd_cat,     # original KDD label (DoS/Probe/R2L/U2R)
            "prediction":    severity,    # Normal/Warning/Suspicious/Threat
            "category":      severity,
            "cat_desc":      cat_desc,
            "threat_desc":   threat_desc,
            "plain_english": plain_en,
            "all_flags":     [],
            "icon":          icon,
            "color":         color,
            "confidence":    confidence,
            "src_bytes":     src_b,
            "dst_bytes":     dst_b,
            "correct":       pred == int(true_bin[i]),
        })

    normal_n     = sum(1 for e in events if e["prediction"] == "Normal")
    threat_n     = sum(1 for e in events if e["prediction"] == "Threat")
    suspicious_n = sum(1 for e in events if e["prediction"] in ("Suspicious", "Warning"))
    correct_n    = sum(1 for e in events if e.get("correct", False))

    # top offending services / protocols
    svc_attacks: Dict[str, int] = {}
    svc_total:   Dict[str, int] = {}
    proto_attacks: Dict[str, int] = {}
    proto_total:   Dict[str, int] = {}
    for e in events:
        s = e["service"]
        p = e["protocol"]
        svc_total[s]   = svc_total.get(s, 0) + 1
        proto_total[p] = proto_total.get(p, 0) + 1
        if e["prediction"] != "Normal":
            svc_attacks[s]   = svc_attacks.get(s, 0) + 1
            proto_attacks[p] = proto_attacks.get(p, 0) + 1

    top_services = sorted(
        [{"name": k, "attacks": v, "total": svc_total[k]} for k, v in svc_attacks.items()],
        key=lambda x: -x["attacks"])[:5]
    top_protocols = sorted(
        [{"name": k, "attacks": v, "total": proto_total[k]} for k, v in proto_attacks.items()],
        key=lambda x: -x["attacks"])[:5]

    accuracy = round(correct_n / n * 100, 1)

    stats = {
        "total":          n,
        "normal":         normal_n,
        "threat":         threat_n,
        "suspicious":     suspicious_n,
        "accuracy":       accuracy,
        "bytes_sent_mb":  0,
        "bytes_recv_mb":  0,
        "bandwidth_gbps": 0,
        "established":    0,
        "listening":      0,
        "cat_counts":     cat_counts,
        "mode":           "simulation",
    }

    return {
        "events":        events,
        "stats":         stats,
        "top_services":  top_services,
        "top_protocols": top_protocols,
        "scan_time":     round(time.time() - t0, 2),
    }

# ── PUBLIC: real network stats via psutil ─────────────────────────────────────
def get_network_stats() -> Dict:
    """
    Returns real-time network I/O counters from psutil.
    Falls back gracefully if psutil is unavailable.
    """
    try:
        import psutil
        io = psutil.net_io_counters()
        conns = psutil.net_connections(kind="inet")
        # count by status
        established = sum(1 for c in conns if c.status == "ESTABLISHED")
        listening   = sum(1 for c in conns if c.status == "LISTEN")
        time_wait   = sum(1 for c in conns if c.status == "TIME_WAIT")
        # bytes → Mbps approximation (snapshot, not interval — used for display)
        bytes_sent_mb = round(io.bytes_sent / 1_048_576, 1)
        bytes_recv_mb = round(io.bytes_recv / 1_048_576, 1)
        return {
            "bytes_sent_mb":  bytes_sent_mb,
            "bytes_recv_mb":  bytes_recv_mb,
            "packets_sent":   io.packets_sent,
            "packets_recv":   io.packets_recv,
            "errin":          io.errin,
            "errout":         io.errout,
            "dropin":         io.dropin,
            "dropout":        io.dropout,
            "established":    established,
            "listening":      listening,
            "time_wait":      time_wait,
            "total_conns":    len(conns),
            "available":      True,
        }
    except Exception:
        return {"available": False}

# ── PORT EXPOSURE SCANNER ─────────────────────────────────────────────────────

# Ports that are dangerous if externally reachable
_DANGEROUS_PORTS: Dict[int, Dict] = {
    # Backdoor / RAT ports
    4444:  {"label": "Metasploit default",      "severity": "CRITICAL", "why": "This is the default port used by Metasploit, the most common hacking framework. If this is open, an attacker could have full control of your machine."},
    1337:  {"label": "Backdoor port",            "severity": "CRITICAL", "why": "Port 1337 is associated with remote access tools used by attackers to control a machine without the owner knowing."},
    31337: {"label": "Back Orifice backdoor",    "severity": "CRITICAL", "why": "This port was used by 'Back Orifice', a well-known hacking tool from the 90s that is still sometimes used today."},
    12345: {"label": "NetBus RAT",               "severity": "CRITICAL", "why": "Port 12345 is associated with NetBus, a remote access trojan that lets attackers control your computer remotely."},
    54321: {"label": "Back Orifice 2000",        "severity": "CRITICAL", "why": "Used by Back Orifice 2000, a tool that gives attackers silent remote control over a Windows machine."},
    # Unencrypted / legacy remote access
    23:    {"label": "Telnet (unencrypted)",     "severity": "HIGH",     "why": "Telnet sends everything including passwords in plain text. Anyone on the network can read your login credentials."},
    512:   {"label": "rexec (legacy remote)",    "severity": "HIGH",     "why": "An old remote execution service with no encryption. Should never be exposed on a modern machine."},
    513:   {"label": "rlogin (legacy remote)",   "severity": "HIGH",     "why": "An old remote login service. Replaced by SSH decades ago — its presence suggests something unusual is running."},
    # Container / dev services exposed
    2375:  {"label": "Docker (no TLS)",          "severity": "CRITICAL", "why": "Docker without TLS gives anyone who connects full control over all containers and potentially the host machine."},
    2376:  {"label": "Docker (TLS)",             "severity": "HIGH",     "why": "Docker with TLS is safer but still shouldn't be publicly reachable unless you specifically set this up."},
    # Database ports — should never be public
    3306:  {"label": "MySQL database",           "severity": "HIGH",     "why": "Your MySQL database is reachable. An attacker could attempt to log in and read or delete all your data."},
    5432:  {"label": "PostgreSQL database",      "severity": "HIGH",     "why": "Your PostgreSQL database is reachable. Databases should never be directly exposed to the network."},
    27017: {"label": "MongoDB (no auth)",        "severity": "CRITICAL", "why": "MongoDB on this port is often misconfigured with no authentication. Attackers actively scan for this."},
    6379:  {"label": "Redis (no auth)",          "severity": "CRITICAL", "why": "Redis has no authentication by default. If reachable, an attacker can read all cached data or use it to run commands."},
    # IRC / botnet
    6667:  {"label": "IRC / botnet C2",          "severity": "HIGH",     "why": "IRC port used by botnets to receive commands. A program on your machine may be waiting for instructions from an attacker."},
    6668:  {"label": "IRC / botnet C2",          "severity": "HIGH",     "why": "Same as above — IRC port associated with botnet command-and-control traffic."},
    # Amplification abuse
    11211: {"label": "Memcached (amplification)","severity": "HIGH",     "why": "Memcached on this port can be abused to launch massive DDoS attacks against other targets using your machine."},
    # RDP — high value target
    3389:  {"label": "Remote Desktop (RDP)",     "severity": "MEDIUM",   "why": "RDP lets someone control your desktop remotely. Attackers constantly scan for open RDP ports to brute-force passwords."},
    # VNC
    5900:  {"label": "VNC remote desktop",       "severity": "MEDIUM",   "why": "VNC is a remote desktop tool. If exposed, attackers can attempt to connect and view or control your screen."},
    5901:  {"label": "VNC remote desktop",       "severity": "MEDIUM",   "why": "Same as above — a second VNC display port."},
    # SMB — wormable
    445:   {"label": "Windows File Sharing (SMB)","severity": "MEDIUM",  "why": "SMB is used by WannaCry and other worms. It should never be reachable from outside your local network."},
    139:   {"label": "NetBIOS / SMB",            "severity": "MEDIUM",   "why": "An older Windows file sharing protocol. Externally reachable SMB is a common attack vector."},
}

# Ports that are expected and safe when open
_EXPECTED_SAFE_PORTS: set = {
    80, 443, 8080, 8443,          # web
    53,                            # DNS
    22,                            # SSH (acceptable)
    25, 587, 993, 995, 143, 110,  # email
    67, 68, 123,                   # DHCP, NTP
    135,                           # Windows RPC (internal)
    49152,                         # Windows ephemeral start
}

_SEV_ORDER_PORT = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}


def _socket_check(port: int, host: str = "127.0.0.1", timeout: float = 0.4) -> bool:
    """Returns True if the port accepts a TCP connection."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def run_port_scan(socket_verify: bool = True) -> Dict:
    """
    Two-phase port exposure scan:
      Phase 1 — psutil: get every LISTEN port + owning process name
      Phase 2 — socket: attempt TCP connect to each to confirm external reachability
    Cross-references results to produce per-port severity ratings.
    """
    import psutil, time
    t0 = time.time()

    # ── Phase 1: psutil listening ports ──────────────────────────────────────
    pid_names: Dict[int, str] = {}
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid_names[proc.info["pid"]] = proc.info["name"]
            except Exception:
                pass
    except Exception:
        pass

    listening: Dict[int, Dict] = {}   # port → {process, pid, proto}
    try:
        for conn in psutil.net_connections(kind="inet"):
            if getattr(conn, "status", "") == "LISTEN" and conn.laddr:
                port = conn.laddr.port
                pid  = conn.pid or 0
                if port not in listening:
                    listening[port] = {
                        "port":    port,
                        "process": pid_names.get(pid, f"pid-{pid}"),
                        "pid":     pid,
                        "proto":   "tcp",
                    }
    except Exception:
        pass

    # ── Phase 2: socket reachability check ───────────────────────────────────
    reachable_ports: set = set()
    if socket_verify:
        # Only check ports we know are listening (no need to scan blind)
        for port in list(listening.keys()):
            if _socket_check(port):
                reachable_ports.add(port)
    else:
        # If skipped, assume all listening ports are reachable
        reachable_ports = set(listening.keys())

    # ── Phase 3: classify each port ──────────────────────────────────────────
    ports_out: List[Dict] = []

    for port, info in listening.items():
        reachable = port in reachable_ports
        danger    = _DANGEROUS_PORTS.get(port)
        process   = info["process"]
        is_trusted_proc = process.lower() in _TRUSTED_PROCS

        if danger:
            if reachable:
                # Worst case: dangerous port AND reachable from outside
                severity = danger["severity"]
                status   = "exposed"
                headline = f"Dangerous port open and reachable — {danger['label']}"
                attacker_view = (
                    f"An attacker scanning your IP would find port {port} open. "
                    f"{danger['why']}"
                )
            else:
                # Listening but socket check failed — firewall may be blocking
                severity = "LOW"
                status   = "blocked"
                headline = f"Dangerous port listening but appears blocked — {danger['label']}"
                attacker_view = (
                    f"Port {port} ({danger['label']}) is running on your machine but "
                    f"a connection attempt was refused — your firewall may be protecting it. "
                    f"Still worth investigating why this service is running."
                )
        elif port in _EXPECTED_SAFE_PORTS:
            severity = "SAFE"
            status   = "expected"
            headline = f"Expected service — {_port_to_service(port)}"
            attacker_view = "This is a standard service port. Normal to see this open."
        elif reachable:
            # Unknown port, reachable
            severity = "INFO"
            status   = "exposed"
            headline = f"Unknown service reachable on port {port}"
            attacker_view = (
                f"Port {port} is open and reachable. It's not a known dangerous port, "
                f"but any open port is a potential entry point. "
                f"If you don't recognise '{process}', it's worth investigating."
            )
        else:
            severity = "SAFE"
            status   = "internal"
            headline = f"Internal service — {_port_to_service(port)}"
            attacker_view = "Listening internally but not reachable from outside."

        ports_out.append({
            "port":          port,
            "process":       process,
            "pid":           info["pid"],
            "proto":         info["proto"],
            "reachable":     reachable,
            "severity":      severity,
            "status":        status,
            "headline":      headline,
            "attacker_view": attacker_view,
            "label":         danger["label"] if danger else _port_to_service(port),
            "is_trusted":    is_trusted_proc,
        })

    # Sort: exposed dangerous first, then by severity
    _sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3, "LOW": 4, "SAFE": 5}
    ports_out.sort(key=lambda x: (
        0 if x["status"] == "exposed" else 1,
        _sev_rank.get(x["severity"], 9),
        x["port"]
    ))

    exposed   = [p for p in ports_out if p["status"] == "exposed" and p["severity"] not in ("SAFE","INFO")]
    risky     = [p for p in ports_out if p["status"] in ("exposed","blocked") and p["severity"] not in ("SAFE","INFO","LOW")]
    total_listening = len(listening)
    total_reachable = len(reachable_ports)

    return {
        "ports":            ports_out,
        "exposed":          exposed,
        "risky":            risky,
        "total_listening":  total_listening,
        "total_reachable":  total_reachable,
        "critical_n":       sum(1 for p in ports_out if p["severity"] == "CRITICAL" and p["reachable"]),
        "high_n":           sum(1 for p in ports_out if p["severity"] == "HIGH"     and p["reachable"]),
        "medium_n":         sum(1 for p in ports_out if p["severity"] == "MEDIUM"   and p["reachable"]),
        "scan_time":        round(time.time() - t0, 2),
        "socket_verified":  socket_verify,
    }
