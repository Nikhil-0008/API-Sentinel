import os
import re
import time
import uuid
import json
import sqlite3
import threading
import statistics
from collections import defaultdict, deque
from datetime import datetime

import requests
from flask import Flask, request, jsonify, Response, g

PROJECT_NAME = "API Sentinel"
AI_NAME = "Minion"
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:6000")
DB_PATH = os.path.join(os.path.dirname(__file__), "sentinel.db")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
AI_ENABLED = bool(OPENROUTER_API_KEY)
API_SPEC = {
    r"^/api/login$": {
        "methods": ["POST"],
        "auth_required": False,
        "rate_limit_per_min": 5,
        "allowed_response_fields": ["token", "error"],
    },
    r"^/api/users/\d+$": {
        "methods": ["GET"],
        "auth_required": True,
        "rate_limit_per_min": 30,
        "allowed_response_fields": ["id", "name", "email", "error"],
    },
    r"^/api/search$": {
        "methods": ["GET"],
        "auth_required": True,
        "rate_limit_per_min": 20,
        "allowed_response_fields": ["id", "name", "email", "error", "query_used"],
    },
    r"^/api/orders/\d+$": {
        "methods": ["GET"],
        "auth_required": True,
        "rate_limit_per_min": 15,
        "allowed_response_fields": ["order_id", "status", "total", "error"],
    },
}
INJECTION_PATTERNS = [
    (re.compile(r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+", re.I), "sqli_tautology", "SQL Injection"),
    (re.compile(r"UNION(\s+ALL)?\s+SELECT", re.I), "sqli_union", "SQL Injection"),
    (re.compile(r"DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO", re.I), "sqli_dml", "SQL Injection"),
    (re.compile(r"--\s|#\s*$|/\*.*\*/", re.I), "sqli_comment", "SQL Injection"),
    (re.compile(r"\$where|\$ne\s*:|\$gt\s*:", re.I), "nosqli_operator", "NoSQL Injection"),
    (re.compile(r";\s*(rm|cat|ls|wget|curl|nc)\s", re.I), "cmd_injection", "Command Injection"),
    (re.compile(r"<script[\s>]", re.I), "xss_script_tag", "XSS"),
]

WEIGHTS = {
    "auth_missing": 40,
    "method_not_in_spec": 15,
    "injection": 50,
    "rate_limit_exceeded": 30,
    "schema_violation": 20,
    "anomaly": 25,
    "unknown_endpoint": 10,
}
BLOCK_THRESHOLD = 50
THROTTLE_THRESHOLD = 20
AI_TRIGGER_THRESHOLD = 15
CORRELATION_WINDOW_SECONDS = 90
CORRELATION_MIN_EVENTS = 4

db_lock = threading.Lock()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, ts TEXT, client_id TEXT, method TEXT, path TEXT,
            status_code INTEGER, risk_score INTEGER, action TEXT, findings TEXT, latency_ms INTEGER,
            ai_verdict TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS blocked_clients (
            client_id TEXT PRIMARY KEY, blocked_at TEXT, reason TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS overrides (
            id TEXT PRIMARY KEY, ts TEXT, event_id TEXT, action TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY, client_id TEXT, first_seen TEXT, last_seen TEXT,
            attack_type TEXT, severity TEXT, request_count INTEGER, risk_score INTEGER,
            status TEXT, ai_summary TEXT, recommended_action TEXT, endpoints TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS ai_analyses (
            id TEXT PRIMARY KEY, ts TEXT, event_id TEXT, attack_type TEXT, severity TEXT,
            confidence INTEGER, explanation TEXT, intent TEXT, recommended_action TEXT,
            mitigation TEXT, incident_summary TEXT, source TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS shadow_apis (
            path TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, hit_count INTEGER, classification TEXT
        )
    """)
    conn.commit()
    conn.close()


def log_event(client_id, method, path, status_code, risk_score, action, findings, latency_ms, ai_verdict=""):
    event_id = str(uuid.uuid4())
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, datetime.utcnow().isoformat(), client_id, method, path,
             status_code, risk_score, action, json.dumps(findings), latency_ms, ai_verdict),
        )
        conn.commit()
        conn.close()
    return event_id


def update_event_ai_verdict(event_id, verdict_text):
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE events SET ai_verdict = ? WHERE id = ?", (verdict_text, event_id))
        conn.commit()
        conn.close()


def is_blocked(client_id):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT 1 FROM blocked_clients WHERE client_id = ?", (client_id,)).fetchone()
    conn.close()
    return row is not None


def block_client(client_id, reason):
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT OR REPLACE INTO blocked_clients VALUES (?,?,?)",
                     (client_id, datetime.utcnow().isoformat(), reason))
        conn.commit()
        conn.close()


def unblock_client(client_id):
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM blocked_clients WHERE client_id = ?", (client_id,))
        conn.commit()
        conn.close()


def save_ai_analysis(event_id, analysis, source):
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO ai_analyses VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), datetime.utcnow().isoformat(), event_id,
             analysis.get("attack_type", ""), analysis.get("severity", ""),
             int(analysis.get("confidence", 0) or 0), analysis.get("explanation", ""),
             analysis.get("intent", ""), analysis.get("recommended_action", ""),
             analysis.get("mitigation", ""), analysis.get("incident_summary", ""), source),
        )
        conn.commit()
        conn.close()


def upsert_incident(client_id, attack_type, severity, request_count, risk_score, endpoints, ai_summary, recommended_action):
    """Find an ACTIVE incident for this client+attack_type within the window, else create one."""
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM incidents WHERE client_id=? AND attack_type=? AND status='ACTIVE' ORDER BY last_seen DESC LIMIT 1",
            (client_id, attack_type),
        ).fetchone()
        now = datetime.utcnow().isoformat()
        if row:
            conn.execute(
                "UPDATE incidents SET last_seen=?, request_count=?, risk_score=?, severity=?, endpoints=?, ai_summary=?, recommended_action=? WHERE id=?",
                (now, request_count, risk_score, severity, json.dumps(endpoints), ai_summary, recommended_action, row["id"]),
            )
            incident_id = row["id"]
        else:
            incident_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (incident_id, client_id, now, now, attack_type, severity, request_count,
                 risk_score, "ACTIVE", ai_summary, recommended_action, json.dumps(endpoints)),
            )
        conn.commit()
        conn.close()
    return incident_id


def record_shadow_api(path):
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT hit_count FROM shadow_apis WHERE path=?", (path,)).fetchone()
        now = datetime.utcnow().isoformat()
        if row:
            conn.execute("UPDATE shadow_apis SET last_seen=?, hit_count=hit_count+1 WHERE path=?", (now, path))
        else:
            classification = classify_shadow_path(path)
            conn.execute("INSERT INTO shadow_apis VALUES (?,?,?,?,?)", (path, now, now, 1, classification))
        conn.commit()
        conn.close()


def classify_shadow_path(path):
    suspicious_markers = ("debug", "admin", "internal", "test", "backup", "config", "..")
    if any(m in path.lower() for m in suspicious_markers):
        return "SUSPICIOUS"
    return "UNDOCUMENTED"

class RateLimiter:
    def __init__(self):
        self.windows = defaultdict(deque)
        self.lock = threading.Lock()

    def hit(self, key, limit_per_min):
        now = time.time()
        with self.lock:
            dq = self.windows[key]
            dq.append(now)
            while dq and now - dq[0] > 60:
                dq.popleft()
            return len(dq) > limit_per_min


class AnomalyDetector:

    def __init__(self, history_len=20):
        self.history = defaultdict(lambda: deque(maxlen=history_len))
        self.minute_counts = defaultdict(int)
        self.current_minute = int(time.time() // 60)
        self.lock = threading.Lock()

    def record_and_check(self, client_id):
        minute = int(time.time() // 60)
        with self.lock:
            if minute != self.current_minute:
                for cid in list(self.minute_counts.keys()):
                    self.history[cid].append(self.minute_counts[cid])
                self.minute_counts = defaultdict(int)
                self.current_minute = minute

            self.minute_counts[client_id] += 1
            count_this_minute = self.minute_counts[client_id]
            hist = self.history[client_id]
            if len(hist) < 5:
                return False
            mean = statistics.mean(hist)
            stdev = statistics.pstdev(hist) or 1.0
            return (count_this_minute - mean) / stdev > 3


rate_limiter = RateLimiter()
anomaly_detector = AnomalyDetector()


def match_spec(path):
    for pattern, spec in API_SPEC.items():
        if re.match(pattern, path):
            return spec
    return None


def get_client_id():
    return request.headers.get("X-API-Key") or request.remote_addr or "unknown"

def _flatten(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _flatten(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _flatten(v)
    else:
        yield obj


def scan_for_injection(req):
    specific, attack_types = [], []
    haystacks = list(req.args.values()) + [req.path]
    if req.is_json:
        try:
            body = req.get_json(silent=True) or {}
            haystacks.extend(str(v) for v in _flatten(body))
        except Exception:
            pass
    for text in haystacks:
        if not isinstance(text, str):
            continue
        for pattern, label, attack_type in INJECTION_PATTERNS:
            if pattern.search(text):
                specific.append(label)
                attack_types.append(attack_type)
    return list(set(specific)), list(set(attack_types))


class DetectionEngine:
    def inspect_request(self, req, client_id):
        findings = []
        specific_labels, injected_attack_types = [], []
        spec = match_spec(req.path)

        if spec is None:
            findings.append("unknown_endpoint")
            record_shadow_api(req.path)
        else:
            if req.method not in spec["methods"]:
                findings.append("method_not_in_spec")
            if spec.get("auth_required") and not req.headers.get("Authorization") and not req.headers.get("X-API-Key"):
                findings.append("auth_missing")
            limit = spec.get("rate_limit_per_min", 60)
            if rate_limiter.hit(f"{client_id}:{req.path}", limit):
                findings.append("rate_limit_exceeded")

        specific_labels, injected_attack_types = scan_for_injection(req)
        if specific_labels:
            findings.append("injection")
            findings.extend(specific_labels)
        if anomaly_detector.record_and_check(client_id):
            findings.append("anomaly")

        score = sum(WEIGHTS[f] for f in findings if f in WEIGHTS)
        return score, findings, injected_attack_types

    def inspect_response(self, path, payload):
        """Excessive-data-exposure check: redact any field the spec doesn't allow."""
        spec = match_spec(path)
        if spec is None or not isinstance(payload, dict):
            return payload, []
        allowed = set(spec.get("allowed_response_fields", []))
        leaked = [k for k in payload.keys() if k not in allowed]
        if leaked:
            return {k: v for k, v in payload.items() if k in allowed}, ["schema_violation:" + ",".join(leaked)]
        return payload, []


detection_engine = DetectionEngine()


class IncidentCorrelator:

    def __init__(self):
        self.client_windows = defaultdict(deque)
        self.lock = threading.Lock()

    def record(self, client_id, path, findings, injected_attack_types, score):
        now = time.time()
        with self.lock:
            dq = self.client_windows[client_id]
            dq.append((now, path, findings, injected_attack_types))
            while dq and now - dq[0][0] > CORRELATION_WINDOW_SECONDS:
                dq.popleft()
            if len(dq) < CORRELATION_MIN_EVENTS:
                return None
            events = list(dq)

        attack_type = self._classify(events)
        endpoints = sorted(set(e[1] for e in events))
        max_score = max(score, WEIGHTS.get("injection", 0))
        severity = "CRITICAL" if attack_type in ("SQL Injection", "Command Injection") else \
                   "HIGH" if len(events) >= 8 else "MEDIUM"

        return {
            "attack_type": attack_type,
            "severity": severity,
            "request_count": len(events),
            "risk_score": max_score,
            "endpoints": endpoints,
        }

    def _classify(self, events):
        all_attack_types = [t for _, _, _, ats in events for t in ats]
        if all_attack_types:
            return max(set(all_attack_types), key=all_attack_types.count)
        all_findings = [f for _, _, findings, _ in events for f in findings]
        if all_findings.count("rate_limit_exceeded") >= 2:
            return "Rate Limit Abuse"
        paths = [p for _, p, _, _ in events]
        if len(set(re.sub(r"\d+", "#", p) for p in paths)) == 1 and len(set(paths)) >= 3:
            return "BOLA / IDOR"
        if all_findings.count("unknown_endpoint") >= 3:
            return "Reconnaissance"
        if all_findings.count("anomaly") >= 2:
            return "Anomalous Behavior"
        return "API Abuse"


incident_correlator = IncidentCorrelator()
def compute_endpoint_scores():
    """Returns a list of {path, score, risk_level, weaknesses, recommendations}."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT path, COUNT(*) req_count, AVG(risk_score) avg_risk,
               SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) blocked_count,
               findings
        FROM events GROUP BY path
    """).fetchall()
    # gather all findings per path
    finding_map = defaultdict(list)
    for r in conn.execute("SELECT path, findings FROM events"):
        try:
            finding_map[r[0]].extend(json.loads(r[1]))
        except Exception:
            pass
    incident_counts = defaultdict(int)
    for r in conn.execute("SELECT endpoints FROM incidents"):
        try:
            for ep in json.loads(r[0]):
                incident_counts[ep] += 1
        except Exception:
            pass
    conn.close()

    results = []
    for r in rows:
        path = r["path"]
        findings = finding_map.get(path, [])
        spec = match_spec(path)
        undocumented = spec is None
        score = 100
        weaknesses = []
        if "auth_missing" in findings:
            score -= 25
            weaknesses.append("Requests observed without authentication")
        if any(f.startswith("sqli") for f in findings) or "injection" in findings:
            score -= 30
            weaknesses.append("Injection attempts detected against this endpoint")
        if "rate_limit_exceeded" in findings:
            score -= 10
            weaknesses.append("Clients repeatedly exceeding the rate limit")
        if any(f.startswith("schema_violation") for f in findings):
            score -= 15
            weaknesses.append("Response has leaked fields outside the declared schema")
        if "anomaly" in findings:
            score -= 10
            weaknesses.append("Abnormal traffic bursts detected")
        if undocumented:
            score -= 20
            weaknesses.append("Endpoint is not declared in the API specification (shadow API)")
        score -= min(15, incident_counts.get(path, 0) * 5)
        score = max(0, min(100, score))

        recs = []
        if "auth_missing" in findings:
            recs.append("Enforce authentication at the gateway, not just in the backend")
        if any(f.startswith("sqli") for f in findings):
            recs.append("Use parameterized queries; never string-concatenate SQL")
        if "rate_limit_exceeded" in findings:
            recs.append("Tighten the per-client rate limit for this endpoint")
        if any(f.startswith("schema_violation") for f in findings):
            recs.append("Whitelist response fields explicitly; strip everything else")
        if undocumented:
            recs.append("Document this endpoint in the API spec or retire it if unintended")
        if not recs:
            recs.append("No major issues observed -- keep monitoring")

        risk_level = "CRITICAL" if score < 40 else "HIGH" if score < 60 else "MEDIUM" if score < 80 else "LOW"
        results.append({
            "path": path,
            "requests": r["req_count"],
            "threats": len([f for f in findings if f in WEIGHTS]),
            "score": score,
            "risk_level": risk_level,
            "status": "SHADOW" if undocumented else "DOCUMENTED",
            "weaknesses": weaknesses,
            "recommendations": recs,
        })
    return sorted(results, key=lambda x: x["score"])


ANALYST_SYSTEM_PROMPT = f"""You are {AI_NAME}, the AI security analyst embedded in {PROJECT_NAME}, \
an API security gateway. You are given a single structured security event (endpoint, method, \
parameters, which detection rules fired, risk score, client id, recent related events, response/schema \
violations, and prior suspicious behavior from this client). Analyze it and respond with ONLY a JSON \
object, no prose, no markdown fences, matching exactly this shape:
{{"attack_type": "", "severity": "LOW|MEDIUM|HIGH|CRITICAL", "confidence": 0, "explanation": "", \
"intent": "", "recommended_action": "ALLOW|THROTTLE|BLOCK", "mitigation": "", "incident_summary": ""}}
attack_type must be one of: SQL Injection, NoSQL Injection, XSS, Command Injection, Broken Authentication, \
BOLA / IDOR, API Abuse, Credential Stuffing, Enumeration, Rate Limit Abuse, Data Exfiltration, \
Reconnaissance, Anomalous Behavior, Unknown/Other."""

CHAT_SYSTEM_PROMPT = f"""You are {AI_NAME}, the AI security analyst chat assistant inside {PROJECT_NAME}, \
a hackathon API security gateway project. You ONLY discuss: this project, its architecture, the security \
events/incidents/scores it has recorded, why a specific request was allowed/throttled/blocked, and general \
API security concepts directly relevant to it. You have access to a summary of recent events/incidents \
which will be given to you as context -- use it to give specific, concrete answers (cite the actual \
client id, path, risk score, or attack type when relevant). If the user asks anything outside this scope \
(personal topics, relationships, opinions unrelated to the project, general chit-chat, or anything not \
about {PROJECT_NAME}/API security), reply with exactly: "I can't help with that — it's outside of my \
limits as {PROJECT_NAME}'s security analyst. Ask me about a blocked request, an incident, or the \
platform itself." Keep answers concise and confident, like a real SOC analyst."""


def _openrouter_call(messages, max_tokens=500):
    if not AI_ENABLED:
        return None
    try:
        resp = requests.post(
            OPENROUTER_URL,
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
            },
            json={"model": OPENROUTER_MODEL, "messages": messages, "max_tokens": max_tokens, "temperature": 0.3},
            timeout=12,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[{AI_NAME}] OpenRouter call failed, falling back: {e}")
        return None


def _fallback_analysis(event_context):
    """Deterministic explanation used when the AI is unavailable/disabled."""
    findings = event_context.get("findings", [])
    action = event_context.get("action", "allow")
    if any(f.startswith("sqli") for f in findings) or "sqli_union" in findings:
        attack_type, expl = "SQL Injection", "The request parameters matched known SQL injection patterns (tautologies, UNION SELECT, or SQL comment terminators)."
    elif "nosqli_operator" in findings:
        attack_type, expl = "NoSQL Injection", "MongoDB-style query operators ($where/$ne/$gt) were found in the input."
    elif "cmd_injection" in findings:
        attack_type, expl = "Command Injection", "Shell metacharacters and command names were found chained onto the input."
    elif "xss_script_tag" in findings:
        attack_type, expl = "XSS", "A <script> tag was found in the input, consistent with a cross-site scripting attempt."
    elif "auth_missing" in findings:
        attack_type, expl = "Broken Authentication", "This endpoint requires authentication and none was supplied."
    elif "rate_limit_exceeded" in findings:
        attack_type, expl = "Rate Limit Abuse", "This client exceeded the allowed request rate for this endpoint."
    elif "unknown_endpoint" in findings:
        attack_type, expl = "Reconnaissance", "This endpoint isn't in the declared API spec -- traffic here often means probing/scanning."
    elif any(f.startswith("schema_violation") for f in findings):
        leaked = next((f.split(":", 1)[1] for f in findings if f.startswith("schema_violation")), "extra fields")
        attack_type, expl = "Data Exfiltration", f"The backend response included fields outside the declared schema ({leaked}) -- API Sentinel redacted them before they reached the client."
    elif "anomaly" in findings:
        attack_type, expl = "Anomalous Behavior", "This client's request rate is a statistical outlier compared to its own history."
    else:
        attack_type, expl = "Unknown/Other", "General risk signals were present without a single dominant pattern."
    return {
        "attack_type": attack_type,
        "severity": "HIGH" if action == "blocked" else "MEDIUM" if action == "throttle" else "LOW",
        "confidence": 60,
        "explanation": expl,
        "intent": "Likely automated probing or an attack tool" if action != "allow" else "No malicious intent indicated",
        "recommended_action": action.upper() if action in ("block", "throttle", "allow") else "ALLOW",
        "mitigation": "Deterministic rules already handled this request; see recommendations on the endpoint's score card.",
        "incident_summary": f"{attack_type} pattern observed from this client (rule-engine fallback, AI analyst unavailable).",
    }


def ai_analyze_event(event_context):
    """event_context: dict with endpoint, method, params, findings, risk_score, client_id, action, recent_events"""
    raw = _openrouter_call([
        {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(event_context)},
    ])
    if raw is None:
        return _fallback_analysis(event_context), "fallback"
    try:
        cleaned = raw.strip().strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
        return json.loads(cleaned), "openrouter"
    except Exception:
        return _fallback_analysis(event_context), "fallback"


def ai_chat(user_message, context_summary):
    if not AI_ENABLED:
        return (f"Hi, I'm {AI_NAME}. My OpenRouter connection isn't configured right now "
                f"(no OPENROUTER_API_KEY set), so I can only give you rule-based answers. "
                f"Based on the recent events I can see: {context_summary}")
    raw = _openrouter_call([
        {"role": "system", "content": CHAT_SYSTEM_PROMPT},
        {"role": "user", "content": f"Context on recent activity:\n{context_summary}\n\nUser question: {user_message}"},
    ], max_tokens=350)
    if raw is None:
        return f"I'm having trouble reaching my AI backend right now, but here's what the logs show: {context_summary}"
    return raw.strip()

class ControlSystem:
    def decide(self, score):
        if score >= BLOCK_THRESHOLD:
            return "block"
        if score >= THROTTLE_THRESHOLD:
            return "throttle"
        return "allow"

    def enforce(self, action, score):
        if action == "throttle":
            delay = min(2.0, 0.05 * (score - THROTTLE_THRESHOLD + 1))
            time.sleep(delay)


control_system = ControlSystem()
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>API Sentinel &middot; SOC Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  :root {
    --bg:#0a0e14; --panel:#111826; --panel2:#0d1420; --border:#1e2a3a; --text:#e7edf5;
    --muted:#8b98ac; --green:#3fd47a; --yellow:#f2b84b; --red:#ff5d6c; --blue:#5ba8ff; --purple:#b18cff;
    --accent:#00e5c7;
  }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; background:radial-gradient(circle at 20% 0%, #0f1a2b 0%, var(--bg) 45%); color:var(--text); padding:22px 26px 60px; }
  h1 { font-size:22px; margin:0; letter-spacing:.02em; display:flex; align-items:center; gap:10px; }
  h1 .tag { font-size:11px; background:linear-gradient(90deg,var(--accent),var(--blue)); color:#00201c; padding:2px 8px; border-radius:20px; font-weight:700; letter-spacing:.06em; }
  .sub { color:var(--muted); font-size:12.5px; margin:4px 0 20px; }
  .stats { display:grid; grid-template-columns:repeat(8,1fr); gap:12px; margin-bottom:22px; }
  .stat { background:linear-gradient(180deg,var(--panel),var(--panel2)); border:1px solid var(--border); border-radius:10px; padding:12px 14px; }
  .stat .num { font-size:22px; font-weight:700; }
  .stat .label { font-size:10.5px; color:var(--muted); margin-top:2px; text-transform:uppercase; letter-spacing:.04em; }
  .threat-LOW{color:var(--green)} .threat-MEDIUM{color:var(--yellow)} .threat-HIGH{color:#ff8a5c} .threat-CRITICAL{color:var(--red)}
  .grid { display:grid; grid-template-columns:1.5fr 1fr; gap:18px; align-items:start; }
  .panel { background:linear-gradient(180deg,var(--panel),var(--panel2)); border:1px solid var(--border); border-radius:12px; padding:16px; overflow:hidden; margin-bottom:18px; }
  .panel h2 { font-size:12.5px; margin:0 0 12px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; display:flex; justify-content:space-between; align-items:center; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  th { text-align:left; color:var(--muted); font-weight:500; padding:6px 8px; border-bottom:1px solid var(--border); }
  td { padding:6px 8px; border-bottom:1px solid #16202e; vertical-align:top; }
  tr:hover td { background:#141f30; }
  .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:10.5px; font-weight:700; }
  .badge.allow { background:rgba(63,212,122,.15); color:var(--green); }
  .badge.throttle { background:rgba(242,184,75,.15); color:var(--yellow); }
  .badge.blocked, .badge.blocked_repeat_offender { background:rgba(255,93,108,.15); color:var(--red); }
  .badge.ACTIVE { background:rgba(255,93,108,.15); color:var(--red); }
  .badge.MITIGATED { background:rgba(242,184,75,.15); color:var(--yellow); }
  .badge.RESOLVED { background:rgba(63,212,122,.15); color:var(--green); }
  .badge.SHADOW, .badge.SUSPICIOUS { background:rgba(177,140,255,.18); color:var(--purple); }
  .badge.DOCUMENTED, .badge.UNDOCUMENTED { background:rgba(91,168,255,.15); color:var(--blue); }
  .finding-tag { display:inline-block; background:#182333; border:1px solid var(--border); border-radius:4px; padding:1px 6px; margin:1px 2px 1px 0; font-size:10px; }
  .risk-bar-bg { background:#182333; border-radius:4px; height:6px; width:50px; overflow:hidden; }
  .risk-bar { height:100%; }
  .path-mono { font-family:ui-monospace,SFMono-Regular,monospace; font-size:11.5px; }
  button.unblock, button.demo-btn { background:linear-gradient(90deg,var(--accent),var(--blue)); border:none; color:#001b17; font-size:11px; font-weight:700; padding:6px 12px; border-radius:7px; cursor:pointer; }
  button.unblock:hover, button.demo-btn:hover { opacity:.85; }
  .empty { color:var(--muted); font-size:12px; padding:8px 0; }
  .live-dot { display:inline-block; width:7px; height:7px; border-radius:50%; background:var(--green); margin-right:2px; animation:pulse 1.6s infinite; }
  @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.3; } }
  .demo-row { display:flex; flex-wrap:wrap; gap:8px; }
  .ai-verdict { color:var(--accent); font-size:11px; }
  .score-cell { font-weight:700; }
  .full-row { grid-column:1 / -1; }
  canvas#pie { max-height:230px; }

  /* Minion chat widget */
  #minion-bubble { position:fixed; bottom:22px; right:22px; width:56px; height:56px; border-radius:50%;
    background:linear-gradient(135deg,var(--accent),var(--blue)); display:flex; align-items:center; justify-content:center;
    font-size:24px; cursor:pointer; box-shadow:0 6px 20px rgba(0,0,0,.4); z-index:999; }
  #minion-window { position:fixed; bottom:90px; right:22px; width:340px; height:440px; background:var(--panel);
    border:1px solid var(--border); border-radius:14px; display:none; flex-direction:column; overflow:hidden;
    box-shadow:0 10px 40px rgba(0,0,0,.5); z-index:999; }
  #minion-header { background:linear-gradient(90deg,var(--accent),var(--blue)); color:#001b17; padding:10px 14px; font-weight:700; font-size:13px; display:flex; justify-content:space-between; align-items:center; }
  #minion-messages { flex:1; overflow-y:auto; padding:10px 12px; display:flex; flex-direction:column; gap:8px; font-size:12.5px; }
  .msg { padding:8px 10px; border-radius:10px; max-width:85%; line-height:1.4; }
  .msg.bot { background:#182333; align-self:flex-start; border:1px solid var(--border); }
  .msg.user { background:linear-gradient(90deg,var(--accent),var(--blue)); color:#001b17; align-self:flex-end; font-weight:600; }
  #minion-input-row { display:flex; border-top:1px solid var(--border); }
  #minion-input { flex:1; background:var(--panel2); border:none; color:var(--text); padding:10px; font-size:12.5px; outline:none; }
  #minion-send { background:var(--accent); border:none; color:#001b17; font-weight:700; padding:0 14px; cursor:pointer; }
</style>
</head>
<body>

<h1><span class="live-dot"></span>API Sentinel <span class="tag">SOC</span></h1>
<div class="sub">Intelligent API security gateway &mdash; detection, correlation, AI analysis, and shadow API discovery, all in one place.</div>

<div class="stats" id="stats"></div>

<div class="grid">
  <div>
    <div class="panel">
      <h2>Live Attack Feed</h2>
      <table>
        <thead><tr><th>Time</th><th>Client</th><th>Endpoint</th><th>Attack</th><th>Risk</th><th>Action</th><th>AI Verdict</th></tr></thead>
        <tbody id="events-body"></tbody>
      </table>
    </div>

    <div class="panel">
      <h2>Active Incidents</h2>
      <table>
        <thead><tr><th>Attack Type</th><th>Client</th><th>Severity</th><th>Reqs</th><th>Status</th><th>Summary</th></tr></thead>
        <tbody id="incidents-body"></tbody>
      </table>
    </div>

    <div class="panel">
      <h2>Endpoint Security Scores</h2>
      <table>
        <thead><tr><th>Endpoint</th><th>Reqs</th><th>Threats</th><th>Score</th><th>Status</th></tr></thead>
        <tbody id="scores-body"></tbody>
      </table>
    </div>
  </div>

  <div>
    <div class="panel">
      <h2>Attack Distribution</h2>
      <canvas id="pie"></canvas>
    </div>

    <div class="panel">
      <h2>Shadow / Undocumented APIs</h2>
      <table>
        <thead><tr><th>Path</th><th>Hits</th><th>Class</th></tr></thead>
        <tbody id="shadow-body"></tbody>
      </table>
    </div>

    <div class="panel">
      <h2>Blocklist</h2>
      <table>
        <thead><tr><th>Client</th><th>Reason</th><th></th></tr></thead>
        <tbody id="blocked-body"></tbody>
      </table>
    </div>

    <div class="panel">
      <h2>Attack Replay / Demo Mode</h2>
      <div class="demo-row" id="demo-buttons"></div>
    </div>
  </div>
</div>

<div id="minion-bubble" onclick="toggleMinion()">🤖</div>
<div id="minion-window">
  <div id="minion-header"><span>🤖 Minion &middot; Security Analyst</span><span style="cursor:pointer" onclick="toggleMinion()">&times;</span></div>
  <div id="minion-messages"></div>
  <div id="minion-input-row">
    <input id="minion-input" placeholder="Ask why something was blocked..." onkeydown="if(event.key==='Enter')sendMinion()">
    <button id="minion-send" onclick="sendMinion()">Send</button>
  </div>
</div>

<script>
const DEMO_ATTACKS = [
  ["sqli","SQL Injection"], ["xss","XSS"], ["bola","BOLA Enumeration"],
  ["rate","Rate Limit Abuse"], ["cmdi","Command Injection"],
  ["unknown","Unknown Endpoint"], ["noauth","Missing Auth"]
];
document.getElementById('demo-buttons').innerHTML = DEMO_ATTACKS.map(([id,label]) =>
  `<button class="demo-btn" onclick="runDemo('${id}')">${label}</button>`).join('');

async function runDemo(attackType) {
  await fetch('/api/security/demo/' + attackType, { method: 'POST' });
  setTimeout(refreshAll, 500);
}

function riskColor(score) { if (score >= 50) return 'var(--red)'; if (score >= 20) return 'var(--yellow)'; return 'var(--green)'; }
function fmtTime(iso) { try { return new Date(iso + 'Z').toLocaleTimeString(); } catch(e){ return iso; } }
function renderFindings(list) { if (!list || list.length === 0) return '<span class="empty">&mdash;</span>'; return list.slice(0,3).map(f => `<span class="finding-tag">${f}</span>`).join(''); }

let pieChart = null;

async function refreshStats() {
  const s = await (await fetch('/api/security/stats')).json();
  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="num">${s.total_requests}</div><div class="label">Total Requests</div></div>
    <div class="stat"><div class="num" style="color:var(--red)">${s.blocked_requests}</div><div class="label">Blocked</div></div>
    <div class="stat"><div class="num" style="color:var(--yellow)">${s.suspicious_requests}</div><div class="label">Suspicious</div></div>
    <div class="stat"><div class="num" style="color:var(--red)">${s.active_incidents}</div><div class="label">Active Incidents</div></div>
    <div class="stat"><div class="num">${s.attack_attempts}</div><div class="label">Attack Attempts</div></div>
    <div class="stat"><div class="num" style="color:var(--purple)">${s.shadow_apis}</div><div class="label">Shadow APIs</div></div>
    <div class="stat"><div class="num threat-${s.threat_level}">${s.threat_level}</div><div class="label">Threat Level</div></div>
    <div class="stat"><div class="num">${s.api_security_score}</div><div class="label">API Security Score</div></div>
  `;
}

async function refreshEvents() {
  const rows = await (await fetch('/api/security/events')).json();
  const body = document.getElementById('events-body');
  if (rows.length === 0) { body.innerHTML = '<tr><td colspan="7" class="empty">No traffic yet.</td></tr>'; return; }
  body.innerHTML = rows.map(e => `
    <tr>
      <td>${fmtTime(e.ts)}</td><td class="path-mono">${e.client_id}</td><td class="path-mono">${e.path}</td>
      <td>${renderFindings(e.findings)}</td>
      <td><div style="display:flex; align-items:center; gap:6px;"><div class="risk-bar-bg"><div class="risk-bar" style="width:${Math.min(100,e.risk_score)}%; background:${riskColor(e.risk_score)}"></div></div>${e.risk_score}</div></td>
      <td><span class="badge ${e.action}">${e.action}</span></td>
      <td class="ai-verdict">${e.ai_verdict || '&mdash;'}</td>
    </tr>`).join('');
}

async function refreshIncidents() {
  const rows = await (await fetch('/api/security/incidents')).json();
  const body = document.getElementById('incidents-body');
  if (rows.length === 0) { body.innerHTML = '<tr><td colspan="6" class="empty">No incidents yet.</td></tr>'; return; }
  body.innerHTML = rows.map(i => `
    <tr>
      <td>${i.attack_type}</td><td class="path-mono">${i.client_id}</td>
      <td class="threat-${i.severity}">${i.severity}</td><td>${i.request_count}</td>
      <td><span class="badge ${i.status}">${i.status}</span></td>
      <td style="max-width:260px">${i.ai_summary || ''}</td>
    </tr>`).join('');
}

async function refreshScores() {
  const rows = await (await fetch('/api/security/scores')).json();
  const body = document.getElementById('scores-body');
  if (rows.length === 0) { body.innerHTML = '<tr><td colspan="5" class="empty">No endpoints observed yet.</td></tr>'; return; }
  body.innerHTML = rows.map(r => `
    <tr>
      <td class="path-mono">${r.path}</td><td>${r.requests}</td><td>${r.threats}</td>
      <td class="score-cell threat-${r.risk_level}">${r.score}</td>
      <td><span class="badge ${r.status}">${r.status}</span></td>
    </tr>`).join('');
}

async function refreshShadow() {
  const rows = await (await fetch('/api/security/shadow-apis')).json();
  const body = document.getElementById('shadow-body');
  if (rows.length === 0) { body.innerHTML = '<tr><td colspan="3" class="empty">None discovered yet.</td></tr>'; return; }
  body.innerHTML = rows.map(r => `
    <tr><td class="path-mono">${r.path}</td><td>${r.hit_count}</td><td><span class="badge ${r.classification}">${r.classification}</span></td></tr>`).join('');
}

async function refreshBlocked() {
  const rows = await (await fetch('/api/security/blocked')).json();
  const body = document.getElementById('blocked-body');
  if (rows.length === 0) { body.innerHTML = '<tr><td colspan="3" class="empty">No clients blocked.</td></tr>'; return; }
  body.innerHTML = rows.map(r => `
    <tr><td class="path-mono">${r.client_id}</td><td>${r.reason}</td>
    <td><button class="unblock" onclick="unblock('${r.client_id}')">Unblock</button></td></tr>`).join('');
}

async function refreshDistribution() {
  const dist = await (await fetch('/api/security/attack-distribution')).json();
  const labels = Object.keys(dist);
  const values = Object.values(dist);
  const colors = ['#ff5d6c','#f2b84b','#b18cff','#5ba8ff','#3fd47a','#00e5c7','#ff8a5c','#8b98ac'];
  const ctx = document.getElementById('pie');
  if (labels.length === 0) { if (pieChart) { pieChart.destroy(); pieChart=null; } return; }
  const cfg = { type:'pie', data:{ labels, datasets:[{ data:values, backgroundColor: colors }] },
    options:{ plugins:{ legend:{ labels:{ color:'#e7edf5', font:{size:10.5} } } } } };
  if (pieChart) { pieChart.data = cfg.data; pieChart.update(); } else { pieChart = new Chart(ctx, cfg); }
}

async function unblock(clientId) {
  await fetch('/api/security/unblock', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({client_id:clientId}) });
  refreshBlocked(); refreshStats();
}

function refreshAll() { refreshStats(); refreshEvents(); refreshIncidents(); refreshScores(); refreshShadow(); refreshBlocked(); refreshDistribution(); }
refreshAll();
setInterval(refreshAll, 2500);

// ---- Minion chat widget ----
let minionOpen = false;
function toggleMinion() {
  minionOpen = !minionOpen;
  document.getElementById('minion-window').style.display = minionOpen ? 'flex' : 'none';
  if (minionOpen && document.getElementById('minion-messages').children.length === 0) {
    addMinionMsg("bot", "Hi, I'm Minion 🤖 — API Sentinel's AI security analyst. Ask me why a request was blocked, about an active incident, or how the platform works.");
  }
}
function addMinionMsg(role, text) {
  const box = document.getElementById('minion-messages');
  const div = document.createElement('div');
  div.className = 'msg ' + role;
  div.textContent = text;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}
async function sendMinion() {
  const input = document.getElementById('minion-input');
  const text = input.value.trim();
  if (!text) return;
  addMinionMsg('user', text);
  input.value = '';
  addMinionMsg('bot', '...');
  const box = document.getElementById('minion-messages');
  const thinking = box.lastChild;
  try {
    const res = await fetch('/api/security/chat', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ message: text }) });
    const data = await res.json();
    thinking.textContent = data.reply;
  } catch (e) {
    thinking.textContent = "I couldn't reach the analysis backend just now -- try again in a moment.";
  }
}
</script>
</body>
</html>"""

DEMO_DB_PATH = os.path.join(os.path.dirname(__file__), "demo_backend.db")
demo_app = Flask("demo_backend")


def init_demo_db():
    if os.path.exists(DEMO_DB_PATH):
        os.remove(DEMO_DB_PATH)
    conn = sqlite3.connect(DEMO_DB_PATH)
    conn.execute("""CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT,
                     password_hash TEXT, ssn TEXT)""")
    conn.executemany("INSERT INTO users VALUES (?,?,?,?,?)", [
        (1, "Alice Rao", "alice@example.com", "5f4dcc3b5aa765d61d8327deb882cf99", "123-45-6789"),
        (2, "Ben Kumar", "ben@example.com", "e10adc3949ba59abbe56e057f20f883e", "234-56-7890"),
        (3, "Chen Wei", "chen@example.com", "25d55ad283aa400af464c76d713c07ad", "345-67-8901"),
    ])
    conn.commit()
    conn.close()


@demo_app.route("/api/login", methods=["POST"])
def demo_login():
    data = request.get_json(silent=True) or {}
    if data.get("username") == "admin" and data.get("password") == "admin123":
        return jsonify({"token": "static-demo-token-never-expires"})
    return jsonify({"error": "invalid credentials"}), 401


@demo_app.route("/api/users/<user_id>", methods=["GET"])
def demo_get_user(user_id):
    conn = sqlite3.connect(DEMO_DB_PATH)
    row = conn.execute("SELECT id, name, email, password_hash, ssn FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row[0], "name": row[1], "email": row[2], "password_hash": row[3], "ssn": row[4]})


@demo_app.route("/api/search", methods=["GET"])
def demo_search():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DEMO_DB_PATH)
    query = f"SELECT id, name, email FROM users WHERE name LIKE '%{q}%'"
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.Error as e:
        conn.close()
        return jsonify({"error": str(e), "query_used": query}), 500
    conn.close()
    return jsonify([{"id": r[0], "name": r[1], "email": r[2]} for r in rows])


@demo_app.route("/api/orders/<order_id>", methods=["GET"])
def demo_get_order(order_id):
    return jsonify({"order_id": order_id, "status": "shipped", "total": 42.50})


def run_demo_backend():
    init_demo_db()
    demo_app.run(host="0.0.0.0", port=6000, debug=False, use_reloader=False)



app = Flask("api_sentinel")

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "content-encoding",
}


def _recent_events_for_client(client_id, limit=5):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT ts, method, path, risk_score, action, findings FROM events WHERE client_id=? ORDER BY ts DESC LIMIT ?",
        (client_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _maybe_run_ai_and_correlate(event_id, client_id, req, score, findings, injected_attack_types, action):
    correlation = incident_correlator.record(client_id, req.path, findings, injected_attack_types, score)

    analysis = None
    if score >= AI_TRIGGER_THRESHOLD:
        event_context = {
            "endpoint": req.path,
            "method": req.method,
            "params": dict(req.args),
            "rules_triggered": findings,
            "risk_score": score,
            "client_id": client_id,
            "action": action,
            "recent_related_events": _recent_events_for_client(client_id),
        }
        analysis, source = ai_analyze_event(event_context)
        save_ai_analysis(event_id, analysis, source)
        verdict = f"[{analysis.get('attack_type','?')}] {analysis.get('explanation','')}"[:180]
        update_event_ai_verdict(event_id, verdict)

    if correlation:
        default_summary = f"{correlation['attack_type']} campaign detected: {correlation['request_count']} related requests from this client in the last {CORRELATION_WINDOW_SECONDS}s."
        upsert_incident(
            client_id=client_id,
            attack_type=correlation["attack_type"],
            severity=correlation["severity"],
            request_count=correlation["request_count"],
            risk_score=correlation["risk_score"],
            endpoints=correlation["endpoints"],
            ai_summary=(analysis or {}).get("incident_summary") or default_summary,
            recommended_action=(analysis or {}).get("recommended_action", action.upper()),
        )


@app.route("/api/<path:subpath>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def gateway(subpath):
    start = time.time()
    path = "/api/" + subpath
    client_id = get_client_id()

    if is_blocked(client_id):
        latency_ms = int((time.time() - start) * 1000)
        log_event(client_id, request.method, path, 403, 100, "blocked_repeat_offender", ["client_blocklisted"], latency_ms)
        return jsonify({"error": "blocked", "reason": "client is on the blocklist"}), 403

    score, findings, injected_attack_types = detection_engine.inspect_request(request, client_id)
    action = control_system.decide(score)

    if action == "block":
        if "injection" in findings or "rate_limit_exceeded" in findings:
            block_client(client_id, reason=",".join(findings))
        latency_ms = int((time.time() - start) * 1000)
        event_id = log_event(client_id, request.method, path, 403, score, "blocked", findings, latency_ms)
        _maybe_run_ai_and_correlate(event_id, client_id, request, score, findings, injected_attack_types, action)
        return jsonify({"error": "request blocked by API Sentinel", "findings": findings}), 403

    control_system.enforce(action, score)

    try:
        backend_resp = requests.request(
            method=request.method,
            url=BACKEND_URL + path,
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            params=request.args,
            data=request.get_data(),
            timeout=10,
        )
    except requests.RequestException as e:
        latency_ms = int((time.time() - start) * 1000)
        log_event(client_id, request.method, path, 502, score, action + "+backend_error", findings, latency_ms)
        return jsonify({"error": "backend unreachable", "detail": str(e)}), 502

    findings_out = list(findings)
    body_to_return = backend_resp.content
    try:
        payload = backend_resp.json()
        redacted, exposure_findings = detection_engine.inspect_response(path, payload)
        if exposure_findings:
            findings_out.extend(exposure_findings)
            score += WEIGHTS["schema_violation"]
            body_to_return = json.dumps(redacted).encode()
    except ValueError:
        pass

    latency_ms = int((time.time() - start) * 1000)
    event_id = log_event(client_id, request.method, path, backend_resp.status_code, score, action, findings_out, latency_ms)
    _maybe_run_ai_and_correlate(event_id, client_id, request, score, findings_out, injected_attack_types, action)

    out_headers = [(k, v) for k, v in backend_resp.headers.items() if k.lower() not in HOP_BY_HOP_HEADERS]
    return Response(body_to_return, status=backend_resp.status_code, headers=out_headers)

@app.route("/")
def dashboard():
    return DASHBOARD_HTML


@app.route("/api/security/events")
def api_events():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY ts DESC LIMIT 200").fetchall()]
    conn.close()
    for r in rows:
        r["findings"] = json.loads(r["findings"])
    return jsonify(rows)


@app.route("/api/security/incidents")
def api_incidents():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM incidents ORDER BY last_seen DESC LIMIT 100").fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/security/incidents/<incident_id>")
def api_incident_detail(incident_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


@app.route("/api/security/scores")
def api_scores():
    return jsonify(compute_endpoint_scores())


@app.route("/api/security/shadow-apis")
def api_shadow_apis():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM shadow_apis ORDER BY hit_count DESC").fetchall()]
    conn.close()
    return jsonify(rows)


@app.route("/api/security/attack-distribution")
def api_attack_distribution():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT findings FROM events WHERE action != 'allow'").fetchall()
    conn.close()
    counts = defaultdict(int)
    label_map = {l: t for _, l, t in INJECTION_PATTERNS}
    for (findings_json,) in rows:
        try:
            findings = json.loads(findings_json)
        except Exception:
            continue
        mapped = False
        for f in findings:
            if f in label_map:
                counts[label_map[f]] += 1
                mapped = True
        if not mapped:
            if "auth_missing" in findings:
                counts["Broken Authentication"] += 1
            elif "rate_limit_exceeded" in findings:
                counts["Rate Limit Abuse"] += 1
            elif "unknown_endpoint" in findings:
                counts["Reconnaissance"] += 1
            elif "anomaly" in findings:
                counts["Anomalous Behavior"] += 1
    return jsonify(dict(counts))

@app.route("/api/security/timeline")
def api_timeline():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT substr(ts,1,16) as minute, COUNT(*),
               SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END)
        FROM events GROUP BY minute ORDER BY minute DESC LIMIT 60
    """).fetchall()
    conn.close()
    return jsonify([{"minute": r[0], "requests": r[1], "blocked": r[2]} for r in reversed(rows)])

@app.route("/api/security/blocked")
def api_blocked():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM blocked_clients ORDER BY blocked_at DESC").fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/security/unblock", methods=["POST"])
def api_unblock():
    client_id = (request.json or {}).get("client_id")
    unblock_client(client_id)
    with db_lock:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO overrides VALUES (?,?,?,?)",
                     (str(uuid.uuid4()), datetime.utcnow().isoformat(), client_id, "manual_unblock"))
        conn.commit()
        conn.close()
    return jsonify({"status": "unblocked", "client_id": client_id})

@app.route("/api/security/ai-analysis/<event_id>")
def api_ai_analysis(event_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM ai_analyses WHERE event_id=? ORDER BY ts DESC LIMIT 1", (event_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "no analysis for this event"}), 404
    return jsonify(dict(row))

@app.route("/api/security/stats")
def api_stats():
    conn = sqlite3.connect(DB_PATH)
    total, avg_risk = conn.execute("SELECT COUNT(*), AVG(risk_score) FROM events").fetchone()
    blocked = conn.execute("SELECT COUNT(*) FROM events WHERE action LIKE 'blocked%'").fetchone()[0]
    suspicious = conn.execute("SELECT COUNT(*) FROM events WHERE risk_score >= ?", (AI_TRIGGER_THRESHOLD,)).fetchone()[0]
    active_incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE status='ACTIVE'").fetchone()[0]
    shadow_count = conn.execute("SELECT COUNT(*) FROM shadow_apis").fetchone()[0]
    attack_attempts = conn.execute("SELECT COUNT(*) FROM events WHERE risk_score >= ?", (THROTTLE_THRESHOLD,)).fetchone()[0]
    conn.close()

    scores = compute_endpoint_scores()
    api_security_score = round(sum(s["score"] for s in scores) / len(scores)) if scores else 100
    avg_risk = round(avg_risk or 0, 1)
    threat_level = "CRITICAL" if avg_risk >= 50 or active_incidents >= 3 else \
                   "HIGH" if avg_risk >= 30 or active_incidents >= 1 else \
                   "MEDIUM" if avg_risk >= 10 else "LOW"

    return jsonify({
        "total_requests": total or 0,
        "blocked_requests": blocked or 0,
        "suspicious_requests": suspicious or 0,
        "active_incidents": active_incidents or 0,
        "attack_attempts": attack_attempts or 0,
        "shadow_apis": shadow_count or 0,
        "threat_level": threat_level,
        "api_security_score": api_security_score,
    })


@app.route("/api/security/chat", methods=["POST"])
def api_chat():
    message = (request.json or {}).get("message", "").strip()
    if not message:
        return jsonify({"reply": "Ask me something about a blocked request, an incident, or the platform."})

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    recent = [dict(r) for r in conn.execute(
        "SELECT ts, client_id, path, risk_score, action, findings, ai_verdict FROM events ORDER BY ts DESC LIMIT 8"
    ).fetchall()]
    incidents = [dict(r) for r in conn.execute(
        "SELECT attack_type, client_id, severity, status, ai_summary FROM incidents ORDER BY last_seen DESC LIMIT 5"
    ).fetchall()]
    conn.close()

    lines = []
    for e in recent:
        lines.append(f"- {e['ts']} {e['client_id']} {e['path']} risk={e['risk_score']} action={e['action']} verdict={e['ai_verdict']}")
    for i in incidents:
        lines.append(f"- INCIDENT [{i['status']}] {i['attack_type']} from {i['client_id']} ({i['severity']}): {i['ai_summary']}")
    context_summary = "\n".join(lines) if lines else "No security events recorded yet."

    reply = ai_chat(message, context_summary)
    return jsonify({"reply": reply})


# ---- Attack Replay / Demo Mode ----
# Each simulated attack uses its own client id. This keeps demos independent --
# e.g. clicking "SQL Injection" (which gets its simulated client blocklisted, as
# it should) won't cause the next demo click to be short-circuited as a
# repeat-offender before detection even runs.

def _fire(method, path, client_id, **kwargs):
    headers = kwargs.pop("headers", {"X-API-Key": client_id})
    try:
        requests.request(method, f"http://localhost:5000{path}", headers=headers, timeout=5, **kwargs)
    except Exception as e:
        print(f"[demo] request failed: {e}")


def _run_demo_attack(attack_type):
    cid = f"demo-{attack_type}"
    unblock_client(cid)  # start each demo run from a clean slate
    if attack_type == "sqli":
        for q in ["test", "'", "' OR 1=1 --", "' UNION SELECT 1,2,3 --"]:
            _fire("GET", "/api/search", cid, params={"q": q})
    elif attack_type == "xss":
        for q in ["hello", "<script>alert(1)</script>", "<script>document.cookie</script>"]:
            _fire("GET", "/api/search", cid, params={"q": q})
    elif attack_type == "bola":
        for uid in range(1, 8):
            _fire("GET", f"/api/users/{uid}", cid)
    elif attack_type == "rate":
        for _ in range(25):
            _fire("GET", "/api/orders/1", cid)
    elif attack_type == "cmdi":
        for q in ["file.txt", "file.txt; cat /etc/passwd", "file.txt; rm -rf /"]:
            _fire("GET", "/api/search", cid, params={"q": q})
    elif attack_type == "unknown":
        for p in ["/api/debug", "/api/admin/export", "/api/internal/users", "/api/config"]:
            _fire("GET", p, cid)
    elif attack_type == "noauth":
        for uid in range(1, 5):
            _fire("GET", f"/api/users/{uid}", cid, headers={})
    else:
        return False
    return True


@app.route("/api/security/demo/<attack_type>", methods=["POST"])
def api_demo(attack_type):
    ok = _run_demo_attack(attack_type)
    if not ok:
        return jsonify({"error": "unknown demo attack type"}), 400
    return jsonify({"status": "fired", "attack_type": attack_type})


# ---- Backward-compatible aliases for the original /api/_shield/* routes ----
app.add_url_rule("/api/_shield/stats", "shield_stats_alias", api_stats)
app.add_url_rule("/api/_shield/events", "shield_events_alias", api_events)
app.add_url_rule("/api/_shield/blocked", "shield_blocked_alias", api_blocked)
app.add_url_rule("/api/_shield/unblock", "shield_unblock_alias", api_unblock, methods=["POST"])




if __name__ == "__main__":
    init_db()

    if BACKEND_URL == "http://localhost:6000":
        threading.Thread(target=run_demo_backend, daemon=True).start()
        time.sleep(1.0)

    print(f"{PROJECT_NAME} gateway running on http://localhost:5000")
    print("dashboard:                    http://localhost:5000/")
    print("send traffic through:         http://localhost:5000/api/...")
    print(f"proxying to backend:          {BACKEND_URL}")
    print(f"AI analyst ({AI_NAME}):       {'ENABLED via OpenRouter (' + OPENROUTER_MODEL + ')' if AI_ENABLED else 'DISABLED (set OPENROUTER_API_KEY to enable) -- fallback rules still explain every block'}")
    app.run(host="0.0.0.0", port=5000, debug=False)
