from flask import Flask, jsonify, request, render_template_string
import jwt
import os
import urllib.request
import json
from datetime import datetime
import threading

app = Flask(__name__)

SECRET_KEY = os.environ.get('JWT_SECRET', 'fallback-secret-key')

# This list stores all access events in memory
events = []
events_lock = threading.Lock()

def log_event(service, action, decision, reason, door):
    event = {
        "id": len(events) + 1,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "service": service,
        "action": action,
        "decision": decision,  # "ALLOWED" or "BLOCKED"
        "reason": reason,
        "door": door
    }
    with events_lock:
        events.append(event)
    return event

def verify_token(req):
    auth_header = req.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, "No token provided"
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "Token has expired"
    except jwt.InvalidTokenError:
        return None, "Invalid token"

def check_opa(service, action):
    opa_input = {"input": {"service": service, "action": action}}
    data = json.dumps(opa_input).encode('utf-8')
    try:
        req = urllib.request.Request(
            'http://opa:8181/v1/data/authz/allow',
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=3) as response:
            result = json.loads(response.read())
            return result.get('result', False)
    except Exception as e:
        print(f"OPA error: {e}")
        return False

@app.route('/health')
def health():
    return jsonify({"service": "dashboard", "status": "running"})

# This endpoint receives logs from other services
@app.route('/log', methods=['POST'])
def receive_log():
    data = request.get_json()
    event = log_event(
        service=data.get('service', 'unknown'),
        action=data.get('action', 'unknown'),
        decision=data.get('decision', 'UNKNOWN'),
        reason=data.get('reason', ''),
        door=data.get('door', '')
    )
    return jsonify({"logged": True, "event": event})

# This endpoint returns all events as JSON
@app.route('/events')
def get_events():
    with events_lock:
        return jsonify(list(reversed(events)))

# Simulate an attack for demo purposes
@app.route('/simulate-attack')
def simulate_attack():
    # patient-service trying to access admin — should be blocked
    allowed = check_opa('patient-service', 'read:admin')
    decision = "ALLOWED" if allowed else "BLOCKED"
    event = log_event(
        service="patient-service",
        action="read:admin",
        decision=decision,
        reason="OPA policy: patient-service cannot access admin",
        door="Door 3 - OPA Policy"
    )
    return jsonify({
        "simulated": True,
        "event": event
    })

# Simulate a normal allowed request
@app.route('/simulate-normal')
def simulate_normal():
    allowed = check_opa('patient-service', 'read:patients')
    decision = "ALLOWED" if allowed else "BLOCKED"
    event = log_event(
        service="patient-service",
        action="read:patients",
        decision=decision,
        reason="Valid token and OPA policy approved",
        door="All 3 doors passed"
    )
    return jsonify({
        "simulated": True,
        "event": event
    })

# The main dashboard page
@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

DASHBOARD_HTML = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero Trust Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', sans-serif;
            background: #0a0e1a;
            color: #e0e6f0;
            min-height: 100vh;
        }

        header {
            background: #0d1226;
            border-bottom: 1px solid #1e2d4a;
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        header h1 {
            font-size: 20px;
            color: #4a9eff;
            letter-spacing: 0.05em;
        }

        .live-dot {
            width: 10px; height: 10px;
            background: #22c55e;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
            animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }

        .stats-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 16px;
            padding: 24px;
        }

        .stat-card {
            background: #0d1226;
            border: 1px solid #1e2d4a;
            border-radius: 12px;
            padding: 16px;
            text-align: center;
        }

        .stat-number {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 4px;
        }

        .stat-label {
            font-size: 12px;
            color: #6b7fa3;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .green { color: #22c55e; }
        .red { color: #ef4444; }
        .blue { color: #4a9eff; }
        .yellow { color: #f59e0b; }

        .controls {
            padding: 0 24px 16px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }

        button {
            padding: 10px 20px;
            border-radius: 8px;
            border: none;
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: opacity 0.15s;
        }

        button:hover { opacity: 0.85; }

        .btn-attack {
            background: #ef4444;
            color: white;
        }

        .btn-normal {
            background: #22c55e;
            color: white;
        }

        .btn-clear {
            background: #1e2d4a;
            color: #e0e6f0;
        }

        .feed-section {
            padding: 0 24px 24px;
        }

        .feed-title {
            font-size: 13px;
            color: #6b7fa3;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 12px;
        }

        .event-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .event-row {
            background: #0d1226;
            border: 1px solid #1e2d4a;
            border-radius: 10px;
            padding: 12px 16px;
            display: grid;
            grid-template-columns: 80px 140px 1fr 1fr 100px;
            gap: 12px;
            align-items: center;
            font-size: 13px;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-8px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .event-row.allowed {
            border-left: 3px solid #22c55e;
        }

        .event-row.blocked {
            border-left: 3px solid #ef4444;
        }

        .badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 99px;
            font-size: 11px;
            font-weight: 600;
            text-align: center;
        }

        .badge-allowed {
            background: #14532d;
            color: #22c55e;
        }

        .badge-blocked {
            background: #450a0a;
            color: #ef4444;
        }

        .time { color: #6b7fa3; font-size: 12px; }
        .service-name { color: #4a9eff; font-weight: 500; }
        .action-name { color: #e0e6f0; }
        .reason-text { color: #6b7fa3; font-size: 12px; }

        .empty-state {
            text-align: center;
            padding: 48px;
            color: #6b7fa3;
        }

        .empty-state p { margin-top: 8px; font-size: 13px; }
    </style>
</head>
<body>

<header>
    <h1>🔐 Zero Trust Network — Live Dashboard</h1>
    <div>
        <span class="live-dot"></span>
        <span style="font-size:13px; color:#6b7fa3">Live monitoring</span>
    </div>
</header>

<div class="stats-row">
    <div class="stat-card">
        <div class="stat-number blue" id="total">0</div>
        <div class="stat-label">Total Requests</div>
    </div>
    <div class="stat-card">
        <div class="stat-number green" id="allowed">0</div>
        <div class="stat-label">Allowed</div>
    </div>
    <div class="stat-card">
        <div class="stat-number red" id="blocked">0</div>
        <div class="stat-label">Blocked</div>
    </div>
    <div class="stat-card">
        <div class="stat-number yellow" id="services">0</div>
        <div class="stat-label">Active Services</div>
    </div>
</div>

<div class="controls">
    <button class="btn-attack" onclick="simulateAttack()">
        🔴 Simulate Attack
    </button>
    <button class="btn-normal" onclick="simulateNormal()">
        🟢 Simulate Normal Request
    </button>
    <button class="btn-clear" onclick="clearEvents()">
        Clear Feed
    </button>
</div>

<div class="feed-section">
    <div class="feed-title">Live Access Feed</div>
    <div class="event-list" id="event-list">
        <div class="empty-state">
            <div style="font-size:32px">🛡️</div>
            <p>No events yet. Click a button above to simulate requests.</p>
        </div>
    </div>
</div>

<script>
    let localEvents = [];

    async function fetchEvents() {
        try {
            const res = await fetch('/events');
            const data = await res.json();
            if (data.length !== localEvents.length) {
                localEvents = data;
                renderEvents();
            }
        } catch(e) {}
    }

    function renderEvents() {
        const list = document.getElementById('event-list');

        if (localEvents.length === 0) {
            list.innerHTML = `
                <div class="empty-state">
                    <div style="font-size:32px">🛡️</div>
                    <p>No events yet. Click a button above to simulate requests.</p>
                </div>`;
            updateStats(0, 0, 0, 0);
            return;
        }

        const allowed = localEvents.filter(e => e.decision === 'ALLOWED').length;
        const blocked = localEvents.filter(e => e.decision === 'BLOCKED').length;
        const services = new Set(localEvents.map(e => e.service)).size;
        updateStats(localEvents.length, allowed, blocked, services);

        list.innerHTML = localEvents.map(e => `
            <div class="event-row ${e.decision.toLowerCase()}">
                <span class="time">${e.timestamp.split(' ')[1]}</span>
                <span class="service-name">${e.service}</span>
                <span class="action-name">${e.action}</span>
                <span class="reason-text">${e.reason}</span>
                <span class="badge badge-${e.decision.toLowerCase()}">${e.decision}</span>
            </div>
        `).join('');
    }

    function updateStats(total, allowed, blocked, services) {
        document.getElementById('total').textContent = total;
        document.getElementById('allowed').textContent = allowed;
        document.getElementById('blocked').textContent = blocked;
        document.getElementById('services').textContent = services;
    }

    async function simulateAttack() {
        await fetch('/simulate-attack');
        await fetchEvents();
    }

    async function simulateNormal() {
        await fetch('/simulate-normal');
        await fetchEvents();
    }

    function clearEvents() {
        localEvents = [];
        renderEvents();
    }

    // Refresh every 2 seconds automatically
    setInterval(fetchEvents, 2000);
    fetchEvents();
</script>

</body>
</html>
'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)