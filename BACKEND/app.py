import os
import random
import re
import time
from flask import Flask, jsonify, render_template_string, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

current_state = {
    "network_status": "NORMAL",
    "threat_level": "SAFE",
    "risk_score": 12,
    "packet_count": 1420,
    "connection_count": 8,
    "bandwidth_mbps": 1.4,
    "active_protocol": "HTTPS / TLS 1.3",
    "compromised_node": None,
    "security_checks": {
        "ssl_status": "Secure (Valid Cert)",
        "ip_host": "Domain Resolved",
        "heuristic_entropy": "Normal (Low)",
        "iot_signature": "Clean / Whitelisted"
    },
    "logs": [
        "[INFO] IoT Digital Twin Mesh synchronized.",
        "[MONITOR] Edge Gateway routing telemetry steady."
    ]
}

def analyze_target(url, attack_type=None):
    global current_state
    timestamp = time.strftime("%H:%M:%S")
    
    if attack_type == "botnet" or "botnet" in url.lower():
        current_state["network_status"] = "UNDER ATTACK"
        current_state["threat_level"] = "CRITICAL: Mirai Botnet Flood"
        current_state["risk_score"] = 96
        current_state["compromised_node"] = "node_esp32_1"
        current_state["packet_count"] += random.randint(450, 800)
        current_state["connection_count"] = random.randint(85, 120)
        current_state["bandwidth_mbps"] = round(random.uniform(45.2, 88.7), 2)
        current_state["active_protocol"] = "SYN Flood / Raw TCP"
        current_state["security_checks"] = {
            "ssl_status": "Bypassed / Missing",
            "ip_host": "Raw IP Detected",
            "heuristic_entropy": "High Suspicion (9.4)",
            "iot_signature": "MIRAI_IOT_C2_SIGNATURE"
        }
        current_state["logs"].append(f"[{timestamp}] [ANOMALY] High SYN flood on Node-ESP32-01 (Port 8080).")
        current_state["logs"].append(f"[{timestamp}] [ZERO-TRUST] Link severed! Quarantined Node-ESP32-01.")
        
    elif attack_type == "phishing" or any(k in url.lower() for k in ["login", "verify", "account", "update"]):
        current_state["network_status"] = "UNDER ATTACK"
        current_state["threat_level"] = "HIGH: Credential Harvester"
        current_state["risk_score"] = 84
        current_state["compromised_node"] = "node_cam"
        current_state["packet_count"] += random.randint(60, 120)
        current_state["connection_count"] = random.randint(18, 35)
        current_state["bandwidth_mbps"] = round(random.uniform(5.1, 12.3), 2)
        current_state["active_protocol"] = "HTTP Insecure / Form Hijack"
        current_state["security_checks"] = {
            "ssl_status": "Self-Signed / Untrusted",
            "ip_host": "Suspicious Homograph Host",
            "heuristic_entropy": "High Lexical Anomaly",
            "iot_signature": "PHISH_PORTAL_MATCH"
        }
        current_state["logs"].append(f"[{timestamp}] [ALERT] Rogue RTSP / HTTP tunnel detected on SmartCam.")
        current_state["logs"].append(f"[{timestamp}] [ISOLATION] Zero-trust rule enforced on RTSP stream.")
        
    else:
        current_state["network_status"] = "NORMAL"
        current_state["threat_level"] = "SAFE"
        current_state["risk_score"] = random.randint(5, 18)
        current_state["compromised_node"] = None
        current_state["packet_count"] += random.randint(10, 25)
        current_state["connection_count"] = random.randint(4, 9)
        current_state["bandwidth_mbps"] = round(random.uniform(0.8, 2.1), 2)
        current_state["active_protocol"] = "HTTPS / TLS 1.3"
        current_state["security_checks"] = {
            "ssl_status": "Verified (CA Validated)",
            "ip_host": "Clean Domain Route",
            "heuristic_entropy": "Safe Baseline (1.2)",
            "iot_signature": "No Anomaly Detected"
        }
        current_state["logs"].append(f"[{timestamp}] [SYNC] Mesh heartbeat ping verified (All nodes safe).")

    current_state["logs"] = current_state["logs"][-7:]
    return current_state

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IoT AI Cybersecurity Operations Center (SOC)</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg: #070b14;
      --card-bg: #0f172a;
      --border: #1e293b;
      --accent-blue: #38bdf8;
      --safe-green: #10b981;
      --danger-red: #f43f5e;
      --text-main: #f8fafc;
      --text-sub: #94a3b8;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text-main);
      margin: 0;
      padding: 20px;
    }
    .header-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 16px;
      margin-bottom: 20px;
      border-bottom: 1px solid var(--border);
    }
    .status-badge {
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.5px;
      background: rgba(16, 185, 129, 0.15);
      color: var(--safe-green);
      border: 1px solid var(--safe-green);
    }
    .panel-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
      margin-bottom: 18px;
    }
    .scanner-flex {
      display: flex;
      gap: 10px;
      margin-bottom: 12px;
    }
    .scanner-flex input {
      flex: 1;
      padding: 10px 14px;
      background: #090e17;
      border: 1px solid #334155;
      color: #fff;
      border-radius: 8px;
      outline: none;
    }
    .scan-btn {
      background: #0284c7;
      color: #fff;
      border: none;
      padding: 10px 20px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
    }
    .chip-btn {
      background: #1e293b;
      color: #cbd5e1;
      border: 1px solid #334155;
      padding: 6px 14px;
      border-radius: 16px;
      font-size: 12px;
      cursor: pointer;
      margin-right: 8px;
    }
    .chip-btn:hover { border-color: var(--accent-blue); color: #fff; }

    /* Telemetry grid */
    .metric-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 14px;
      margin-bottom: 18px;
    }
    .stat-box {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
    }
    .stat-label { font-size: 11px; text-transform: uppercase; color: var(--text-sub); }
    .stat-val { font-size: 24px; font-weight: 700; margin-top: 6px; }

    /* Visual Mesh Layout */
    .visual-grid {
      display: grid;
      grid-template-columns: 1.4fr 1fr;
      gap: 18px;
      margin-bottom: 18px;
    }
    #topologyCanvas {
      width: 100%;
      height: 290px;
      background: #050811;
      border-radius: 8px;
      border: 1px solid #1e293b;
      display: block;
    }
    .terminal-box {
      background: #04070e;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 12px;
      font-family: 'Courier New', monospace;
      font-size: 12px;
      height: 120px;
      overflow-y: auto;
    }
    .node-legend {
      display: flex;
      gap: 16px;
      font-size: 12px;
      color: var(--text-sub);
      margin-top: 8px;
    }
    .legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 4px; }
  </style>
</head>
<body>

  <div class="header-bar">
    <div>
      <h2 style="margin: 0; font-size: 20px; letter-spacing: 0.5px;">IoT AI CYBERSECURITY OPERATIONS CENTER</h2>
      <span style="font-size: 12px; color: var(--text-sub);">Zero-Trust Dynamic Mesh Topology & Hardware Threat Intelligence</span>
    </div>
    <div id="liveBadge" class="status-badge">SYSTEM SECURE</div>
  </div>

  <!-- Simulation Control -->
  <div class="panel-card">
    <div class="scanner-flex">
      <input type="text" id="targetInput" placeholder="Inspect payload URL or target IP (e.g. 192.168.1.105:8080)...">
      <button class="scan-btn" onclick="submitScan()">Analyze Vector</button>
    </div>
    <div>
      <span style="font-size: 12px; color: var(--text-sub); margin-right: 8px;">Simulation Vectors:</span>
      <button class="chip-btn" onclick="triggerPreset('safe')">🟢 Legitimate Ping</button>
      <button class="chip-btn" onclick="triggerPreset('phishing')">🟡 Web Cam Form Hijack</button>
      <button class="chip-btn" onclick="triggerPreset('botnet')">🔴 Mirai Botnet Node Infiltration</button>
    </div>
  </div>

  <!-- Stats Grid -->
  <div class="metric-grid">
    <div class="stat-box">
      <div class="stat-label">Network State</div>
      <div id="statStatus" class="stat-val" style="color: var(--safe-green);">NORMAL</div>
    </div>
    <div class="stat-box">
      <div class="stat-label">AI Threat Confidence</div>
      <div id="statRisk" class="stat-val" style="color: var(--safe-green);">12%</div>
    </div>
    <div class="stat-box">
      <div class="stat-label">Live Packet Flow</div>
      <div id="statPackets" class="stat-val">1,420</div>
    </div>
    <div class="stat-box">
      <div class="stat-label">Bandwidth Load</div>
      <div id="statBandwidth" class="stat-val">1.4 MB/s</div>
    </div>
  </div>

  <!-- Visual Mesh Diagram + Telemetry Chart -->
  <div class="visual-grid">
    <div class="panel-card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <span style="font-size: 13px; font-weight: 600; color: #cbd5e1;">LIVE IOT TOPOLOGY (DIGITAL TWIN MESH)</span>
        <span id="meshAlert" style="font-size: 11px; color: var(--safe-green);">● ALL NODES OPERATIONAL</span>
      </div>
      <canvas id="topologyCanvas" width="600" height="290"></canvas>
      <div class="node-legend">
        <span><span class="legend-dot" style="background: #38bdf8;"></span>Gateway</span>
        <span><span class="legend-dot" style="background: #10b981;"></span>Active Mesh Link</span>
        <span><span class="legend-dot" style="background: #f43f5e;"></span>Quarantined Node (Zero-Trust)</span>
      </div>
    </div>

    <div class="panel-card">
      <span style="font-size: 13px; font-weight: 600; color: #cbd5e1;">PACKET SURGE ANOMALY DETECTOR</span>
      <div style="margin-top: 14px;">
        <canvas id="trafficChart" height="180"></canvas>
      </div>
    </div>
  </div>

  <!-- Realtime Threat Audit Logs -->
  <div class="panel-card">
    <span style="font-size: 12px; font-weight: 600; color: var(--text-sub);">ZERO-TRUST ISOLATION & KERNEL AUDIT TRAIL</span>
    <div class="terminal-box" id="terminalLogs" style="margin-top: 10px;"></div>
  </div>

  <script>
    // 1. TOPOLOGY CANVAS SETUP
    const canvas = document.getElementById('topologyCanvas');
    const ctx = canvas.getContext('2d');

    const nodes = {
      cloud: { x: 90, y: 145, label: "Cloud C2", type: "cloud", status: "safe" },
      gateway: { x: 260, y: 145, label: "Edge Gateway (Pi)", type: "gw", status: "safe" },
      node_esp32_1: { x: 470, y: 65, label: "Node-ESP32-01", type: "sensor", status: "safe" },
      node_esp32_2: { x: 490, y: 145, label: "Node-ESP32-02", type: "sensor", status: "safe" },
      node_cam: { x: 470, y: 225, label: "SmartCam Node", type: "cam", status: "safe" }
    };

    let pulseOffset = 0;
    let compromisedNodeKey = null;

    function drawTopology() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Links: Cloud -> Gateway
      drawLink(nodes.cloud, nodes.gateway, false);

      // Links: Gateway -> Leaf Nodes
      for (let key of ['node_esp32_1', 'node_esp32_2', 'node_cam']) {
        const isCut = (compromisedNodeKey === key);
        drawLink(nodes.gateway, nodes[key], isCut);
      }

      // Draw Nodes
      for (let key in nodes) {
        drawNode(nodes[key], key === compromisedNodeKey);
      }

      pulseOffset += 0.8;
      requestAnimationFrame(drawTopology);
    }

    function drawLink(n1, n2, isSevered) {
      ctx.beginPath();
      ctx.moveTo(n1.x, n1.y);
      ctx.lineTo(n2.x, n2.y);
      if (isSevered) {
        ctx.strokeStyle = "rgba(244, 63, 94, 0.4)";
        ctx.setLineDash([4, 4]);
        ctx.lineWidth = 1.5;
        ctx.stroke();
        ctx.setLineDash([]);
        // Red Quarantine X
        const midX = (n1.x + n2.x) / 2;
        const midY = (n1.y + n2.y) / 2;
        ctx.fillStyle = "#f43f5e";
        ctx.font = "bold 13px sans-serif";
        ctx.fillText("✕ QUARANTINED", midX - 35, midY - 6);
      } else {
        ctx.strokeStyle = "rgba(56, 189, 248, 0.25)";
        ctx.lineWidth = 2;
        ctx.stroke();

        // Moving Data Packet Particles
        const t = ((pulseOffset % 40) / 40);
        const px = n1.x + (n2.x - n1.x) * t;
        const py = n1.y + (n2.y - n1.y) * t;
        ctx.beginPath();
        ctx.arc(px, py, 3, 0, Math.PI * 2);
        ctx.fillStyle = "#10b981";
        ctx.fill();
      }
    }

    function drawNode(n, isCompromised) {
      ctx.beginPath();
      ctx.arc(n.x, n.y, 16, 0, Math.PI * 2);
      ctx.fillStyle = isCompromised ? "#f43f5e" : "#0f172a";
      ctx.fill();
      ctx.lineWidth = 2;
      ctx.strokeStyle = isCompromised ? "#fda4af" : (n.type === 'gw' ? "#38bdf8" : "#10b981");
      ctx.stroke();

      // Pulsing Aura if under attack
      if (isCompromised) {
        ctx.beginPath();
        ctx.arc(n.x, n.y, 24 + Math.sin(pulseOffset * 0.15) * 4, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(244, 63, 94, 0.5)";
        ctx.lineWidth = 2;
        ctx.stroke();
      }

      ctx.fillStyle = isCompromised ? "#fda4af" : "#f8fafc";
      ctx.font = "11px -apple-system, sans-serif";
      ctx.fillText(n.label, n.x - 30, n.y + 30);
    }

    drawTopology();

    // 2. CHART.JS TELEMETRY
    const chartCtx = document.getElementById('trafficChart').getContext('2d');
    const chart = new Chart(chartCtx, {
      type: 'line',
      data: {
        labels: ['-12s', '-10s', '-8s', '-6s', '-4s', '-2s', 'Now'],
        datasets: [{
          data: [14, 18, 12, 19, 15, 17, 20],
          borderColor: '#38bdf8',
          backgroundColor: 'rgba(56, 189, 248, 0.1)',
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: '#1e293b' }, ticks: { color: '#64748b' } },
          y: { grid: { color: '#1e293b' }, ticks: { color: '#64748b' } }
        }
      }
    });

    // 3. UI SYNC
    function updateDashboard(data) {
      const isAttack = data.network_status === "UNDER ATTACK";
      const themeColor = isAttack ? '#f43f5e' : '#10b981';

      compromisedNodeKey = data.compromised_node;

      document.getElementById('statStatus').innerText = data.network_status;
      document.getElementById('statStatus').style.color = themeColor;

      document.getElementById('statRisk').innerText = data.risk_score + '%';
      document.getElementById('statRisk').style.color = themeColor;

      document.getElementById('statPackets').innerText = data.packet_count.toLocaleString();
      document.getElementById('statBandwidth').innerText = data.bandwidth_mbps + ' MB/s';

      const badge = document.getElementById('liveBadge');
      badge.innerText = isAttack ? "CRITICAL ALERT: BREACH CONTAINED" : "SYSTEM SECURE";
      badge.style.color = themeColor;
      badge.style.borderColor = themeColor;
      badge.style.background = isAttack ? 'rgba(244, 63, 94, 0.15)' : 'rgba(16, 185, 129, 0.15)';

      const meshAlert = document.getElementById('meshAlert');
      meshAlert.innerText = isAttack ? "⚠ NODE QUARANTINED BY ZERO-TRUST" : "● ALL NODES OPERATIONAL";
      meshAlert.style.color = themeColor;

      // Terminal feed
      const term = document.getElementById('terminalLogs');
      term.innerHTML = data.logs.map(log => {
        const clr = (log.includes('ANOMALY') || log.includes('ALERT') || log.includes('ZERO-TRUST')) ? '#f43f5e' : '#10b981';
        return `<div style="color: ${clr}; margin-bottom: 4px;">${log}</div>`;
      }).join('');
      term.scrollTop = term.scrollHeight;

      // Graph surge
      const surgeVal = isAttack ? Math.floor(Math.random() * 80) + 120 : Math.floor(Math.random() * 12) + 14;
      chart.data.datasets[0].data.shift();
      chart.data.datasets[0].data.push(surgeVal);
      chart.data.datasets[0].borderColor = themeColor;
      chart.data.datasets[0].backgroundColor = isAttack ? 'rgba(244, 63, 94, 0.2)' : 'rgba(56, 189, 248, 0.1)';
      chart.update();
    }

    async function sendRequest(payload) {
      try {
        const res = await fetch('/check_target', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        updateDashboard(data);
      } catch (err) {
        console.error(err);
      }
    }

    function triggerPreset(type) {
      if (type === 'safe') {
        document.getElementById('targetInput').value = 'https://clean-sensor-feed.mesh';
        sendRequest({ url: 'safe-mesh', attack_type: 'safe' });
      } else if (type === 'phishing') {
        document.getElementById('targetInput').value = 'rtsp://192.168.1.105:554/live-feed-login';
        sendRequest({ url: 'login-cam', attack_type: 'phishing' });
      } else if (type === 'botnet') {
        document.getElementById('targetInput').value = 'http://192.168.1.101:8080/mirai.bin';
        sendRequest({ url: 'botnet-node', attack_type: 'botnet' });
      }
    }

    function submitScan() {
      const url = document.getElementById('targetInput').value;
      if (!url) return alert("Target enter pannunga!");
      sendRequest({ url: url });
    }

    fetch('/api/status').then(r => r.json()).then(updateDashboard);
  </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify(current_state)

@app.route('/check_target', methods=['POST'])
def check_target():
    data = request.get_json() or {}
    url = data.get('url', '')
    attack_type = data.get('attack_type', None)
    result = analyze_target(url, attack_type)
    return jsonify(result)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)