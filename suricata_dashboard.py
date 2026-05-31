#!/usr/bin/env python3
import json
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import Counter

LOG_FILE = '/var/log/suricata/eve.json'

class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/':
            self.send_response(404)
            self.end_headers()
            return
        
        critical = high = medium = 0
        attackers = Counter()
        signatures = Counter()
        recent = []
        
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()[-100:]
                for line in lines:
                    try:
                        data = json.loads(line)
                        if data.get('event_type') == 'alert':
                            pri = data.get('alert', {}).get('priority', 3)
                            if pri == 1:
                                critical += 1
                            elif pri == 2:
                                high += 1
                            else:
                                medium += 1
                            
                            src = data.get('src_ip', 'unknown')
                            sig = data.get('alert', {}).get('signature', 'Unknown')[:60]
                            attackers[src] += 1
                            signatures[sig] += 1
                            
                            recent.append({
                                'time': data.get('timestamp', '')[-8:],
                                'pri': pri,
                                'sig': sig,
                                'src': src,
                                'dst': data.get('dest_ip', 'unknown')
                            })
                    except:
                        pass
        
        recent = recent[-20:]
        
        # Build HTML
        html = '<!DOCTYPE html><html><head>'
        html += '<title>Suricata NIDS Dashboard</title>'
        html += '<meta http-equiv="refresh" content="3">'
        html += '<style>'
        html += 'body{font-family:monospace;background:#0a0a0a;color:#0f0;padding:20px;}'
        html += 'h1{color:#f44;text-align:center;}'
        html += '.stats{display:flex;gap:20px;margin-bottom:30px;}'
        html += '.stat{flex:1;background:#111;padding:20px;text-align:center;border:1px solid #333;}'
        html += '.stat-num{font-size:48px;font-weight:bold;}'
        html += '.critical .stat-num{color:#f00;}'
        html += '.high .stat-num{color:#f80;}'
        html += '.medium .stat-num{color:#ff0;}'
        html += '.total .stat-num{color:#0f0;}'
        html += 'h2{color:#f44;margin:20px 0 10px 0;}'
        html += 'table{width:100%;border-collapse:collapse;}'
        html += 'th,td{padding:8px;text-align:left;border-bottom:1px solid #333;}'
        html += 'th{color:#f44;}'
        html += '.alert{padding:10px;margin:8px 0;background:#111;border-left:4px solid;}'
        html += '.alert-p1{border-left-color:#f00;}'
        html += '.alert-p2{border-left-color:#f80;}'
        html += '.alert-p3{border-left-color:#ff0;}'
        html += '.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;margin-right:10px;}'
        html += '.badge-p1{background:#f00;color:#fff;}'
        html += '.badge-p2{background:#f80;color:#000;}'
        html += '.badge-p3{background:#ff0;color:#000;}'
        html += '.timestamp{color:#888;font-size:12px;}'
        html += '.footer{text-align:center;color:#888;margin-top:30px;}'
        html += '</style></head><body>'
        
        html += '<h1>🔍 SURICATA NETWORK INTRUSION DETECTION SYSTEM</h1>'
        
        # Stats
        total = critical + high + medium
        html += '<div class="stats">'
        html += f'<div class="stat critical"><div class="stat-num">{critical}</div><div>🔴 CRITICAL</div></div>'
        html += f'<div class="stat high"><div class="stat-num">{high}</div><div>🟠 HIGH</div></div>'
        html += f'<div class="stat medium"><div class="stat-num">{medium}</div><div>🟡 MEDIUM</div></div>'
        html += f'<div class="stat total"><div class="stat-num">{total}</div><div>📊 TOTAL</div></div>'
        html += '</div>'
        
        # Top Attackers
        html += '<h2>🎯 TOP ATTACKING IPS</h2><table>'
        html += '<tr><th>IP Address</th><th>Count</th></tr>'
        for ip, c in attackers.most_common(10):
            html += f'<tr><td>{ip}</td><td>{c}</td></tr>'
        if not attackers:
            html += '<tr><td colspan="2">No data yet</td></tr>'
        html += '</table>'
        
        # Top Signatures
        html += '<h2>📝 TOP ATTACK SIGNATURES</h2><table>'
        html += '<tr><th>Signature</th><th>Count</th></tr>'
        for sig, c in signatures.most_common(10):
            html += f'<tr><td style="font-size:12px">{sig[:50]}</td><td>{c}</td></tr>'
        if not signatures:
            html += '<tr><td colspan="2">No data yet</td></tr>'
        html += '</table>'
        
        # Recent Alerts
        html += '<h2>⏱️ RECENT ALERTS</h2>'
        if recent:
            for a in recent:
                badge = 'CRITICAL' if a['pri'] == 1 else 'HIGH' if a['pri'] == 2 else 'MEDIUM'
                badge_class = f'badge-p{a["pri"]}'
                alert_class = f'alert-p{a["pri"]}'
                html += f'<div class="alert {alert_class}">'
                html += f'<span class="badge {badge_class}">{badge}</span>'
                html += f'<span class="timestamp">[{a["time"]}]</span>'
                html += f' {a["sig"]}<br>'
                html += f'<span style="color:#666;font-size:11px">📡 {a["src"]} → {a["dst"]}</span>'
                html += '</div>'
        else:
            html += '<div style="color:#666;text-align:center">No alerts yet. Generate traffic to see alerts!</div>'
        
        html += '<div class="footer">🔄 Auto-refreshes every 3 seconds | 📡 Monitoring wlan0</div>'
        html += '</body></html>'
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        pass

print("\n" + "="*50)
print("🔥 SURICATA NIDS DASHBOARD")
print("="*50)
print("📊 Dashboard starting at: http://localhost:8080")
print("🔍 Open this URL in Firefox")
print("⚡ Press Ctrl+C to stop")
print("="*50 + "\n")

server = HTTPServer(('0.0.0.0', 8080), DashboardHandler)
server.serve_forever()
