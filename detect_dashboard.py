import warnings
warnings.filterwarnings("ignore")
from scapy.all import sniff, IP, TCP, ICMP
import joblib
from collections import defaultdict, Counter
from flask import Flask, render_template_string
import threading
import time

model = joblib.load("model_v2.pkl")
print("Modele charge !")

ATTACKER = "192.168.56.104"
VICTIMS = {"192.168.56.102": "Metasploitable", "192.168.56.103": "Ubuntu"}

alerts = []
stats = Counter()
flows = defaultdict(list)
lock = threading.Lock()

app = Flask(__name__)

PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>IDS Dashboard</title>
<meta http-equiv="refresh" content="3">
<style>
  body { font-family: 'Segoe UI', sans-serif; background:#0d1117; color:#e6edf3; margin:0; padding:20px; }
  h1 { color:#58a6ff; text-align:center; }
  .stats { display:flex; justify-content:center; gap:15px; flex-wrap:wrap; margin:20px 0; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:15px 25px; text-align:center; min-width:110px; }
  .card .num { font-size:28px; font-weight:bold; }
  .card .lbl { color:#8b949e; font-size:13px; margin-top:5px; }
  table { width:100%; border-collapse:collapse; margin-top:20px; }
  th,td { padding:10px; text-align:left; border-bottom:1px solid #30363d; }
  th { background:#161b22; color:#58a6ff; }
  .badge { padding:3px 10px; border-radius:12px; font-size:12px; font-weight:bold; }
  .b-attack { background:#f8514922; color:#f85149; }
  .b-normal { background:#3fb95022; color:#3fb950; }
</style>
</head>
<body>
  <h1>Network IDS Dashboard - Machine Learning</h1>
  <div class="stats">
    <div class="card"><div class="num" style="color:#f85149">{{ total_attacks }}</div><div class="lbl">Attaques</div></div>
    <div class="card"><div class="num" style="color:#3fb950">{{ total_normal }}</div><div class="lbl">Normal</div></div>
    <div class="card"><div class="num" style="color:#d29922">{{ stats.get('bruteforce',0) }}</div><div class="lbl">Brute Force</div></div>
    <div class="card"><div class="num" style="color:#a371f7">{{ stats.get('portscan',0) }}</div><div class="lbl">Port Scan</div></div>
    <div class="card"><div class="num" style="color:#db61a2">{{ stats.get('web',0) }}</div><div class="lbl">Web Attack</div></div>
    <div class="card"><div class="num" style="color:#f0883e">{{ stats.get('exploit',0) }}</div><div class="lbl">Exploit</div></div>
  </div>
  <table>
    <tr><th>Heure</th><th>Source</th><th>Victime</th><th>Port</th><th>Paquets</th><th>Verdict</th></tr>
    {% for a in alerts %}
    <tr>
      <td>{{ a.time }}</td><td>{{ a.src }}</td><td>{{ a.victim }}</td>
      <td>{{ a.port }}</td><td>{{ a.pkts }}</td>
      <td><span class="badge {{ 'b-attack' if a.type!='normal' else 'b-normal' }}">{{ a.type.upper() }}</span></td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""

@app.route("/")
def index():
    with lock:
        ta = sum(v for k,v in stats.items() if k!="normal")
        tn = stats.get("normal",0)
        return render_template_string(PAGE, alerts=list(reversed(alerts[-30:])), stats=stats, total_attacks=ta, total_normal=tn)

def analyser():
    global flows
    with lock:
        for key, pkts in list(flows.items()):
            src, dst, dport = key
            if len(pkts) < 2: continue
            nb = len(pkts); tot = sum(len(p) for p in pkts)
            times = [float(p.time) for p in pkts]
            dur = round(max(times)-min(times),4); avg = round(tot/nb,2)
            direction = 1 if src==ATTACKER else 0
            pred = model.predict([[nb,tot,dport,dur,avg,direction]])[0]
            victim = VICTIMS.get(dst, dst)
            stats[pred] += 1
            alerts.append({"time":time.strftime("%H:%M:%S"),"src":src,"victim":victim,"port":dport,"pkts":nb,"type":pred})
            if pred!="normal": print(f"ALERTE {src} -> {victim}:{dport} >> {pred.upper()}")
        flows = defaultdict(list)

def paquet(pkt):
    if IP in pkt and TCP in pkt:
        flows[(pkt[IP].src,pkt[IP].dst,pkt[TCP].dport)].append(pkt)
    elif IP in pkt and ICMP in pkt:
        flows[(pkt[IP].src,pkt[IP].dst,0)].append(pkt)

def sniffer():
    while True:
        sniff(iface="eth0", prn=paquet, timeout=5, store=False)
        analyser()

if __name__=="__main__":
    threading.Thread(target=sniffer, daemon=True).start()
    print("Dashboard : http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
