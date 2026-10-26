"""NetSage local demo server. Uses only the Python standard library."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote
from pathlib import Path
from datetime import datetime
import json, random, time, csv, io, mimetypes

ROOT = Path(__file__).resolve().parent
rng = random.Random()
running = True
started_at = time.time()
events = []
traffic_history = []
NORMAL_IPS = ["192.168.1.12", "192.168.1.24", "10.0.0.8", "172.16.0.14", "192.168.1.31"]
SUSPICIOUS_IPS = ["185.220.101.4", "45.95.147.22", "103.74.120.8", "198.51.100.77"]
PORTS = [53, 80, 123, 443, 22, 3306, 8080, 3389, 445]
PROTOCOLS = ["TCP", "UDP", "DNS", "HTTP", "HTTPS", "ICMP"]

def make_event(force_anomaly=False):
    anomaly = force_anomaly or rng.random() < .18
    src = rng.choice(SUSPICIOUS_IPS if anomaly else NORMAL_IPS)
    dst = rng.choice(NORMAL_IPS + ["8.8.8.8", "1.1.1.1"])
    protocol = rng.choice(["TCP", "UDP", "ICMP"] if anomaly else PROTOCOLS)
    port = rng.choice([22, 445, 3389, 4444, 8080, 9001] if anomaly else PORTS)
    packets = rng.randint(90, 950) if anomaly else rng.randint(1, 70)
    byte_count = packets * rng.randint(400, 1400)
    reasons, score = [], 12
    if packets > 120: score += 30; reasons.append("Unusually high packet volume")
    if port in [4444, 9001, 3389, 445]: score += 28; reasons.append(f"Sensitive or uncommon destination port {port}")
    if src in SUSPICIOUS_IPS: score += 24; reasons.append("Source differs from baseline traffic profile")
    score = min(99, score + rng.randint(0, 12)); suspicious = score >= 58
    severity = "Critical" if score >= 85 else "High" if score >= 70 else "Medium" if suspicious else "Low"
    if not reasons: reasons = ["Traffic volume and destination match baseline"]
    action = "Isolate host and investigate immediately" if severity == "Critical" else "Review endpoint and correlate related events" if suspicious else "Continue monitoring"
    return {"id": f"NS-{int(time.time()*1000)}-{rng.randint(100,999)}", "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"), "src_ip":src,"dst_ip":dst,"src_port":rng.randint(1024,65535),"dst_port":port,"protocol":protocol,"packets":packets,"bytes":byte_count,"duration_ms":rng.randint(3,4500),"risk_score":score,"confidence":min(99,72+score//4),"severity":severity,"status":"ANOMALY" if suspicious else "NORMAL","reasons":reasons,"action":action,"threat_intel":"Potentially suspicious source (demo indicator)" if src in SUSPICIOUS_IPS and suspicious else "No matching demo indicator","model":"Heuristic baseline detector","is_anomaly":suspicious}

def seed_data():
    for _ in range(24):
        e=make_event(rng.random()<.25); e["timestamp"]=datetime.fromtimestamp(time.time()-rng.randint(0,1800)).astimezone().isoformat(timespec="seconds"); events.append(e)
    events.sort(key=lambda e:e["timestamp"],reverse=True)
    for i in range(20): traffic_history.append({"label":datetime.fromtimestamp(time.time()-(19-i)*15).strftime("%H:%M:%S"),"packets":rng.randint(15,140),"anomalies":rng.randint(0,5)})
seed_data()
last_tick=0

def tick():
    global last_tick
    if running and time.time()-last_tick>=4:
        last_tick=time.time(); e=make_event(); events.insert(0,e); del events[250:]
        traffic_history.append({"label":datetime.now().astimezone().strftime("%H:%M:%S"),"packets":e["packets"],"anomalies":1 if e["is_anomaly"] else 0}); del traffic_history[:-30]

def summary():
    tick(); total=len(events)
    return {"running":running,"total_events":total,"anomalies":sum(e["is_anomaly"] for e in events),"critical":sum(e["severity"]=="Critical" for e in events),"avg_risk":round(sum(e["risk_score"] for e in events)/max(1,total)),"events":events[:80],"history":traffic_history[-30:],"mode":"DEMO SIMULATION","uptime_seconds":int(time.time()-started_at)}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): print("[NetSage] " + (fmt % args))
    def send_bytes(self, body, content_type="application/json; charset=utf-8", status=200, headers=None):
        if isinstance(body,str): body=body.encode("utf-8")
        self.send_response(status); self.send_header("Content-Type",content_type); self.send_header("Content-Length",str(len(body))); self.send_header("X-Content-Type-Options","nosniff")
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(body)
    def read_json(self):
        try: return json.loads(self.rfile.read(int(self.headers.get("Content-Length",0))) or b"{}")
        except (ValueError, json.JSONDecodeError): return {}
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/": return self.send_bytes((ROOT/"templates/index.html").read_text(encoding="utf-8"),"text/html; charset=utf-8")
        if path=="/api/summary": return self.send_bytes(json.dumps(summary()))
        if path=="/api/events.csv":
            out=io.StringIO(); fields=["timestamp","id","src_ip","dst_ip","src_port","dst_port","protocol","packets","bytes","risk_score","confidence","severity","status","action"]
            writer=csv.DictWriter(out,fieldnames=fields); writer.writeheader()
            for e in events: writer.writerow({k:e.get(k,"") for k in fields})
            return self.send_bytes(out.getvalue(),"text/csv; charset=utf-8",headers={"Content-Disposition":"attachment; filename=netsage-events.csv"})
        if path.startswith("/static/"):
            rel=unquote(path[len("/static/"):]); target=(ROOT/"static"/rel).resolve()
            if not target.is_relative_to((ROOT/"static").resolve()) or not target.is_file(): return self.send_bytes("Not found", "text/plain",404)
            return self.send_bytes(target.read_bytes(),mimetypes.guess_type(str(target))[0] or "application/octet-stream")
        return self.send_bytes("Not found","text/plain; charset=utf-8",404)
    def do_POST(self):
        global running
        path=urlparse(self.path).path; data=self.read_json()
        if path=="/api/control":
            action=data.get("action")
            if action=="start": running=True
            elif action=="pause": running=False
            elif action=="clear": events.clear()
            elif action=="inject":
                e=make_event(True); events.insert(0,e); del events[250:]; traffic_history.append({"label":datetime.now().astimezone().strftime("%H:%M:%S"),"packets":e["packets"],"anomalies":1}); del traffic_history[:-30]
                return self.send_bytes(json.dumps({"ok":True,"event":e}))
            else: return self.send_bytes(json.dumps({"ok":False,"error":"Unknown action"}),status=400)
            return self.send_bytes(json.dumps({"ok":True,"running":running}))
        if path=="/api/analyze":
            try: packets=int(data.get("packets",1)); port=int(data.get("dst_port",443)); byte_count=int(data.get("bytes",packets*700))
            except (TypeError,ValueError): return self.send_bytes(json.dumps({"error":"packets, dst_port and bytes must be numeric"}),status=400)
            if min(packets,port,byte_count)<0 or port>65535: return self.send_bytes(json.dumps({"error":"Values must be non-negative and port must be <= 65535"}),status=400)
            score=min(99,12+(30 if packets>120 else 0)+(28 if port in [4444,9001,3389,445] else 0)+(18 if byte_count>100000 else 0))
            result={"risk_score":score,"severity":"Critical" if score>=85 else "High" if score>=70 else "Medium" if score>=58 else "Low","status":"ANOMALY" if score>=58 else "NORMAL","explanation":["High packet count" if packets>120 else "Packet count within baseline","Sensitive/uncommon port" if port in [4444,9001,3389,445] else "Destination port is commonly used","Large data transfer" if byte_count>100000 else "Transfer size within baseline"],"note":"Demonstration heuristic, not a production-grade security verdict."}
            return self.send_bytes(json.dumps(result))
        return self.send_bytes(json.dumps({"error":"Not found"}),status=404)

if __name__=="__main__":
    print("\nNetSage is starting at http://127.0.0.1:5000\nDemo simulation mode is enabled. Press Ctrl+C to stop.\n")
    ThreadingHTTPServer(("127.0.0.1",5000),Handler).serve_forever()
