"""Virtual Pi 5 gateway + simulated ESP32 verifier (100% software simulation)."""
import json, hmac, hashlib, secrets, time, threading, queue
from pathlib import Path
import joblib, numpy as np, pandas as pd

ROOT = Path(__file__).resolve().parent.parent
bundle = joblib.load(ROOT / "models/detector.joblib")
MODEL, FEATURES = bundle["model"], bundle["features"]
POOL = pd.read_csv(ROOT / "data/sim_pool.csv")

# HMAC software prototype. NOT equivalent to a hardware ATECC608B.
SHARED_KEY = b"SIMULATED-SECURE-ELEMENT-KEY"
TIMEOUT_S = 5.0
RISK_THRESHOLD = 50
ALLOWED_COMMANDS = {"VERIFY_DEVICE"}
MAX_AGE_S = 10

(ROOT / "logs").mkdir(exist_ok=True)
LOG_FILE = ROOT / "logs/events.jsonl"
STATE_FILE = ROOT / "logs/state.json"


def sign(body: dict) -> str:
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(SHARED_KEY, raw, hashlib.sha256).hexdigest()


def log(device, event, **kw):
    rec = {"time": time.strftime("%H:%M:%S"), "device": device, "event": event, **kw}
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[{rec['time']}] {device}: {event} {kw if kw else ''}")


# ---------------- Detector (Pi 5 logic) ----------------
def make_evidence(f):
    n = len(f)
    ports = f["Destination Port"]
    return {"flows": n,
            "unique_dest_ports": int(ports.nunique()),
            "dominant_port_fraction": round(float(ports.value_counts().iloc[0] / n), 2),
            "mean_packets_per_s": round(float(f["Flow Packets/s"].mean()), 1),
            "mean_fwd_packets": round(float(f["Total Fwd Packets"].mean()), 2)}


def detect(flows):
    proba = MODEL.predict_proba(flows[FEATURES])
    classes = list(MODEL.classes_)
    risk = round(float(100 * (1 - proba[:, classes.index("BENIGN")].mean())), 1)
    preds = pd.Series(np.array(classes)[proba.argmax(1)])
    attack = preds[preds != "BENIGN"].value_counts()
    threat = attack.idxmax() if (risk >= RISK_THRESHOLD and len(attack)) else "BENIGN"
    return {"threat": threat, "risk": risk, "evidence": make_evidence(flows)}


# ---------------- Simulated ESP32 verifier ----------------
def independent_rules(ev):
    """Separate rules on raw evidence only. It does NOT use the ML model."""
    n = ev["flows"]
    if n >= 10 and ev["unique_dest_ports"] / n >= 0.5 and ev["mean_fwd_packets"] <= 3:
        return "PORTSCAN"
    if n >= 10 and ev["dominant_port_fraction"] >= 0.9 and ev["unique_dest_ports"] <= 2:
        return "DDOS"
    return "BENIGN"


class ESP32Verifier:
    def __init__(self, delay=0.3, drop=False, tamper=False):
        self.delay, self.drop, self.tamper = delay, drop, tamper
        self.seen_nonces = set()

    def handle(self, req):
        body, sig = req["body"], req["sig"]
        if not hmac.compare_digest(sig, sign(body)):
            return {"error": "bad_request_signature"}
        if body["command"] not in ALLOWED_COMMANDS:
            return {"error": "command_not_allowed"}
        if abs(time.time() - body["timestamp"]) > MAX_AGE_S:
            return {"error": "expired_request"}
        if body["nonce"] in self.seen_nonces:
            return {"error": "replay_detected"}
        self.seen_nonces.add(body["nonce"])

        verdict = "CONFIRMED" if independent_rules(body["evidence"]) == body["claimed_threat"] else "REJECTED"
        rbody = {"request_id": body["request_id"], "device_id": body["device_id"],
                 "verdict": verdict, "resp_nonce": secrets.token_hex(8),
                 "timestamp": time.time()}
        rsig = sign(rbody)
        if self.tamper:
            rsig = "0" * 64
        return {"body": rbody, "sig": rsig}


# ---------------- Pi 5 gateway ----------------
class Gateway:
    def __init__(self):
        self.devices = {}
        self.seen_resp_nonces = set()

    def save(self):
        STATE_FILE.write_text(json.dumps(self.devices, indent=2))

    def make_request(self, device_id, evidence, threat):
        body = {"request_id": secrets.token_hex(6), "device_id": device_id,
                "command": "VERIFY_DEVICE", "nonce": secrets.token_hex(8),
                "timestamp": time.time(), "claimed_threat": threat,
                "evidence": evidence}
        return {"body": body, "sig": sign(body)}

    def check_response(self, resp, req):
        if resp is None or "error" in resp:
            return False
        b = resp["body"]
        return (hmac.compare_digest(resp["sig"], sign(b))
                and b["device_id"] == req["body"]["device_id"]
                and b["request_id"] == req["body"]["request_id"]
                and b["resp_nonce"] not in self.seen_resp_nonces
                and abs(time.time() - b["timestamp"]) <= MAX_AGE_S)

    def process_window(self, device_id, flows, verifier):
        d = self.devices.setdefault(device_id, {})
        d.update(vlan="MAIN", status="NORMAL", rate_limit_pct=100,
                 verification="NONE", remaining_s=None, esp32_result=None)
        r = detect(flows)
        d.update(risk=r["risk"], threat=r["threat"], evidence=r["evidence"])
        if r["threat"] == "BENIGN":
            log(device_id, "NORMAL", risk=r["risk"])
            self.save()
            return d

        log(device_id, "SUSPICIOUS", threat=r["threat"], risk=r["risk"])
        req = self.make_request(device_id, r["evidence"], r["threat"])
        d.update(status="VERIFICATION_PENDING", verification="PENDING", rate_limit_pct=50)
        log(device_id, "RATE_LIMIT_50_APPLIED; device stays in MAIN VLAN")
        log(device_id, "MIRRORED_EVIDENCE_SENT to MaliciousCheck VLAN (logical)")

        q = queue.Queue()

        def run():
            time.sleep(verifier.delay)
            if not verifier.drop:
                q.put(verifier.handle(req))
        threading.Thread(target=run, daemon=True).start()

        deadline = time.monotonic() + TIMEOUT_S
        resp = None
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                resp = q.get(timeout=min(0.25, remaining))
                break
            except queue.Empty:
                d["remaining_s"] = round(remaining, 1)
                self.save()

        d["remaining_s"] = 0
        if resp is None:
            outcome = "TIMEOUT"
        elif not self.check_response(resp, req):
            outcome = "AUTH_FAILED"
        else:
            self.seen_resp_nonces.add(resp["body"]["resp_nonce"])
            outcome = resp["body"]["verdict"]

        d["esp32_result"] = outcome
        d["verification"] = outcome
        if outcome == "CONFIRMED":
            d.update(vlan="ISOLATION", status="ISOLATED", rate_limit_pct=0)
            log(device_id, "ISOLATED: moved to ISOLATION VLAN")
        elif outcome in ("TIMEOUT", "AUTH_FAILED"):
            d.update(vlan="MAIN", status="RESTRICTED", rate_limit_pct=0)
            log(device_id, f"RESTRICTED via ACL (reason={outcome}); fail-safe")
        else:  # REJECTED
            d.update(vlan="MAIN", status="UNDER_REVIEW", rate_limit_pct=100)
            log(device_id, "VERIFIER REJECTED: rate limit removed, under review")
        self.save()
        return d


def window(label, n=30, seed=None):
    g = POOL[POOL["Label"] == label]
    return g.sample(n, random_state=seed).reset_index(drop=True)


if __name__ == "__main__":
    LOG_FILE.write_text("")
    gw = Gateway()
    tests = [("IoT_001", "BENIGN", {}, "normal traffic"),
             ("IoT_002", "DDOS", {}, "DDoS, ESP32 confirms"),
             ("IoT_003", "PORTSCAN", {}, "port scan, ESP32 confirms"),
             ("IoT_004", "DDOS", {"delay": 7}, "ESP32 timeout"),
             ("IoT_005", "DDOS", {"tamper": True}, "invalid auth")]
    rows = []
    for dev, kind, kw, name in tests:
        print("\n---", name)
        d = gw.process_window(dev, window(kind, seed=7), ESP32Verifier(**kw))
        rows.append((name, d["threat"], d["risk"], d["verification"], d["vlan"], d["status"]))
        print("   evidence:", d["evidence"])

    print("\n--- replay attack")
    v = ESP32Verifier(delay=0)
    ev = make_evidence(window("DDOS", seed=7))
    req = gw.make_request("IoT_006", ev, "DDOS")
    print("first send :", "accepted" if "body" in v.handle(req) else "rejected")
    print("second send:", v.handle(req))

    print("\nSUMMARY")
    for r in rows:
        print(r)