import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_FILE = ROOT / "logs/state.json"
OUT_FILE = ROOT / "logs/explanations.json"


def build_advisory(device_id: str, d: dict) -> dict:
    threat = d.get("threat", "BENIGN")
    risk = d.get("risk", 0)
    verification = d.get("verification", "NONE")
    vlan = d.get("vlan", "MAIN")
    status = d.get("status", "NORMAL")
    ev = d.get("evidence", {})

    if threat == "BENIGN":
        return {
            "explanation": f"{device_id} shows normal network activity (risk score: {risk}/100).",
            "action": "No action needed. Keep the device in the MAIN VLAN."
        }

    ports = ev.get("unique_dest_ports", "N/A")
    pkt_rate = ev.get("mean_packets_per_s", "N/A")
    dom_port = ev.get("dominant_port_fraction", "N/A")

    if threat == "DDOS":
        reason = (
            f"{device_id} triggered a possible DDoS alert (risk {risk}/100) with dominant port "
            f"share {dom_port} and average packet rate {pkt_rate} pkt/s."
        )
    elif threat == "PORTSCAN":
        reason = (
            f"{device_id} triggered a possible port scan alert (risk {risk}/100) across "
            f"{ports} unique destination ports."
        )
    else:
        reason = f"{device_id} showed suspicious activity ({threat}, risk {risk}/100)."

    outcome_note = f" Secondary verification result: {verification}. Current state: {status} on {vlan} VLAN."

    if status == "ISOLATED":
        action = "Keep the device isolated in the ISOLATION VLAN and inspect it before restoring access."
    elif status == "RESTRICTED":
        action = "Keep traffic restricted via firewall/ACL rules until verification or review completes."
    else:
        action = "Monitor the device closely and review its traffic logs."

    return {
        "explanation": reason + outcome_note,
        "action": action
    }


def main():
    if not STATE_FILE.exists():
        print("Run python app\\pipeline.py first so logs\\state.json exists.")
        return
    state = json.loads(STATE_FILE.read_text())
    out = {dev: build_advisory(dev, info) for dev, info in state.items()}
    OUT_FILE.write_text(json.dumps(out, indent=2))
    for dev, item in out.items():
        print(f"\n[{dev}]")
        print("  Explanation:", item["explanation"])
        print("  Action     :", item["action"])
    print("\nSaved logs\\explanations.json")


if __name__ == "__main__":
    main()