import json
import sys
from pathlib import Path
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT / "ai"))

from pipeline import Gateway, ESP32Verifier, window
from advisor import build_advisory

STATE_FILE = ROOT / "logs/state.json"
LOG_FILE = ROOT / "logs/events.jsonl"
EXP_FILE = ROOT / "logs/explanations.json"

st.set_page_config(page_title="Digital Safety Assistant", layout="wide")
st.title("AI-Powered On-Device Digital Safety Assistant (Prototype)")
st.caption("Network Intrusion Use Case | Software Simulation of Gateway, Verifier, Rate Limit & VLANs")

if st.button("Run Simulation Now"):
    LOG_FILE.write_text("")
    gw = Gateway()
    cases = [
        ("IoT_001", "BENIGN", {}),
        ("IoT_002", "DDOS", {}),
        ("IoT_003", "PORTSCAN", {}),
        ("IoT_004", "DDOS", {"delay": 6}),
        ("IoT_005", "DDOS", {"tamper": True}),
    ]
    for dev, kind, kw in cases:
        gw.process_window(dev, window(kind, seed=7), ESP32Verifier(**kw))
    state_now = json.loads(STATE_FILE.read_text())
    exps_now = {dev: build_advisory(dev, info) for dev, info in state_now.items()}
    EXP_FILE.write_text(json.dumps(exps_now, indent=2))
    st.success("Simulation and explanations updated.")

if STATE_FILE.exists():
    state = json.loads(STATE_FILE.read_text())
    exps = json.loads(EXP_FILE.read_text()) if EXP_FILE.exists() else {}

    table_rows = []
    for dev, d in state.items():
        table_rows.append({
            "Device": dev,
            "Threat": d.get("threat"),
            "Risk": d.get("risk"),
            "Verification": d.get("verification"),
            "Rate Limit (%)": d.get("rate_limit_pct"),
            "VLAN": d.get("vlan"),
            "Status": d.get("status"),
        })

    st.subheader("Device Status Overview")
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True)

    left, right = st.columns(2)
    with left:
        st.subheader("Explanations & Safe Actions")
        for dev, d in state.items():
            info = exps.get(dev) or build_advisory(dev, d)
            with st.expander(f"{dev} — {d.get('threat')} ({d.get('status')})", expanded=(d.get("threat") != "BENIGN")):
                st.write("**Explanation:**", info["explanation"])
                st.write("**Recommended Action:**", info["action"])
                st.json(d.get("evidence", {}))

    with right:
        st.subheader("Event Logs")
        if LOG_FILE.exists() and LOG_FILE.read_text().strip():
            lines = [json.loads(line) for line in LOG_FILE.read_text().splitlines() if line.strip()]
            st.dataframe(pd.DataFrame(lines), use_container_width=True)
else:
    st.info("Click 'Run Simulation Now' to generate device states and logs.")