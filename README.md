# AI-Powered On-Device Digital Safety Assistant (`ArmBharat-PS3`)

A multi-stage network intrusion detection, verification, and security enforcement prototype designed for Home/SME IoT environments (Veda AI SOC Challenge — Problem Statement 3).

> **Phase 1 Scope Disclosure:** This Phase 1 submission is a **100% software prototype and simulation** running locally on a Windows laptop. No physical Raspberry Pi 5, ESP32-S3, ATECC608B secure element, or managed VLAN switch hardware was used in this prototype. Hardware-dependent components and full Arm on-device benchmarks are planned for Phase 2.

---

## Project Architecture & Workflow

```text
CICIDS2017 Network Flows (Virtual IoT Devices: IoT_001 .. IoT_006)
        │
        ▼
[1] Virtual Raspberry Pi 5 Gateway (app/pipeline.py + models/detector.joblib)
    ├── Random Forest Threat Classifier (BENIGN / DDOS / PORTSCAN)
    ├── Evidence-Based Risk Scoring (0–100)
    └── Temporary 50% Rate Limiting & 5-Second Verification Timer
        │
        ▼  (HMAC-SHA256 Signed Request + Nonce + Timestamp)
[2] Simulated ESP32-S3 Independent Verifier (app/pipeline.py)
    ├── Replay Protection & Command Allowlist Validation
    └── Independent Rule-Based Secondary Verification
        │
        ├──► CONFIRMED   ──► Move Device to ISOLATION VLAN (0% traffic)
        ├──► TIMEOUT     ──► Fail-Safe ACL Restriction (5s expiry)
        ├──► AUTH_FAILED ──► Fail-Safe ACL Restriction (tamper/invalid signature)
        └──► REJECTED    ──► Restore Rate Limit & Mark UNDER_REVIEW
        │
        ▼
[3] Advisory Explanation Generator (ai/advisor.py)
    └── Plain-Language Threat Explanation & Recommended Safe Action
        │
        ▼
[4] Interactive Security Dashboard (app/dashboard.py)
    └── Device Table, Risk Scores, VLAN States, AI Guidance & Event Logs
```

---

## Phase 1 Implemented Features (Current Prototype)

### 1. Network Threat Detection Engine (`detector/train.py`, `models/detector.joblib`)
* **Dataset:** CICIDS2017 flow dataset (`BENIGN`, `DDoS`/`DoS`, and `PortScan` classes).
* **Lightweight Feature Set:** Uses 14 Pi-friendly flow features (`Destination Port`, `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Flow Bytes/s`, `Flow Packets/s`, `SYN Flag Count`, `ACK Flag Count`, etc.).
* **Model & Metrics:** Trained Random Forest classifier (`n_estimators=60`, `max_depth=14`) achieving **99.92% accuracy** and a **0.00061 benign false positive rate** on a balanced 54,000-flow test split (`reports/confusion_matrix.png`).
* **Risk Scoring:** Computes continuous risk scores from class probabilities alongside structured flow evidence (`unique_dest_ports`, `dominant_port_fraction`, `mean_packets_per_s`, `mean_fwd_packets`).

### 2. Virtual Raspberry Pi 5 Gateway (`app/pipeline.py`)
* Evaluates per-device traffic windows and triggers suspicious-device workflows when risk exceeds the threshold (`RISK_THRESHOLD = 50`).
* Applies **temporary 50% rate limiting** while keeping the device in the `MAIN` VLAN during verification.
* Logs logical port-mirroring events to `MaliciousCheck` VLAN and manages fail-safe enforcement state transitions.

### 3. Simulated ESP32-S3 Secondary Verifier (`app/pipeline.py`)
* Performs independent rule-based checks on raw flow evidence without relying on the gateway's ML model.
* Validates `PORTSCAN` (high unique destination port ratio with low forward packets per flow) and `DDOS` (high dominant destination port concentration).

### 4. Authenticated Messaging & Replay Protection (`app/pipeline.py`)
* **Message Authentication:** Signs requests and responses using HMAC-SHA256 (`SHARED_KEY`) with device ID and request ID binding. *(Software cryptographic prototype; not hardware-backed ATECC608B execution).*
* **Replay & Tamper Defense:** Enforces unique nonces (`seen_nonces`), timestamp freshness (`MAX_AGE_S = 10`), command allowlisting (`VERIFY_DEVICE`), and automatic fail-safe restriction upon signature tampering.

### 5. Time-Bounded Verification & Logical VLAN Isolation (`app/pipeline.py`)
* **5-Second Verification Timeout:** Automatically restricts unresponsive devices (`TIMEOUT` $\rightarrow$ `RESTRICTED` via ACL) if verification does not complete within 5 seconds.
* **Three Logical VLAN States:** Models `MAIN`, `MaliciousCheck` (mirrored evidence), and `ISOLATION` VLAN transitions with full audit logging in `logs/events.jsonl` and `logs/state.json`.

### 6. Plain-Language Explanations & Streamlit Dashboard (`ai/advisor.py`, `app/dashboard.py`)
* **Evidence-Grounded Explanations:** Translates detector risk scores, flow statistics, and verification results into concise plain-language explanations and safe remediation actions (`logs/explanations.json`) without inventing threat evidence.
* **Live Dashboard:** Streamlit interface displaying device status, risk scores, verification outcomes, rate limits, VLAN assignments, AI guidance, and real-time event logs.

---

## Phase 2 Roadmap (Planned Additions & Hardware Validation)

In **Phase 2**, the prototype will expand from a single-use-case software simulation into a complete, hardware-validated multi-threat edge assistant:

1. **Physical Arm & Embedded Hardware Deployment**
   * Deploy the gateway, ML detector, and inference runtime onto a physical **Raspberry Pi 5** (Arm Cortex-A76) for real-world offline validation.
   * Port the secondary verifier onto an actual **ESP32-S3** microcontroller communicating over a physical serial/UART or isolated network link.
2. **Hardware-Backed Cryptographic Identity (`ATECC608B`)**
   * Replace the Phase 1 software HMAC simulation with hardware-backed key storage, mutual authentication, and signing via **Microchip ATECC608B** secure elements.
3. **Full Local Llama + ExecuTorch Integration**
   * Export and run a quantized **Llama-family model** (e.g., Llama 3.2 1B) natively via **ExecuTorch** on the Raspberry Pi 5 Arm CPU with persistent model loading and zero cloud dependency.
   * Benchmark on-device LLM **Time-To-First-Token (TTFT)**, **Tokens Per Second (TPS)**, RAM footprint, CPU utilization, and thermal behavior.
4. **Additional Digital Safety Threat Modules (PS3 Multi-Threat Scope)**
   * **Phishing URL Detection:** Lightweight on-device lexical and structural URL classifier to warn users before visiting malicious links.
   * **Scam SMS / Message Detection:** Local text classifier to flag social-engineering, OTP theft, and financial scam messages.
5. **Real Network Packet Capture & Switch VLAN Enforcement**
   * Replace pre-extracted CICIDS2017 CSV replay with live packet capture (`scapy` / `pyshark` / `eBPF`) and dynamic firewall (`nftables`/`iptables`) or managed switch 802.1Q VLAN enforcement.
6. **Time-Based & Source-Based Evaluation + Privacy Controls**
   * Evaluate detector generalization using strict time-based/source-based splits on live traffic and add automated PII/IP anonymization for Indian home/SME privacy compliance.

---

## Project Structure

```text
ArmBharat-PS3/
├── ai/
│   └── advisor.py              # Plain-language explanation & safe action generator
├── app/
│   ├── dashboard.py            # Streamlit security monitoring dashboard
│   └── pipeline.py             # Virtual Pi 5 gateway, ESP32 verifier, HMAC auth, timeout & VLAN sim
├── data/
│   ├── raw/                    # CICIDS2017 CSV files (not tracked in git)
│   ├── demo_samples.csv        # Sample flows saved during training
│   └── sim_pool.csv            # Balanced flow pool for virtual device simulation
├── detector/
│   ├── inspect_dataset.py      # Dataset schema & label inspection utility
│   ├── make_pool.py            # Builds simulation flow pool from raw CSVs
│   └── train.py                # Data cleaning, feature selection & Random Forest training
├── logs/
│   ├── events.jsonl            # Structured chronological security event log
│   ├── explanations.json       # Generated threat explanations & recommended actions
│   └── state.json              # Current device VLAN, risk & verification state
├── models/
│   └── detector.joblib         # Trained Random Forest model & feature list
├── reports/
│   └── confusion_matrix.png    # Evaluation confusion matrix plot
└── README.md
```

---

## How to Run Locally (Windows)

1. **Activate the virtual environment:**
   ```powershell
   cd ArmBharat-PS3
   .\venv\Scripts\Activate.ps1
   ```
2. **Run the end-to-end gateway, verifier, and enforcement simulation:**
   ```powershell
   python app\pipeline.py
   ```
3. **Generate plain-language explanations and recommended actions:**
   ```powershell
   python ai\advisor.py
   ```
4. **Launch the Streamlit dashboard:**
   ```powershell
   streamlit run app\dashboard.py
   ```

---

## Known Phase 1 Limitations
* **Virtual Device Mapping:** The `MachineLearningCSV` version of CICIDS2017 omits raw IP addresses and timestamps; flows are assigned to virtual devices (`IoT_001`–`IoT_006`) to test gateway and VLAN state transitions.
* **Dataset Split:** Phase 1 uses a deduplicated stratified random split; CICIDS2017 is known to yield high benchmark accuracy, so real-world false positive rates will vary.
* **Heuristic Verifier Rules:** The simulated ESP32 verifier uses threshold heuristics tuned to CICIDS2017 flow statistics and requires calibration on live IoT traffic in Phase 2.
