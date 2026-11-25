import numpy as np, pandas as pd, joblib
from pathlib import Path

RAW = Path("data/raw")
FILES = ["Monday-WorkingHours.pcap_ISCX.csv",
         "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
         "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"]
FEATURES = joblib.load("models/detector.joblib")["features"]
MAP = {"BENIGN": "BENIGN", "PortScan": "PORTSCAN", "DDoS": "DDOS"}

parts = []
for f in FILES:
    df = pd.read_csv(RAW / f, encoding="latin-1", low_memory=False,
                     usecols=lambda c: c.strip() in FEATURES + ["Label"])
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].str.strip().map(MAP)
    df = df.dropna(subset=["Label"])
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    parts.append(df)
data = pd.concat(parts, ignore_index=True)

pool = pd.concat([g.sample(min(len(g), 600), random_state=1)
                  for _, g in data.groupby("Label")], ignore_index=True)
pool.to_csv("data/sim_pool.csv", index=False)
print(pool["Label"].value_counts())