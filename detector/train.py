from pathlib import Path
import numpy as np, pandas as pd, joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

RAW = Path("data/raw")
FILES = ["Monday-WorkingHours.pcap_ISCX.csv",
         "Wednesday-workingHours.pcap_ISCX.csv",
         "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
         "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"]

# Small, Pi-friendly feature set
FEATURES = ["Destination Port", "Flow Duration", "Total Fwd Packets",
            "Total Backward Packets", "Total Length of Fwd Packets",
            "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s",
            "Flow IAT Mean", "Fwd Packets/s", "SYN Flag Count", "ACK Flag Count",
            "Average Packet Size", "Init_Win_bytes_forward"]

# Map original labels to 3 classes
def map_label(x):
    x = x.strip()
    if x == "BENIGN": return "BENIGN"
    if x == "PortScan": return "PORTSCAN"
    if x.startswith("DoS") or x == "DDoS": return "DDOS"
    return None

frames = []
for f in FILES:
    print("Loading", f)
    df = pd.read_csv(RAW / f, encoding="latin-1", low_memory=False)
    df.columns = df.columns.str.strip()
    df["Label"] = df["Label"].map(map_label)
    df = df.dropna(subset=["Label"])
    frames.append(df[FEATURES + ["Label"]])
data = pd.concat(frames, ignore_index=True)

# Cleaning
data = data.replace([np.inf, -np.inf], np.nan).dropna()
data = data.drop_duplicates()
print("\nAfter cleaning:\n", data["Label"].value_counts())

parts = []
for label, g in data.groupby("Label"):
    parts.append(g.sample(min(len(g), 60000), random_state=42))
data = pd.concat(parts, ignore_index=True)

X, y = data[FEATURES], data["Label"]
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.3,
                                          stratify=y, random_state=42)

model = RandomForestClassifier(n_estimators=60, max_depth=14, n_jobs=-1,
                               random_state=42)
model.fit(X_tr, y_tr)

pred = model.predict(X_te)
print("\n", classification_report(y_te, pred, digits=4))
cm = confusion_matrix(y_te, pred, labels=model.classes_)
print("Confusion matrix:\n", cm)

# False positive rate for BENIGN
b = list(model.classes_).index("BENIGN")
fp = cm[:, b].sum() - cm[b, b]
tn_fp = cm.sum() - cm[b, :].sum()
print("Benign false positive rate:", round(fp / tn_fp, 5))

Path("models").mkdir(exist_ok=True)
Path("reports").mkdir(exist_ok=True)
joblib.dump({"model": model, "features": FEATURES}, "models/detector.joblib")
ConfusionMatrixDisplay(cm, display_labels=model.classes_).plot()
plt.savefig("reports/confusion_matrix.png", dpi=120)
data.sample(20, random_state=1).to_csv("data/demo_samples.csv", index=False)
print("\nSaved models/detector.joblib and reports/confusion_matrix.png")