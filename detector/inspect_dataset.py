from pathlib import Path
import pandas as pd

DATA_DIR = Path("data/raw")
files = sorted(DATA_DIR.glob("*.csv"))
print(f"Total CSV files: {len(files)}")

total = pd.Series(dtype="int64")
for f in files:
    print("\n" + "=" * 70)
    print("FILE:", f.name)
    cols = [c.strip() for c in pd.read_csv(f, nrows=0, encoding="latin-1").columns]
    print("Num columns:", len(cols))
    for name in ["Flow ID", "Source IP", "Destination IP", "Timestamp", "Label"]:
        print(f"  has '{name}':", name in cols)
    # read only the Label column
    labels = pd.read_csv(f, usecols=lambda c: c.strip() == "Label",
                         encoding="latin-1")
    labels.columns = ["Label"]
    counts = labels["Label"].str.strip().value_counts()
    print(counts.to_string())
    total = total.add(counts, fill_value=0)

print("\n" + "=" * 70)
print("OVERALL LABEL COUNTS")
print(total.astype(int).sort_values(ascending=False).to_string())