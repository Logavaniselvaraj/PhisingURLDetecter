
import pandas as pd
from pathlib import Path

data_path = Path("data/PhiUSIIL_Phishing_URL_Dataset.csv")

if not data_path.exists():
    print("Dataset CSV not found!")
    print("Place the downloaded CSV inside the data folder.")
    raise SystemExit

print("Reading dataset...")

df = pd.read_csv(data_path)

print("Dataset loaded successfully!")
print("Columns:", df.columns.tolist())

df = df[["URL", "label"]].dropna()

# UCI: label 1 = legitimate, label 0 = phishing
# Our project: 0 = legitimate, 1 = phishing
df["label"] = df["label"].map({1: 0, 0: 1})

# Select up to 20,000 URLs from each class
legitimate = df[df["label"] == 0].sample(
    n=min(20000, len(df[df["label"] == 0])),
    random_state=42
)

phishing = df[df["label"] == 1].sample(
    n=min(20000, len(df[df["label"] == 1])),
    random_state=42
)

result = pd.concat([legitimate, phishing])
result = result.sample(frac=1, random_state=42)

result.to_csv("data/urls.csv", index=False)

print("\nDataset prepared successfully!")
print("Total URLs:", len(result))
print("Saved to: data/urls.csv")
print(result["label"].value_counts())
