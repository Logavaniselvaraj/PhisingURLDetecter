
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Check whether the dataset exists
data_path = Path("data/urls.csv")

if not data_path.exists():
    print("Dataset not found. Run python download_dataset.py first.")
    raise SystemExit

print("Loading dataset...")
df = pd.read_csv(data_path)
df = df[["url", "label"]].dropna()

X = df["url"].astype(str)
y = df["label"].astype(int)

print("Total URLs:", len(df))
print("Preparing training and testing data...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Learn character patterns in URLs
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        max_features=30000,
        sublinear_tf=True
    )),
    ("classifier", LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    ))
])

print("Training model... Please wait.")

model.fit(X_train, y_train)

print("Testing model...")
predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nModel training completed!")
print(f"Accuracy: {accuracy * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(
    y_test,
    predictions,
    target_names=["Legitimate", "Phishing"]
))

# Save the trained model
Path("models").mkdir(exist_ok=True)
joblib.dump(model, "models/phishing_model.joblib")

print("Model saved to models/phishing_model.joblib")
