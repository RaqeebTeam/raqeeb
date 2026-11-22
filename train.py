"""Train the URL classifier.
Uses data/urls.csv (real dataset) if present, else data/synthetic_urls.csv."""
import json
import os
import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES, feature_vector

BAD = {"1", "phishing", "bad", "malicious", "malware", "defacement", "spam", "fraud", "true"}
GOOD = {"0", "benign", "good", "legitimate", "safe", "false", "-1"}


def load():
    path = "data/urls.csv"
    if not os.path.exists(path):
        if not os.path.exists("data/synthetic_urls.csv"):
            import make_dataset
            make_dataset.main()
        path = "data/synthetic_urls.csv"
        print("!! Using SYNTHETIC data (demo only). Put a real dataset at data/urls.csv for final results.")
    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]
    url_col = next(c for c in ("url", "urls", "link", "website") if c in df.columns)
    lab_col = next(c for c in ("label", "type", "status", "result", "class") if c in df.columns)
    lab = df[lab_col].astype(str).str.strip().str.lower()
    keep = lab.isin(BAD | GOOD)
    df = df[keep].copy()
    df["y"] = lab[keep].isin(BAD).astype(int)
    df = df.rename(columns={url_col: "url"}).drop_duplicates("url")
    print(f"Loaded {len(df)} URLs from {path} (phishing share: {df['y'].mean():.2%})")
    return df


def main():
    df = load()
    if len(df) > 200_000:                       # keep training fast on huge Kaggle files
        df = df.sample(200_000, random_state=1)
    X = pd.DataFrame([feature_vector(u) for u in df["url"]], columns=FEATURE_NAMES)
    y = df["y"].values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    model = RandomForestClassifier(n_estimators=200, max_depth=18, min_samples_leaf=2,
                                   n_jobs=-1, random_state=42, class_weight="balanced")
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)

    acc = accuracy_score(yte, pred)
    cm = confusion_matrix(yte, pred).tolist()
    print(f"\nAccuracy: {acc:.4f}")
    print("Confusion matrix [[TN, FP],[FN, TP]]:", cm)
    print(classification_report(yte, pred, target_names=["benign", "phishing"]))

    imp = sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda t: -t[1])
    print("Top features:")
    for n, v in imp[:10]:
        print(f"  {n:22s} {v:.3f}")

    joblib.dump({"model": model, "features": FEATURE_NAMES,
                 "importances": dict(imp)}, "model/model.joblib")
    json.dump({"accuracy": acc, "confusion_matrix": cm, "importances": dict(imp)},
              open("model/metrics.json", "w"), indent=2)
    print("\nSaved model/model.joblib and model/metrics.json")


if __name__ == "__main__":
    sys.exit(main())
