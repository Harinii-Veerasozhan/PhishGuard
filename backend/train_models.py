import pandas as pd
import numpy as np
from urllib.parse import urlparse
import re

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score

from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression

import joblib
import os


# ===========================
#   FEATURE EXTRACTOR
# ===========================
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.netloc

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "count_dots": url.count("."),
        "count_hyphen": url.count("-"),
        "count_at": url.count("@"),
        "count_question": url.count("?"),
        "count_percent": url.count("%"),
        "count_slash": url.count("/"),
        "count_equal": url.count("="),
        "has_https": 1 if url.startswith("https") else 0,
        "digits_count": sum(c.isdigit() for c in url),
        "letters_count": sum(c.isalpha() for c in url),
        "special_char_count": len(re.findall(r'[^\w]', url)),
        "suspicious_words": int(
            any(word in url for word in ["login", "secure", "verify", "update", "bank", "confirm"])
        )
    }

    return list(features.values())


# ===========================
#   LOAD DATASET
# ===========================
DATA_PATH = "../data/dataset.csv"

if not os.path.exists(DATA_PATH):
    print(f"❌ Dataset not found at: {DATA_PATH}")
    print("Place CSV file at: PhishGuard/data/dataset.csv with columns 'url','label'")
    exit()

data = pd.read_csv(DATA_PATH)

if "url" not in data.columns or "label" not in data.columns:
    print("❌ CSV must contain 'url' and 'label' columns")
    exit()

# Convert dataset into features
print("⏳ Extracting features from dataset...")
X = np.array([extract_features(u) for u in data["url"]])
y = data["label"].map({"legitimate": 0, "phishing": 1}).values

# ===========================
#   TRAIN TEST SPLIT
# ===========================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42
)

# Scaling
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

joblib.dump(scaler, "scaler.pkl")
print("✔ Saved scaler.pkl")


# ===========================
#   TRAIN MODELS
# ===========================

print("\n🔹 Training KNN...")
knn = KNeighborsClassifier(n_neighbors=5)
knn.fit(X_train, y_train)
joblib.dump(knn, "knn.pkl")
print("✔ knn.pkl saved | Accuracy:", accuracy_score(y_test, knn.predict(X_test)))

print("\n🔹 Training Random Forest...")
rf = RandomForestClassifier(n_estimators=200, random_state=42)
rf.fit(X_train, y_train)
joblib.dump(rf, "rf.pkl")
print("✔ rf.pkl saved | Accuracy:", accuracy_score(y_test, rf.predict(X_test)))

print("\n🔹 Training Decision Tree...")
dt = DecisionTreeClassifier(random_state=42)
dt.fit(X_train, y_train)
joblib.dump(dt, "dt.pkl")
print("✔ dt.pkl saved | Accuracy:", accuracy_score(y_test, dt.predict(X_test)))

print("\n🔹 Training Logistic Regression...")
lr = LogisticRegression(max_iter=500)
lr.fit(X_train, y_train)
joblib.dump(lr, "lr.pkl")
print("✔ lr.pkl saved | Accuracy:", accuracy_score(y_test, lr.predict(X_test)))

print("\n========================================")
print("🎉 All models trained successfully!")
print("📁 Saved: knn.pkl, rf.pkl, dt.pkl, lr.pkl, scaler.pkl")
print("========================================")
