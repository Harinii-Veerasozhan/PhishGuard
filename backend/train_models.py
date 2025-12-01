import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from feature_extractor import extract_features

# ===============================
#   LOAD DATASET
# ===============================
DATASET_PATH = "data/dataset.csv"

df = pd.read_csv(DATASET_PATH)

# Required columns: url, label (0 = safe, 1 = phishing)
if "url" not in df.columns or "label" not in df.columns:
    raise ValueError("Dataset must contain 'url' and 'label' columns.")

# ===============================
#   FEATURE EXTRACTION
# ===============================

X = []
y = df["label"].values

print("Extracting features...")

for url in df["url"]:
    try:
        feats = extract_features(url)
        X.append(feats)
    except Exception as e:
        print(f"Error extracting features from URL {url}: {e}")
        X.append([0] * 14)  # fallback to avoid crashes

X = pd.DataFrame(X)

print("Feature extraction completed.")
print(f"Total samples: {len(X)}")
print(f"Total features: {X.shape[1]}")

# ===============================
#   SPLIT DATA
# ===============================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ===============================
#   SCALE FEATURES
# ===============================
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

joblib.dump(scaler, "scaler.pkl")
print("Scaler saved as scaler.pkl")

# ===============================
#   TRAIN MODELS
# ===============================

models = {
    "knn": KNeighborsClassifier(n_neighbors=5),
    "random_forest": RandomForestClassifier(n_estimators=200, random_state=42),
    "decision_tree": DecisionTreeClassifier(random_state=42),
    "logistic_regression": LogisticRegression(max_iter=500)
}

for name, model in models.items():
    print(f"\nTraining {name}...")
    model.fit(X_train_scaled, y_train)
    preds = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, preds)
    print(f"{name} Accuracy: {acc:.4f}")

    # Save model
    joblib.dump(model, f"{name}.pkl")
    print(f"Saved: {name}.pkl")

print("\nTraining completed successfully!")
