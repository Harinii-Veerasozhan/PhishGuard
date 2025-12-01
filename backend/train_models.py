import pandas as pd
import joblib
from feature_extractor import extract_features
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression

# Load dataset
df = pd.read_csv("data/dataset.csv")  # must contain url,label

# Extract features
X = list(df["url"].apply(extract_features))
y = df["label"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

joblib.dump(scaler, "scaler.pkl")

# Train models
models = {
    "knn": KNeighborsClassifier(n_neighbors=5),
    "random_forest": RandomForestClassifier(n_estimators=150),
    "decision_tree": DecisionTreeClassifier(),
    "logistic_regression": LogisticRegression(max_iter=2000)
}

for name, model in models.items():
    print(f"Training {name}...")
    model.fit(X_train_scaled, y_train)
    preds = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, preds)
    print(f"{name} accuracy: {acc}")
    joblib.dump(model, f"models/{name}.pkl")

print("All models trained successfully!")
