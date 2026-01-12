from flask import Flask, render_template, request, jsonify
import pickle
import numpy as np
import re
from urllib.parse import urlparse
from feature_extractor import extract_features

app = Flask(__name__)

# Load models
model = pickle.load(open("rf.pkl", "rb"))
scaler = pickle.load(open("scaler.pkl", "rb"))

# ---------------- URL VALIDATION ----------------
def is_valid_url(url):
    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return False

    domain_regex = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    return bool(domain_regex.match(parsed.netloc))

# ---------------- ROUTES ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze")
def analyze():
    return render_template("analyze.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url", "").strip()

    # 🚨 INVALID URL HANDLING
    if not is_valid_url(url):
        return jsonify({
            "status": "success",
            "prediction": "Invalid URL",
            "trust": 0
        })

    features = extract_features(url)
    X = scaler.transform([features])

    # Prediction
    prediction = model.predict(X)[0]
    phishing_prob = model.predict_proba(X)[0][1]

    trust = int((1 - phishing_prob) * 100)

    result = "Phishing URL" if prediction == 1 else "Legitimate URL"

    return jsonify({
        "status": "success",
        "prediction": result,
        "trust": trust
    })

if __name__ == "__main__":
    app.run(debug=True)
