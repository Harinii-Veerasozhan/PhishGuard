from flask import Flask, render_template, request, jsonify
import pickle
import numpy as np
import re
from urllib.parse import urlparse
from feature_extractor import extract_features
import socket

app = Flask(__name__)

# Load models
model = pickle.load(open("rf.pkl", "rb"))
scaler = pickle.load(open("scaler.pkl", "rb"))

def domain_exists(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

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

    # 1️⃣ Basic format validation
    if not url.startswith("http://") and not url.startswith("https://"):
        return jsonify({
            "status": "success",
            "prediction": "Invalid URL",
            "trust": 0
        })

    parsed = urlparse(url)

    # 2️⃣ Domain structure validation
    if not parsed.netloc:
        return jsonify({
            "status": "success",
            "prediction": "Invalid URL",
            "trust": 0
        })

    # 3️⃣ DNS existence check 🔥🔥🔥
    if not domain_exists(parsed.netloc):
        return jsonify({
            "status": "success",
            "prediction": "Phishing URL",
            "trust": 5
        })

    # 4️⃣ Feature-based ML analysis
    features = extract_features(url)
    X = scaler.transform([features])

    phishing_prob = model.predict_proba(X)[0][1]
    trust = int((1 - phishing_prob) * 100)

    prediction = "Phishing URL" if phishing_prob > 0.5 else "Legitimate URL"

    return jsonify({
        "status": "success",
        "prediction": prediction,
        "trust": trust
    })

if __name__ == "__main__":
    app.run(debug=True)
