from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from feature_extractor import extract_features  # import from your feature_extractor.py
from urllib.parse import urlparse
import re
import requests

app = Flask(__name__)
CORS(app)

# ------------------------------
#  FEATURE SETTINGS
# ------------------------------
TRIGGER_WORDS = ["win", "prize", "gift", "free", "claim", "bonus", "offer"]
SAFE_THRESHOLD = 70  # >70 safe, <=70 phishing/high-risk

# ------------------------------
#  ADDITIONAL FEATURE EXTRACTION FOR SCORING
# ------------------------------
def extract_scoring_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    scheme = parsed.scheme or ""

    url_length = len(url)
    special_chars_count = len(re.findall(r"[!@#$%^&*()_+=\[\]{};:<>,?/\\|]", url))
    special_char_ratio = special_chars_count / url_length if url_length > 0 else 0.0
    trigger_count = sum(word in url.lower() for word in TRIGGER_WORDS)
    token_mismatch = int(any(c.islower() for c in url) and any(c.isupper() for c in url))
    
    try:
        response = requests.get(url, timeout=3)
        redirect_count = len(response.history)
    except requests.RequestException:
        redirect_count = 0

    has_https = int(scheme == "https")
    has_at = int("@" in url)
    has_ip = int(re.match(r"\d+\.\d+\.\d+\.\d+", hostname or "") is not None)

    return {
        "url_length": url_length,
        "special_chars_count": special_chars_count,
        "special_char_ratio": round(special_char_ratio, 4),
        "trigger_count": trigger_count,
        "token_mismatch": token_mismatch,
        "redirect_count": redirect_count,
        "has_https": has_https,
        "has_at": has_at,
        "has_ip": has_ip,
        "hostname": hostname
    }

# ------------------------------
#  SCORING FUNCTION
# ------------------------------
def compute_safety_score(feat):
    token_score = 0.0 if feat["token_mismatch"] == 1 else 1.0
    trigger_score = max(0.0, 1.0 - (feat["trigger_count"] / 5.0))
    redirect_score = max(0.0, 1.0 - (feat["redirect_count"] / 4.0))
    if feat["url_length"] <= 50:
        length_score = 1.0
    else:
        length_score = max(0.0, 1.0 - ((feat["url_length"] - 50) / 170.0))
    special_score = max(0.0, 1.0 - (feat["special_char_ratio"] / 0.15))

    weights = {"token": 0.30, "trigger": 0.20, "redirect": 0.15, "length": 0.20, "special": 0.15}
    weighted = (
        token_score * weights["token"] +
        trigger_score * weights["trigger"] +
        redirect_score * weights["redirect"] +
        length_score * weights["length"] +
        special_score * weights["special"]
    )

    final_score = int(round(weighted * 100))

    per_feature = {
        "token_score_pct": int(round(token_score * 100)),
        "trigger_score_pct": int(round(trigger_score * 100)),
        "redirect_score_pct": int(round(redirect_score * 100)),
        "length_score_pct": int(round(length_score * 100)),
        "special_score_pct": int(round(special_score * 100))
    }

    return final_score, per_feature

# ------------------------------
#  FRONTEND ROUTES
# ------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze")
def analyze_page():
    return render_template("analyze.html")

# ------------------------------
#  MAIN API ENDPOINT
# ------------------------------
@app.route("/scan", methods=["POST"])
def scan_url():
    data = request.get_json() or {}
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400

    try:
        # Extract ML features from feature_extractor.py
        ml_features = extract_features(url)  # returns numeric list (15 features)

        # Extract additional scoring features
        feat = extract_scoring_features(url)

        # Compute safety score
        score, per_feature = compute_safety_score(feat)
        is_safe = score > SAFE_THRESHOLD
        prediction_text = "Safe URL" if is_safe else "Phishing URL"

        # Prepare human-readable insights
        insights = [
            f"URL Length: {feat['url_length']}",
            f"Special Characters: {feat['special_chars_count']} (ratio {feat['special_char_ratio']})",
            f"Trigger Words Detected: {feat['trigger_count']}",
            f"Token Mismatch (mixed-case trick): {'Yes' if feat['token_mismatch'] else 'No'}",
            f"Redirect Count (observed): {feat['redirect_count']}",
            f"Has HTTPS: {'Yes' if feat['has_https'] else 'No'}",
            f"Has '@' symbol: {'Yes' if feat['has_at'] else 'No'}",
            f"Hostname looks like IP: {'Yes' if feat['has_ip'] else 'No'}"
        ]

        return jsonify({
            "status": "success",
            "prediction": prediction_text,
            "trust": score,
            "ml_features": ml_features,
            "features": insights,
            "feature_scores": per_feature,
            "threshold": SAFE_THRESHOLD
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# ------------------------------
#  RUN APP
# ------------------------------
if __name__ == "__main__":
    app.run(debug=True)
