from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re
import requests
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# ------------------------------
#  FEATURE SETTINGS
# ------------------------------
TRIGGER_WORDS = ["win", "prize", "gift", "free", "claim", "bonus", "offer"]
# Threshold for deciding safe vs phishing
SAFE_THRESHOLD = 70  # >70 safe, <=70 phishing/high-risk

# ------------------------------
#  FEATURE EXTRACTION
# ------------------------------
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    scheme = parsed.scheme or ""

    url_length = len(url)
    special_chars_count = len(re.findall(r"[!@#$%^&*()_+=\[\]{};:<>,?/\\|]", url))
    special_char_ratio = special_chars_count / url_length if url_length > 0 else 0.0
    trigger_count = sum(word in url.lower() for word in TRIGGER_WORDS)
    token_mismatch = int(any(c.islower() for c in url) and any(c.isupper() for c in url))  # 1 = mismatch detected
    try:
        # small timeout to avoid long hangs
        response = requests.get(url, timeout=3)
        redirect_count = len(response.history)
    except:
        redirect_count = 0

    # helpful flags
    has_https = int(scheme == "https")
    has_at = int("@" in url)
    has_ip = int(re.match(r"\d+\.\d+\.\d+\.\d+", hostname or "") is not None)

    features = {
        "url": url,
        "url_length": url_length,
        "special_chars_count": special_chars_count,
        "special_char_ratio": round(special_char_ratio, 4),
        "trigger_count": trigger_count,
        "token_mismatch": token_mismatch,
        "redirect_count": redirect_count,
        "has_https": has_https,
        "has_at": has_at,
        "has_ip": has_ip,
        "hostname": hostname,
        "path": path
    }

    return features

# ------------------------------
#  SCORING (weights chosen to reflect importance)
# ------------------------------
def compute_safety_score(feat):
    """
    Compute a 0-100 safety score using:
    - token_mismatch (binary; mismatch is high risk)
    - trigger_count (count of suspicious words)
    - redirect_count (number of redirects)
    - url_length (longer = more risky)
    - special_char_ratio (higher ratio = more risky)
    Higher score = safer.
    """

    # feature values
    url_length = feat["url_length"]
    trigger_count = feat["trigger_count"]
    redirect_count = feat["redirect_count"]
    special_ratio = feat["special_char_ratio"]
    token_mismatch = feat["token_mismatch"]

    # 1) token_mismatch score: 1.0 if NO mismatch (good), 0.0 if mismatch (bad)
    token_score = 0.0 if token_mismatch == 1 else 1.0

    # 2) trigger_count score: 1.0 if 0 triggers, then linearly decay to 0 at >=5 triggers
    trigger_score = max(0.0, 1.0 - (trigger_count / 5.0))

    # 3) redirect_count score: 1.0 if 0 redirects, decay to 0 at >=4
    redirect_score = max(0.0, 1.0 - (redirect_count / 4.0))

    # 4) url_length score: good if length <= 50, decays after that; clamp to [0,1]
    #    we consider URLs > 220 extremely suspicious
    if url_length <= 50:
        length_score = 1.0
    else:
        length_score = max(0.0, 1.0 - ((url_length - 50) / 170.0))

    # 5) special_char_ratio score: 1.0 if ratio 0, decays to 0 at ratio >=0.15 (15% special chars)
    special_score = max(0.0, 1.0 - (special_ratio / 0.15))

    # weights (sum to 1.0)
    weights = {
        "token": 0.30,
        "trigger": 0.20,
        "redirect": 0.15,
        "length": 0.20,
        "special": 0.15
    }

    weighted = (
        token_score * weights["token"] +
        trigger_score * weights["trigger"] +
        redirect_score * weights["redirect"] +
        length_score * weights["length"] +
        special_score * weights["special"]
    )

    # final 0-100 score
    final_score = int(round(weighted * 100))

    # prepare per-feature percentages (for UI)
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
        # extract features
        feat = extract_features(url)

        # compute safety score
        score, per_feature = compute_safety_score(feat)

        # classification using threshold
        is_safe = score > SAFE_THRESHOLD
        prediction_text = "Safe URL" if is_safe else "Phishing URL"

        # human-readable insights
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
            "features": insights,
            "feature_scores": per_feature,
            "threshold": SAFE_THRESHOLD
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    # run on 0.0.0.0 only if you want external access; default local is fine
    app.run(debug=True)
