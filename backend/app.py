from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import re
import requests
from urllib.parse import urlparse
import tldextract  # For domain extraction

app = Flask(__name__)
CORS(app)

# ------------------------------
#  SETTINGS
# ------------------------------
TRIGGER_WORDS = [
    "win", "prize", "gift", "free", "claim", "bonus", "offer",
    "login", "secure", "verify", "update", "bank", "paypal", "auth", "confirm"
]
BRAND_DOMAINS = ["paypal", "bank", "amazon", "google", "facebook", "apple"]
SAFE_THRESHOLD = 70  # >70 safe, <=70 phishing/high-risk

# ------------------------------
#  DOMAIN HELPERS
# ------------------------------
def get_registered_domain(url):
    ext = tldextract.extract(url)
    return ext.domain + "." + ext.suffix

def domain_mismatch(url):
    extracted = tldextract.extract(url)
    reg_domain = extracted.domain.lower()  # actual registered domain
    url_lower = url.lower()
    for brand in BRAND_DOMAINS:
        # Check if brand is in URL but NOT in registered domain
        if brand in url_lower and brand not in reg_domain:
            return 1
    return 0

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
    token_mismatch = int(any(c.islower() for c in url) and any(c.isupper() for c in url))
    brand_mismatch = domain_mismatch(url)

    try:
        response = requests.get(url, timeout=3)
        redirect_count = len(response.history)
    except:
        redirect_count = 0

    has_https = int(scheme == "https")
    has_at = int("@" in url)
    has_ip = int(re.match(r"\d+\.\d+\.\d+\.\d+", hostname or "") is not None)

    return {
        "url": url,
        "url_length": url_length,
        "special_chars_count": special_chars_count,
        "special_char_ratio": round(special_char_ratio, 4),
        "trigger_count": trigger_count,
        "token_mismatch": token_mismatch,
        "brand_mismatch": brand_mismatch,
        "redirect_count": redirect_count,
        "has_https": has_https,
        "has_at": has_at,
        "has_ip": has_ip,
        "hostname": hostname,
        "path": path
    }

# ------------------------------
#  SCORING FUNCTION
# ------------------------------
def compute_safety_score(feat):
    # Scores between 0 (bad) and 1 (good)
    token_score = 1.0 if feat["token_mismatch"] == 0 else 0.0
    brand_score = 1.0 if feat["brand_mismatch"] == 0 else 0.0
    trigger_score = max(0.0, 1.0 - feat["trigger_count"] / 5.0)
    redirect_score = max(0.0, 1.0 - feat["redirect_count"] / 4.0)
    length_score = 1.0 if feat["url_length"] <= 50 else max(0.0, 1.0 - ((feat["url_length"] - 50) / 170.0))
    special_score = max(0.0, 1.0 - feat["special_char_ratio"] / 0.15)

    # Stronger weight for brand mismatch
    weights = {
        "token": 0.1,
        "brand": 0.5,
        "trigger": 0.2,
        "redirect": 0.1,
        "length": 0.05,
        "special": 0.05
    }

    weighted = (
        token_score * weights["token"] +
        brand_score * weights["brand"] +
        trigger_score * weights["trigger"] +
        redirect_score * weights["redirect"] +
        length_score * weights["length"] +
        special_score * weights["special"]
    )

    return int(round(weighted * 100))

# ------------------------------
#  ROUTES
# ------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze")
def analyze_page():
    return render_template("analyze.html")

@app.route("/scan", methods=["POST"])
def scan_url():
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400

    try:
        feat = extract_features(url)
        score = compute_safety_score(feat)
        prediction = "Safe URL" if score > SAFE_THRESHOLD else "Phishing URL"

        insights = [
            f"URL Length: {feat['url_length']}",
            f"Special Characters: {feat['special_chars_count']} (ratio {feat['special_char_ratio']})",
            f"Trigger Words: {feat['trigger_count']}",
            f"Token Mismatch: {'Yes' if feat['token_mismatch'] else 'No'}",
            f"Brand Mismatch: {'Yes' if feat['brand_mismatch'] else 'No'}",
            f"Redirect Count: {feat['redirect_count']}",
            f"Has HTTPS: {'Yes' if feat['has_https'] else 'No'}",
            f"Has '@' symbol: {'Yes' if feat['has_at'] else 'No'}",
            f"Hostname looks like IP: {'Yes' if feat['has_ip'] else 'No'}"
        ]

        return jsonify({
            "status": "success",
            "prediction": prediction,
            "trust": score,
            "features": insights
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
