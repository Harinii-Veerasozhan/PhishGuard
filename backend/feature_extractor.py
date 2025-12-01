import re
from urllib.parse import urlparse

# List of suspicious top-level domains
SUSPICIOUS_TLDS = ["xyz", "top", "club", "monster", "work", "gq", "ml", "tk"]

# Common phishing keywords
PHISHING_KEYWORDS = [
    "secure", "account", "verify", "update", "login",
    "signin", "bank", "paypal", "auth", "confirm"
]

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.netloc.lower()  # ensure lowercase for comparisons

    # Extract TLD
    tld = hostname.split('.')[-1] if '.' in hostname else ''

    # Feature dictionary
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
        "suspicious_words": int(any(word in url.lower() for word in PHISHING_KEYWORDS)),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS)
    }

    # Return features in fixed order
    feature_order = [
        "url_length", "hostname_length", "count_dots", "count_hyphen",
        "count_at", "count_question", "count_percent", "count_slash",
        "count_equal", "has_https", "digits_count", "letters_count",
        "special_char_count", "suspicious_words", "suspicious_tld"
    ]

    return [features[f] for f in feature_order]

# Example usage
if __name__ == "__main__":
    test_url = "http://secure-login-example.tk/account?user=123"
    print(extract_features(test_url))
