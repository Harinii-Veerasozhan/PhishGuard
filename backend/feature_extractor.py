import re
from urllib.parse import urlparse

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
            any(word in url.lower() for word in 
                ["login", "secure", "verify", "update", "bank", "confirm"])
        )
    }

    return list(features.values())
