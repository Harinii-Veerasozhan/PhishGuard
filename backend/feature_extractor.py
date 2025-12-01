import re
from urllib.parse import urlparse

TRIGGER_WORDS = ["gift", "win", "offer", "bonus", "prize", "free", "claim"]

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    # 1. Length of URL
    length = len(url)

    # 2. Ratio of special characters
    special_char_ratio = sum(1 for c in url if not c.isalnum()) / length

    # 3. Token mismatch (google != GoOgle)
    tokens = re.findall(r"[A-Za-z]+", domain)
    token_mismatch = 0
    for t in tokens:
        if not (t.islower() or t.isupper()):
            token_mismatch = 1
            break

    # 4. Trigger words
    trigger_word_flag = 1 if any(word in url.lower() for word in TRIGGER_WORDS) else 0

    return [length, special_char_ratio, token_mismatch, trigger_word_flag]
