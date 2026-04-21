"""
PHISHING DETECTION TOOL
=======================
Install: pip install pandas scikit-learn

Files needed in same folder:
  - verified_online.csv  (PhishTank)
  - top-1m.csv           (Tranco)
"""

import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# ──────────────────────────────────────────────
# HELPER: Strip URL down to plain domain
# ──────────────────────────────────────────────

def get_domain(url):
    url = str(url).strip().lower()
    url = url.replace("https://", "").replace("http://", "").replace("www.", "")
    url = url.split("/")[0]
    url = url.split("?")[0]
    url = url.split("#")[0]
    return url


# ──────────────────────────────────────────────
# STEP 1: LOAD DATA
# ──────────────────────────────────────────────

print("Loading data ...")

phish_raw = pd.read_csv("verified_online.csv", encoding="latin1", low_memory=False)
legit_raw  = pd.read_csv("top-1m.csv")

# Raw URL lists
phish_urls = phish_raw["url"].dropna().astype(str).str.strip().tolist()
legit_col  = "domain" if "domain" in legit_raw.columns else legit_raw.columns[-1]
legit_urls = legit_raw[legit_col].dropna().astype(str).str.strip().tolist()

# ── Phishing: store FULL URLs for exact match (not just domain)
# This prevents google.com being flagged just because
# sites.google.com/fake-page is in PhishTank
phish_full_set   = set(u.strip().lower() for u in phish_urls)

# ── Legit: store normalized domains
legit_domain_set = set(get_domain(u) for u in legit_urls)

print(f"  Phishing URLs loaded : {len(phish_urls):,}")
print(f"  Legit domains loaded : {len(legit_urls):,}")


# ──────────────────────────────────────────────
# STEP 2: FEATURE EXTRACTION
# ──────────────────────────────────────────────

def extract_features(url):
    url = str(url)
    try:
        parsed   = urlparse(url if "://" in url else "http://" + url)
        hostname = parsed.hostname or ""
        path     = parsed.path     or ""
        scheme   = parsed.scheme   or ""
    except:
        hostname = path = scheme = ""

    full = url.lower()

    suspicious_words = ["login", "secure", "verify", "update", "account",
                        "banking", "confirm", "paypal", "amazon", "password",
                        "free", "win", "prize", "click", "signin"]

    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("/"),
        url.count("@"),
        url.count("="),
        url.count("%"),
        sum(c.isdigit() for c in url),
        int(scheme == "https"),
        int(bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", hostname))),
        int("-" in hostname),
        int(url.count("//") > 1),
        int(any(full.endswith(t) for t in [".xyz",".tk",".ml",".ga",".cf",".gq"])),
        sum(w in full for w in suspicious_words),
        len(hostname),
        len(path),
        (-sum((hostname.count(c)/len(hostname)) *
              np.log2(hostname.count(c)/len(hostname))
              for c in set(hostname)) if hostname else 0),
    ]


# ──────────────────────────────────────────────
# STEP 3: TRAIN RANDOM FOREST
# ──────────────────────────────────────────────

print("\nTraining Random Forest ...")

phish_df = pd.DataFrame({"url": phish_urls, "label": 1})
legit_df  = pd.DataFrame({"url": "http://" + pd.Series(legit_urls), "label": 0})

data = pd.concat([phish_df, legit_df], ignore_index=True).sample(frac=1, random_state=42)

X = pd.DataFrame(data["url"].apply(extract_features).tolist()).fillna(0)
y = data["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2,
                                                     random_state=42, stratify=y)

model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

acc = model.score(X_test, y_test)
print(f"Model trained! Accuracy: {acc*100:.1f}%")


# ──────────────────────────────────────────────
# STEP 4: URL CHECKER
# ──────────────────────────────────────────────

def check_url(url):
    url        = url.strip()
    url_lower  = url.lower()
    domain     = get_domain(url)

    print(f"\n  Checking : {url}")
    print(f"  Domain   : {domain}")

# ── 1. Direct match in Tranco ───────────────────
    if domain in legit_domain_set:
        print(f"  RESULT   : LEGITIMATE")
        print(f"  Reason   : Found in Tranco top-1M trusted list")
        return

   # ── 2. Check FULL URL against PhishTank ─────────
    if url_lower in phish_full_set:
        print(f"  RESULT   : PHISHING")
        print(f"  Reason   : Exact URL found in PhishTank database")
        return

    # ── 3. Not found in either → AI prediction ──────
    features = pd.DataFrame([extract_features(url)])
    prob     = model.predict_proba(features)[0][1]

    if prob >= 0.7:
        verdict = "PHISHING (AI Prediction)"
        reason  = f"AI predicts this is phishing  (confidence: {prob*100:.1f}%)"
    elif prob >= 0.4:
        verdict = "SUSPICIOUS — Possibly Phishing"
        reason  = f"AI is not sure but leans phishing  (confidence: {prob*100:.1f}%)"
    else:
        verdict = "Likely Legitimate (AI Prediction)"
        reason  = f"AI predicts this is safe  (phishing chance: {prob*100:.1f}%)"

    print(f"  RESULT   : {verdict}")
    print(f"  Reason   : Not in either database. {reason}")
    print(f"  Note     : This is a prediction, always double-check unknown URLs.")


# ──────────────────────────────────────────────
# STEP 5: INTERACTIVE LOOP
# ──────────────────────────────────────────────

print("\n" + "="*50)
print("  PHISHING DETECTION TOOL  (type 'quit' to exit)")
print("="*50)

while True:
    url = input("\n  Enter URL to check: ").strip()
    if url.lower() in ("quit", "exit", "q"):
        print("  Goodbye!")
        break
    if not url:
        print("  Please enter a URL.")
        continue
    check_url(url)