# 🛡️ Phishing Detection Tool

A Python-based cybersecurity tool that detects phishing URLs using a **dual-layer approach** — combining blacklist lookups with a **Machine Learning classifier** for accurate, real-time threat detection.

---

## 🔍 How It Works

This tool uses two layers of detection:

1. **Blacklist Check** — The URL is checked against a database of known malicious domains (`top-1m.csv`, `verified_online.csv`). If it matches, it's flagged immediately.
2. **Machine Learning Classification** — If the URL isn't on the blacklist, it's passed through a trained ML model (built with scikit-learn) that analyzes URL patterns and features to predict whether it's phishing or legitimate.

---

## 🧠 Tech Stack

| Technology | Purpose |
|------------|---------|
| Python | Core programming language |
| scikit-learn | ML model training & prediction |
| Pandas | Data loading and preprocessing |

---

## 📁 Project Structure

```
phishing-detection-tool/
│
├── phishing.py           # Main detection script
├── top-1m.csv            # Top 1 million legitimate domains (Alexa)
├── verified_online.csv   # Verified phishing URLs dataset
└── README.md             # Project documentation
```

---

## ⚙️ Installation & Setup

**1. Clone the repository**
```bash
git clone https://github.com/G-Akhil-7/phishing-detection-tool.git
cd phishing-detection-tool
```

**2. Install dependencies**
```bash
pip install scikit-learn pandas
```

**3. Run the tool**
```bash
python phishing.py
```

---

## 🚀 Features

- ✅ Dual-layer detection (Blacklist + ML)
- ✅ Trained on real-world phishing datasets
- ✅ Fast URL lookup using Pandas
- ✅ Simple command-line interface

---

## 📊 Dataset

- **`top-1m.csv`** — List of top 1 million legitimate domains used to verify safe URLs
- **`verified_online.csv`** — Dataset of verified phishing URLs used to train and test the ML model

---

## 🤖 ML Model Details

The machine learning component uses **scikit-learn** to extract and analyze features from URLs such as:
- URL length
- Presence of special characters (`@`, `-`, `//`)
- Domain patterns
- Subdomain depth

These features help the model distinguish between legitimate and phishing URLs.

---

## 👨‍💻 Author

**Akhil G**
- GitHub: [@G-Akhil-7](https://github.com/G-Akhil-7)

---

## 📌 Note

This is my **first project** — built to learn cybersecurity concepts and apply machine learning to real-world problems. Feedback and suggestions are welcome!
