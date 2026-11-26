# 🛡️ PhishGuard – Multi-Layer Phishing Detection System

PhishGuard is a machine learning-based phishing detection system designed to identify potentially malicious and suspicious websites through multiple layers of analysis.

Unlike traditional URL-only detection systems, PhishGuard combines URL-based machine learning, website content inspection, and threat-intelligence lookup to provide a more comprehensive security assessment.

## 🚀 Project Overview

Phishing attacks use fraudulent websites and URLs to steal sensitive information such as usernames, passwords, banking details, and personal data.

PhishGuard aims to help users identify potentially dangerous websites before interacting with them.

The system analyses submitted URLs using three detection layers and generates an overall screening report with individual findings.

## ✨ Key Features

### 1. Machine Learning-Based URL Detection
- Uses a trained machine learning model to classify URLs.
- Identifies URL patterns associated with phishing websites.
- Uses TF-IDF character-level feature extraction.
- Implements Logistic Regression for classification.
- Displays the model's prediction and confidence score.

### 2. Website Content Inspection
- Inspects website HTML content.
- Identifies password input fields.
- Detects HTML forms and external form destinations.
- Checks for iframe elements.
- Identifies external links.
- Checks HTTP and HTTPS usage.
- Monitors limited redirect behaviour.

### 3. Threat Intelligence Integration
- Integrates with Google Safe Browsing API.
- Checks submitted URLs against known threat information.
- Identifies reported malware and social engineering threats.
- Supports optional API key configuration.

### 4. Scan History
- Stores previous scan results using SQLite.
- Displays recently scanned URLs.
- Maintains prediction results and timestamps.

### 5. Web-Based Interface
- Built using HTML and CSS.
- Developed with Python Flask.
- Provides an interactive URL scanning interface.
- Displays individual analysis results.

## 🧠 System Architecture

```text
              USER
                |
                v
          ENTER WEBSITE URL
                |
                v
        URL VALIDATION LAYER
                |
                v
       MULTI-LAYER ANALYSIS
                |
       +--------+--------+
       |        |        |
       v        v        v
     URL      WEBSITE   THREAT
     ML       CONTENT   INTELLIGENCE
     MODEL    ANALYSIS  LOOKUP
       |        |        |
       +--------+--------+
                |
                v
        COMBINED SCREENING
              REPORT
                |
        +-------+-------+
        |               |
        v               v
    RESULT DISPLAY   SQLITE HISTORY
```

## 🛠️ Technologies Used

| Category | Technology |
|---|---|
| Programming Language | Python |
| Backend | Flask |
| Machine Learning | Scikit-learn |
| ML Algorithm | Logistic Regression |
| Feature Extraction | TF-IDF |
| Data Processing | Pandas, NumPy |
| Website Inspection | BeautifulSoup |
| HTTP Requests | Requests |
| Database | SQLite |
| Frontend | HTML, CSS |
| Threat Intelligence | Google Safe Browsing API |
| Development Tool | Visual Studio Code |

## 📊 Machine Learning Model

The project uses the PhiUSIIL Phishing URL dataset from the UCI Machine Learning Repository.

Dataset preparation:
- Total selected URLs: 40,000
- Legitimate URLs: 20,000
- Phishing URLs: 20,000
- Training samples: 32,000
- Testing samples: 8,000

Model details:
- Character-level TF-IDF vectorization
- Character n-grams: 3–5
- Maximum features: 30,000
- Classification algorithm: Logistic Regression

### Model Performance

**Achieved test accuracy: 99.41%**

The model was evaluated using a train-test split and classification metrics including precision, recall, and F1-score.

Note: This is the measured result on the selected test split. It does not guarantee equivalent performance on new or real-world phishing URLs.

## 📁 Project Structure

```text
PhisingURLDetector/
│
├── data/
│   ├── urls.csv
│   └── scan_history.db
│
├── models/
│   └── phishing_model.joblib
│
├── templates/
│   └── index.html
│
├── static/
│   └── style.css
│
├── download_dataset.py
├── train_models.py
├── app.py
├── requirements.txt
├── .gitignore
└── README.md
```

## ⚙️ Installation and Setup

### Step 1: Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd PhisingURLDetector
```

### Step 2: Create a Virtual Environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Prepare the Dataset

Download the PhiUSIIL dataset from:

https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

Place the downloaded CSV in the expected location:

```text
data/PhiUSIIL_Phishing_URL_Dataset.csv
```

Run:

```bash
python download_dataset.py
```

This prepares the selected 40,000 URL samples in `data/urls.csv`.

### Step 5: Train the Machine Learning Model

```bash
python train_models.py
```

The trained model will be saved as:

```text
models/phishing_model.joblib
```

### Step 6: Start the Flask Application

```bash
python app.py
```

### Step 7: Open the Application

Visit the following address in your browser:

http://127.0.0.1:5000

## 🔑 Google Safe Browsing API Configuration

Threat-intelligence lookup is optional.

Configure your Google Safe Browsing API key in PowerShell:

```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY="YOUR_API_KEY"
python app.py
```

If the API key is not configured, the application will mark the threat-intelligence check as skipped.

## 🔒 Security Considerations

- The application does not execute JavaScript from inspected websites.
- Website inspection has request timeouts and a response-size limit.
- Redirect destinations are checked before requests.
- Localhost and non-public IP destinations are blocked by basic validation.
- Submitted URLs may be sent to Google Safe Browsing when that integration is enabled.
- Scan results are screening indicators, not proof of website safety.

This project is an educational prototype. Its network restrictions are not sufficient to guarantee protection against all server-side request forgery (SSRF), DNS rebinding, or malicious-content risks. Run locally only; additional isolation and security controls are required before public deployment.

## 🔮 Future Enhancements

- Advanced URL feature extraction.
- Explainable AI-based prediction reports.
- Domain age and registration analysis.
- Additional threat-intelligence providers.
- Real-time phishing detection.
- Improved frontend dashboard.
- Enhanced risk scoring and visual analytics.
- Automated security testing.

## 🎯 Project Objective

The main objective of PhishGuard is to develop a multi-layer phishing detection prototype that combines machine learning, website structure inspection, and threat intelligence to help users recognise potentially malicious websites.

## 👩‍💻 Developer

**Logavani SS**

B.Tech – Information Technology

Dr. N.G.P. Institute of Technology

## 📌 Disclaimer

PhishGuard is developed for educational and research purposes. Its results should not be treated as a guarantee that a website is safe or malicious. Always exercise caution before entering sensitive information online.

---

**PhishGuard – Check Before You Click! 🛡️**