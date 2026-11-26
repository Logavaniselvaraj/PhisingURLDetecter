
import os
import socket
import ipaddress
import sqlite3
from pathlib import Path
from urllib.parse import urlparse, urljoin

import joblib
import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request

app = Flask(__name__)

MODEL_PATH = Path("models/phishing_model.joblib")
DATABASE_PATH = Path("data/scan_history.db")

MAX_HTML_BYTES = 1_000_000
MAX_REDIRECTS = 3
TIMEOUT = (3, 5)

# Optional Google Safe Browsing API key.
# Never hardcode your actual API key here.
GOOGLE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        "Model not found. Run python train_models.py first."
    )

model = joblib.load(MODEL_PATH)


def validate_public_url(raw_url):
    """Normalise a URL and reject non-public destinations."""

    raw_url = raw_url.strip()

    if not raw_url or any(c.isspace() for c in raw_url):
        raise ValueError("Enter a valid URL without spaces.")

    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("The URL does not contain a hostname.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing login credentials are blocked.")

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")

    if port is not None and not (1 <= port <= 65535):
        raise ValueError("The URL contains an invalid port.")

    hostname = parsed.hostname.rstrip(".").lower()

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Localhost addresses are blocked.")

    if hostname.endswith(".local"):
        raise ValueError("Local network hostnames are blocked.")

    try:
        # If the hostname is an IP address, validate it directly.
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            answers = socket.getaddrinfo(
                hostname,
                port or (443 if parsed.scheme == "https" else 80),
                type=socket.SOCK_STREAM,
            )
            addresses = list({
                ipaddress.ip_address(answer[4][0])
                for answer in answers
            })
        except (OSError, ValueError):
            raise ValueError("The hostname could not be resolved.")

    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError(
            "This URL resolves to a non-public or restricted IP address."
        )

    # Return the normalised URL while preserving the original hostname.
    return raw_url


def inspect_website(start_url):
    """Fetch a small amount of HTML without executing page scripts."""

    findings = []
    current_url = start_url
    redirects = 0
    session = requests.Session()

    # Avoid inheriting proxy settings from the environment in this demo.
    session.trust_env = False

    headers = {
        "User-Agent": "PhishGuard-Educational-Scanner/1.0",
        "Accept": "text/html,application/xhtml+xml",
    }

    try:
        for attempt in range(MAX_REDIRECTS + 1):
            # Re-check every destination before making a request.
            current_url = validate_public_url(current_url)

            with session.get(
                current_url,
                headers=headers,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
            ) as response:

                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")

                    if not location:
                        return {
                            "status": "unavailable",
                            "error": "Redirect had no destination.",
                            "findings": findings,
                        }

                    if attempt >= MAX_REDIRECTS:
                        return {
                            "status": "unavailable",
                            "error": "Too many redirects.",
                            "findings": findings,
                        }

                    current_url = urljoin(current_url, location)
                    redirects += 1
                    continue

                content_type = response.headers.get(
                    "Content-Type", ""
                ).lower()

                if "text/html" not in content_type and \
                   "application/xhtml+xml" not in content_type:
                    return {
                        "status": "unavailable",
                        "error": "The destination did not return HTML.",
                        "findings": findings,
                    }

                chunks = []
                size = 0

                for chunk in response.iter_content(chunk_size=16384):
                    if not chunk:
                        continue

                    remaining = MAX_HTML_BYTES - size

                    if len(chunk) > remaining:
                        chunks.append(chunk[:remaining])
                        size = MAX_HTML_BYTES
                        break

                    chunks.append(chunk)
                    size += len(chunk)

                    if size >= MAX_HTML_BYTES:
                        break

                encoding = response.encoding or "utf-8"
                html = b"".join(chunks).decode(
                    encoding, errors="replace"
                )

        soup = BeautifulSoup(html, "html.parser")
        page_title = (
            soup.title.get_text(" ", strip=True)
            if soup.title else "(No page title)"
        )

        page_host = urlparse(current_url).hostname
        password_fields = soup.find_all(
            "input",
            attrs={"type": lambda value:
                   value and value.lower() == "password"},
        )

        forms = soup.find_all("form")
        external_form_count = 0

        for form in forms:
            action = form.get("action", "").strip()

            if not action:
                # Empty action generally submits to the current page.
                continue

            action_url = urljoin(current_url, action)
            action_host = urlparse(action_url).hostname

            if action_host and action_host.lower() != page_host.lower():
                external_form_count += 1

        if urlparse(current_url).scheme != "https":
            findings.append(
                "The final page uses HTTP rather than HTTPS."
            )

        if password_fields and urlparse(current_url).scheme != "https":
            findings.append(
                "Password fields appear on a page using HTTP."
            )

        if external_form_count:
            findings.append(
                f"{external_form_count} form(s) submit to another hostname."
            )

        if password_fields:
            findings.append(
                f"The page contains {len(password_fields)} password field(s)."
            )

        iframe_count = len(soup.find_all("iframe"))

        if iframe_count:
            findings.append(
                f"The page contains {iframe_count} iframe(s)."
            )

        external_link_count = sum(
            1 for link in soup.find_all("a", href=True)
            if urlparse(urljoin(current_url, link["href"])).hostname
            and urlparse(urljoin(current_url, link["href"])).hostname.lower()
            != page_host.lower()
        )

        return {
            "status": "completed",
            "final_url": current_url,
            "title": page_title[:300],
            "status_code": response.status_code,
            "redirects": redirects,
            "password_fields": len(password_fields),
            "forms": len(forms),
            "external_forms": external_form_count,
            "iframes": iframe_count,
            "external_links": external_link_count,
            "findings": findings,
        }

    except (requests.RequestException, ValueError, OSError) as exc:
        return {
            "status": "unavailable",
            "error": str(exc)[:250],
            "findings": findings,
        }

    finally:
        session.close()


def check_google_safe_browsing(url):
    """Check Google's threat database when an API key is configured."""

    if not GOOGLE_API_KEY:
        return {
            "status": "skipped",
            "message": "Google Safe Browsing API key is not configured.",
            "matches": [],
        }

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/"
        "threatMatches:find"
    )

    payload = {
        "client": {
            "clientId": "phishguard-student-project",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            endpoint,
            params={"key": GOOGLE_API_KEY},
            json=payload,
            timeout=TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])

        return {
            "status": "completed",
            "message": (
                "Known threat found."
                if matches else "No matching threat returned."
            ),
            "matches": [
                {
                    "type": match.get("threatType", "Unknown"),
                    "platform": match.get("platformType", "Unknown"),
                }
                for match in matches
            ],
        }

    except (requests.RequestException, ValueError):
        return {
            "status": "unavailable",
            "message": "Threat-intelligence service could not be reached.",
            "matches": [],
        }


def save_scan(url, result, confidence):
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                result TEXT NOT NULL,
                confidence REAL NOT NULL,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute(
            "INSERT INTO scans (url, result, confidence) VALUES (?, ?, ?)",
            (url, result, confidence),
        )


def get_history():
    if not DATABASE_PATH.exists():
        return []

    with sqlite3.connect(DATABASE_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("""
            SELECT url, result, confidence, scanned_at
            FROM scans
            ORDER BY id DESC
            LIMIT 10
        """).fetchall()


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    error = None
    submitted_url = ""

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()

        try:
            candidate = validate_public_url(submitted_url)

            # Layer 1: ML model checks URL text.
            prediction = int(model.predict([candidate])[0])
            probabilities = model.predict_proba([candidate])[0]
            ml_confidence = round(
                float(probabilities[prediction]) * 100, 2
            )

            ml_result = (
                "Potential phishing"
                if prediction == 1
                else "Likely legitimate"
            )

            # Layer 2: inspect a limited amount of HTML.
            content = inspect_website(candidate)

            # Layer 3: optional external threat lookup.
            threat = check_google_safe_browsing(candidate)

            # Do not combine model confidence with other checks as if
            # it were a calibrated overall risk probability.
            known_threat = (
                threat["status"] == "completed"
                and bool(threat["matches"])
            )

            suspicious_content = bool(content.get("findings"))

            if known_threat:
                verdict = "Known threat reported"
            elif prediction == 1:
                verdict = "Potential phishing"
            elif suspicious_content:
                verdict = "Needs caution"
            else:
                verdict = "No strong warning detected"

            report = {
                "verdict": verdict,
                "ml_result": ml_result,
                "ml_confidence": ml_confidence,
                "content": content,
                "threat": threat,
            }

            save_scan(candidate, verdict, ml_confidence)

        except ValueError as exc:
            error = str(exc)

    return render_template(
        "index.html",
        result=report["verdict"] if report else None,
        confidence=report["ml_confidence"] if report else None,
        submitted_url=submitted_url,
        error=error,
        history=get_history(),
        report=report,
    )


if __name__ == "__main__":
    # Local development only. Do not expose this server to the internet.
    app.run(debug=True)
