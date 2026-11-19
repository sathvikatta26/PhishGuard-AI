
from urllib.parse import urlsplit
import ipaddress
import re


# Suspicious URL keywords
SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "bank",
    "confirm",
    "signin",
    "wallet",
    "payment"
]


def analyze_url(url):

    indicators = []
    recommendations = []
    risk_score = 0

    # Parse URL
    parsed = urlsplit(
        url if "://" in url else "http://" + url
    )

    hostname = parsed.hostname or ""
    full_url = url.lower()

    # 1. URL length analysis
    if len(url) > 120:
        indicators.append("Very long URL")
        risk_score += 20

    elif len(url) > 75:
        indicators.append("Long URL")
        risk_score += 10

    # 2. IP address detection
    try:
        ipaddress.ip_address(hostname)

        indicators.append(
            "Uses an IP address instead of a domain name"
        )

        risk_score += 25

    except ValueError:
        pass

    # 3. Suspicious keyword detection
    found_keywords = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in full_url
    ]

    if found_keywords:

        indicators.append(
            "Suspicious keywords: " +
            ", ".join(found_keywords)
        )

        risk_score += min(
            30,
            len(found_keywords) * 10
        )

    # 4. @ symbol detection
    if "@" in parsed.netloc:

        indicators.append(
            "Contains an @ symbol in the URL authority"
        )

        risk_score += 20

    # 5. Punycode detection
    if "xn--" in hostname:

        indicators.append(
            "Contains a punycode domain"
        )

        risk_score += 20

    # 6. Subdomain analysis
    if len(hostname.split(".")) > 4:

        indicators.append(
            "Contains many subdomains"
        )

        risk_score += 15

    # 7. Special character analysis
    special_count = len(
        re.findall(r"[^a-zA-Z0-9]", url)
    )

    if special_count > 15:

        indicators.append(
            "Contains many special characters"
        )

        risk_score += 10

    # 8. HTTPS analysis
    if parsed.scheme != "https":

        indicators.append(
            "Does not use HTTPS"
        )

        risk_score += 5

        recommendations.append(
            "Check the website's authenticity before entering information."
        )

    # Keep score within 0-100
    risk_score = min(risk_score, 100)

    # 9. Risk classification
    if risk_score >= 50:

        risk_level = "High"

    elif risk_score >= 25:

        risk_level = "Medium"

    else:

        risk_level = "Low"

    # 10. Safety recommendations
    if risk_level == "High":

        recommendations.append(
            "Avoid opening this URL or entering personal information."
        )

    elif risk_level == "Medium":

        recommendations.append(
            "Verify the website address carefully before proceeding."
        )

    else:

        recommendations.append(
            "No major indicators were detected, but always verify the website."
        )

    # Default indicator
    if not indicators:

        indicators.append(
            "No major suspicious URL indicators detected"
        )

    return {

        "risk_score": risk_score,

        "risk_level": risk_level,

        "indicators": indicators,

        "recommendations": recommendations

    }
