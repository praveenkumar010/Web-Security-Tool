import requests
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# ----------------------------------
# SECURITY HEADERS
# ----------------------------------

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

# ----------------------------------
# COMMON PORTS
# ----------------------------------

COMMON_PORTS = [
    21,
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    3306,
    8080
]

# ----------------------------------
# HEADER CHECK
# ----------------------------------

def check_security_headers(headers):

    results = {}

    for header in SECURITY_HEADERS:
        results[header] = header in headers

    return results

# ----------------------------------
# PORT SCAN
# ----------------------------------

def scan_ports(domain):

    open_ports = []

    for port in COMMON_PORTS:

        try:

            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.settimeout(1)

            result = sock.connect_ex(
                (domain, port)
            )

            if result == 0:
                open_ports.append(port)

            sock.close()

        except:
            pass

    return open_ports

# ----------------------------------
# TECHNOLOGY DETECTION
# ----------------------------------

def detect_technologies(headers, html):

    technologies = []

    server = headers.get("Server", "")

    if "Apache" in server:
        technologies.append("Apache")

    if "nginx" in server.lower():
        technologies.append("Nginx")

    if "cloudflare" in server.lower():
        technologies.append("Cloudflare")

    html_lower = html.lower()

    if "bootstrap" in html_lower:
        technologies.append("Bootstrap")

    if "jquery" in html_lower:
        technologies.append("jQuery")

    if "wp-content" in html_lower:
        technologies.append("WordPress")

    return list(set(technologies))

# ----------------------------------
# FORM DETECTION
# ----------------------------------

def detect_forms(soup):

    forms = soup.find_all("form")

    return len(forms)

# ----------------------------------
# SQLI TEST
# ----------------------------------

def test_sqli(url):

    try:

        payload = "' OR 1=1 --"

        response = requests.get(
            url + "?id=" + payload,
            timeout=5
        )

        errors = [

            "sql syntax",
            "mysql",
            "database error",
            "syntax error",
            "unclosed quotation mark"

        ]

        for error in errors:

            if error in response.text.lower():
                return True

        return False

    except:
        return False

# ----------------------------------
# XSS TEST
# ----------------------------------

def test_xss(url):

    try:

        payload = "<script>alert('xss')</script>"

        response = requests.get(
            url + "?q=" + payload,
            timeout=5
        )

        return payload.lower() in response.text.lower()

    except:
        return False

# ----------------------------------
# AI SECURITY ASSESSMENT
# ----------------------------------

def generate_ai_assessment(

        risk_score,
        headers_score,
        forms_count,
        open_ports

):

    if risk_score >= 70:

        return (
            "High risk target. Multiple security "
            "misconfigurations detected. Immediate "
            "remediation is recommended."
        )

    elif risk_score >= 40:

        return (
            "Medium risk target. Security posture "
            "can be improved by implementing missing "
            "security controls and hardening services."
        )

    else:

        return (
            "Low risk target. Basic security controls "
            "appear to be in place. Continue periodic "
            "security monitoring."
        )

# ----------------------------------
# MAIN SCANNER
# ----------------------------------

def scan_website(url):

    if not url.startswith("http"):
        url = "https://" + url

    try:

        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent":
                "WebAppSecurityTool"
            }
        )

        html = response.text

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

        domain = urlparse(url).netloc

        # -----------------------
        # HEADER ANALYSIS
        # -----------------------

        headers_result = check_security_headers(
            response.headers
        )

        headers_score = sum(
            headers_result.values()
        )

        # -----------------------
        # FORM ANALYSIS
        # -----------------------

        forms_count = detect_forms(soup)

        # -----------------------
        # TECHNOLOGY ANALYSIS
        # -----------------------

        technologies = detect_technologies(
            response.headers,
            html
        )

        # -----------------------
        # PORT SCAN
        # -----------------------

        open_ports = scan_ports(domain)

        # -----------------------
        # VULNERABILITIES
        # -----------------------

        vulnerabilities = []

        recommendations = []

        risk_score = 0

        for header, present in headers_result.items():

            if not present:

                vulnerabilities.append({

                    "type":
                    f"Missing {header}",

                    "severity":
                    "Medium",

                    "description":
                    f"{header} is not configured."

                })

                risk_score += 10

        # SQLi

        if test_sqli(url):

            vulnerabilities.append({

                "type":
                "Possible SQL Injection",

                "severity":
                "High",

                "description":
                "Potential SQLi behaviour detected."

            })

            recommendations.append(
                "Use parameterized queries."
            )

            risk_score += 30

        # XSS

        if test_xss(url):

            vulnerabilities.append({

                "type":
                "Possible XSS",

                "severity":
                "High",

                "description":
                "Reflected XSS payload detected."

            })

            recommendations.append(
                "Sanitize user inputs."
            )

            risk_score += 30

        # FORMS

        if forms_count > 0:

            risk_score += 5

        # PORTS

        if len(open_ports) > 5:

            risk_score += 15

        # -----------------------
        # RISK LEVEL
        # -----------------------

        if risk_score >= 70:

            risk_level = "HIGH"

        elif risk_score >= 40:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

        # -----------------------
        # ATTACK SURFACE SCORE
        # -----------------------

        attack_surface = min(

            100,

            (
                forms_count * 5 +
                len(open_ports) * 5 +
                (5 - headers_score) * 10
            )

        )

        # -----------------------
        # AI SUMMARY
        # -----------------------

        ai_assessment = generate_ai_assessment(

            risk_score,
            headers_score,
            forms_count,
            open_ports

        )

        return {

            "url": url,

            "risk_score":
            risk_score,

            "risk_level":
            risk_level,

            "headers":
            headers_result,

            "headers_score":
            headers_score,

            "forms_count":
            forms_count,

            "technologies":
            technologies,

            "open_ports":
            open_ports,

            "attack_surface":
            attack_surface,

            "ai_assessment":
            ai_assessment,

            "vulnerabilities":
            vulnerabilities,

            "recommendations":
            recommendations

        }

    except Exception as e:

        return {
            "error": str(e)
        }