import requests
from bs4 import BeautifulSoup

def scan_website(url):

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    vulnerabilities = []
    recommendations = []

    risk_score = 0

    try:

        response = requests.get(url, timeout=5)

        headers = response.headers
        html = response.text

        soup = BeautifulSoup(html, 'html.parser')

        # HTTPS CHECK

        if not url.startswith("https"):

            vulnerabilities.append({
                "type": "Insecure Connection",
                "severity": "Medium",
                "description": "Website is not using HTTPS."
            })

            recommendations.append(
                "Enable HTTPS using SSL/TLS."
            )

            risk_score += 20

        # CSP HEADER

        if "Content-Security-Policy" not in headers:

            vulnerabilities.append({
                "type": "Missing CSP Header",
                "severity": "High",
                "description": "Content-Security-Policy missing."
            })

            recommendations.append(
                "Add Content-Security-Policy header."
            )

            risk_score += 25

        # X-FRAME

        if "X-Frame-Options" not in headers:

            vulnerabilities.append({
                "type": "Missing X-Frame-Options",
                "severity": "Medium",
                "description": "Clickjacking protection missing."
            })

            recommendations.append(
                "Add X-Frame-Options header."
            )

            risk_score += 15

        # FORMS

        forms = soup.find_all('form')

        if len(forms) > 0:

            vulnerabilities.append({
                "type": "Forms Detected",
                "severity": "Info",
                "description": f"{len(forms)} forms found."
            })

        # SCRIPT CHECK

        scripts = soup.find_all('script')

        if len(scripts) > 10:

            vulnerabilities.append({
                "type": "High Script Usage",
                "severity": "Low",
                "description": "Many scripts detected."
            })

            risk_score += 10

        # SQLi TEST

        sql_payload = "' OR 1=1 --"

        sql_test_url = url + "?id=" + sql_payload

        sql_response = requests.get(sql_test_url)

        sql_errors = [
            "sql syntax",
            "mysql",
            "syntax error",
            "database error"
        ]

        for error in sql_errors:

            if error.lower() in sql_response.text.lower():

                vulnerabilities.append({
                    "type": "Possible SQL Injection",
                    "severity": "High",
                    "description": "SQL error patterns detected."
                })

                recommendations.append(
                    "Use parameterized queries."
                )

                risk_score += 30

                break

        # XSS TEST

        xss_payload = "<script>alert('xss')</script>"

        xss_url = url + "?q=" + xss_payload

        xss_response = requests.get(xss_url)

        if xss_payload.lower() in xss_response.text.lower():

            vulnerabilities.append({
                "type": "Possible XSS",
                "severity": "High",
                "description": "Reflected XSS payload detected."
            })

            recommendations.append(
                "Sanitize and escape user input."
            )

            risk_score += 30

        # FINAL RISK

        if risk_score >= 70:
            risk_level = "HIGH"

        elif risk_score >= 40:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

        return {

            "url": url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "vulnerabilities": vulnerabilities,
            "recommendations": recommendations

        }

    except Exception as e:

        return {
            "error": str(e)
        }