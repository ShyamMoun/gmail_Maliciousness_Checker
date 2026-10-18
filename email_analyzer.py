
import re
from email import policy
from email.parser import Parser
from urllib.parse import urlparse

URGENT_PHRASES = [
    "verify your account immediately",
    "account will be suspended",
    "urgent action required",
    "confirm your password",
    "you have won",
    "payment failed",
    "click immediately",
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def analyze_email(sender, subject, body):
    findings = []
    score = 0

    sender = sender.strip()
    subject = subject.strip()
    body = body.strip()
    content = f"{subject}\n{body}".lower()

    if not sender or "@" not in sender:
        findings.append("Sender address is missing or malformed.")
        score += 15

    for phrase in URGENT_PHRASES:
        if phrase in content:
            findings.append(f"Urgency or social-engineering phrase: '{phrase}'")
            score += 15

    urls = URL_PATTERN.findall(body)

    for raw_url in urls:
        url = raw_url.rstrip(".,);]")
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()

        if not host:
            findings.append("A URL has an invalid or missing hostname.")
            score += 15
            continue

        if parsed.username or parsed.password:
            findings.append(
                f"URL contains embedded credentials: {host}"
            )
            score += 25

        if host.startswith("xn--") or ".xn--" in host:
            findings.append(
                f"URL uses an internationalized/punycode hostname: {host}"
            )
            score += 20

        if parsed.scheme.lower() == "http":
            findings.append(f"URL uses unencrypted HTTP: {host}")
            score += 5

        if host in {"bit.ly", "tinyurl.com", "t.co"}:
            findings.append(f"Known URL shortener detected: {host}")
            score += 15

    score = min(score, 100)

    if score >= 50:
        risk = "HIGH"
    elif score >= 20:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    if not findings:
        findings.append("No indicators covered by these rules were detected.")

    return {
        "risk": risk,
        "score": score,
        "findings": findings,
        "url_count": len(urls),
    }


def main():
    print("=== Email Maliciousness Checker ===")
    print("Paste sample email details. Do not paste passwords or secrets.\n")

    sender = input("Sender email address: ")
    subject = input("Subject: ")
    print("Paste the email body. Press Enter on an empty line to finish:")

    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break

        if not line:
            break
        lines.append(line)

    result = analyze_email(sender, subject, "\n".join(lines))

    print("\n=== Analysis Report ===")
    print(f"Risk level: {result['risk']}")
    print(f"Risk score: {result['score']}/100")
    print(f"URLs found: {result['url_count']}")
    print("Findings:")

    for finding in result["findings"]:
        print(f"- {finding}")

    print("\nThis is a heuristic assessment, not proof of maliciousness.")


if __name__ == "__main__":
    main()
