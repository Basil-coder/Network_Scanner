"""Offline, metadata-only RFC 5322 email triage. No network requests."""
import argparse
import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 2_000_000
MAX_URLS = 100
MAX_PARTS = 100
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
AUTH_RE = re.compile(r'\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none|temperror|permerror)\b', re.I)


def analyze(raw: bytes) -> dict:
    if len(raw) > MAX_BYTES:
        raise ValueError("Email exceeds 2 MB limit")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    authentication = []
    for header in message.get_all("Authentication-Results", []):
        authentication.extend(
            {"mechanism": match.group(1).lower(), "result": match.group(2).lower()}
            for match in AUTH_RE.finditer(str(header))
        )
    urls, attachments = set(), []
    parts = list(message.walk())
    if len(parts) > MAX_PARTS:
        raise ValueError("Too many MIME parts")
    for part in parts:
        if part.is_multipart():
            continue
        if part.get_content_disposition() == "attachment":
            attachments.append({
                "content_type": part.get_content_type(),
                "size_bytes": len(part.get_payload(decode=True) or b""),
            })
            continue
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (UnicodeError, LookupError, ValueError):
            continue
        for match in URL_RE.finditer(str(content)):
            candidate = match.group(0).rstrip(".,);]")
            try:
                parsed = urlsplit(candidate)
                host = parsed.hostname
            except ValueError:
                continue
            if host and len(urls) < MAX_URLS:
                urls.add((parsed.scheme.lower(), host.lower()))
    findings = []
    if any(a["result"] in ("fail", "softfail", "permerror") for a in authentication):
        findings.append("Reported authentication failure; verify trusted receiver before relying on it")
    if any(a["content_type"] in ("application/x-msdownload", "application/x-dosexec") for a in attachments):
        findings.append("Executable-type attachment metadata; do not open without review")
    if not authentication:
        findings.append("No parseable SPF/DKIM/DMARC results in Authentication-Results")
    return {
        "authentication_claims_unverified": authentication,
        "url_hosts": [{"scheme": scheme, "host": host} for scheme, host in sorted(urls)],
        "attachments_metadata_only": attachments,
        "findings": findings,
        "limitations": "Headers can be forged. No DNS lookups, URL visits, attachment execution or malware verdict.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline email metadata triage")
    parser.add_argument("eml", type=Path, help="Saved .eml file; use synthetic or authorized sanitized samples")
    args = parser.parse_args()
    if args.eml.stat().st_size > MAX_BYTES:
        parser.error("Email exceeds 2 MB limit")
    print(json.dumps(analyze(args.eml.read_bytes()), indent=2))


if __name__ == "__main__":
    main()
