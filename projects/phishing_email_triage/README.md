# Offline Phishing Email Metadata Triage

A small, defensive Python 3.10+ CLI for inspecting **saved, authorized or synthetic** RFC 5322 email files. No dependencies outside the Python standard library. Does **not** send email, contact servers, visit URLs, download attachments, or classify a message as definitively malicious.

## Run

From this directory:

```bash
python email_triage.py samples/synthetic.eml
python -m unittest discover -s tests -v
```

Output is JSON with reported SPF/DKIM/DMARC values, URL **hostnames only** (not paths or query strings), attachment **content type and decoded size only**, and review indicators.

## Technical decisions

- `Authentication-Results` is treated as **unverified sender-supplied data** until a trusted receiving mail server is established. Header results are not independent SPF/DKIM/DMARC validation.
- The parser limits input to 2 MB, MIME parts to 100, and distinct URL hosts to 100, bounding ordinary processing. This is not a hardened sandbox for hostile MIME decompression or memory exhaustion.
- No URL paths, query tokens, email addresses, attachment filenames, or attachment bodies are included in the JSON output. Review the original evidence securely if deeper investigation is authorized.
- This is a triage aid, not a malware scanner, phishing verdict, DMARC alignment validator, or forensic chain-of-custody system.
- The synthetic example uses reserved `.test` domains. Do not upload real messages containing personal data or secrets.

## Verification

Run the offline unittest suite from this folder. During local development on 2026-11-16, the five tests passed and Python compilation passed; hosted CI and clean-checkout testing must be independently verified before merging.

## SOC / IT support relevance

Demonstrates safe email incident intake, structured parsing, evidence minimization, suspicious authentication indicators, and explainable JSON reports. Useful for junior SOC investigations and service-desk phishing escalation.

AI-assisted development. Review results manually; no live target testing.
