# Offline Password Policy Audit — synthetic fixtures only

A **defensive training tool** for validating a configurable password policy against self-generated test strings. It is **not** a password cracker, breach checker, authentication service, or real-user password auditor. **Never feed real credentials into this program.** This project is AI-assisted; verify the code and policy choices before use.

## Quick start

Requires Python 3.10+; no third-party dependencies or network access.

```bash
python -m unittest discover -s tests -v
python password_audit.py --policy examples/policy.json --fixtures examples/synthetic_cases.json --output report.json
```

The JSON report includes synthetic IDs, accepted/rejected decisions and reason codes, **never password values**. The CLI prints only counts and the report path. Example IDs deliberately cannot be email addresses.

## Design and limitations

* Validates policy schema and input records; limits file size to 1 MiB and records to 1,000. Duplicate IDs are rejected.
* Length is measured in Python Unicode code points, not bytes or grapheme clusters. Character classes use ASCII lower/upper/digit; symbol means a nonalphanumeric non-whitespace character. This is a teaching simplification.
* Blocklist comparisons use Unicode `casefold()` and are performed in memory. The sample list is **synthetic**, not a leaked-password corpus.
* Reports contain no submitted password strings, but the **input fixture file does contain plaintext test values**. Use only synthetic values; do not log, upload or commit actual credentials.
* Complexity-class rules are included to illustrate legacy policy checks; modern recommendations generally favor long passwords/passphrases, screening against known compromised passwords, MFA and rate limiting rather than mandatory character mixes. This program cannot establish entropy or actual password safety.
* No hashes are created, no credentials are tested against accounts, and no authentication or network calls occur.

## Security review checklist

Run the tests from a fresh checkout; inspect JSON output; confirm no fixture values appear in the report; confirm the tool has no network imports or credential-handling integration. A passing test suite is not a substitute for security review.

## Career demonstration

Explains policy-as-code, test fixture design, input validation, safe evidence minimization and secure operational reporting in an IT support/SOC context.
