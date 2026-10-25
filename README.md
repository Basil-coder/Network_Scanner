# Network Scanner

A small Python CLI that discovers devices on an IPv4 subnet with ARP requests.
The target is selected explicitly in CIDR notation, and subnets larger than
`/16` are rejected to guard against accidental broad scans.

Only scan networks you own or have permission to test.

## Requirements

- Python 3.10 or newer
- Scapy 2.x (only needed for a real scan)
- Administrator/root privileges for raw network access during a real scan

Install the runtime dependency:

```bash
python -m pip install -r requirements.txt
```

## Usage

Start with a dry run. It validates and normalizes the subnet, reports the
number of target addresses, and exits without importing Scapy or sending any
packets:

```bash
python network_scanner.py --subnet 192.168.1.0/24 --dry-run
```

Example output:

```text
Dry run: would scan 192.168.1.0/24 (256 addresses); no packets sent.
```

After confirming the target and your authorization, run the scan with:

```bash
sudo python network_scanner.py --subnet 192.168.1.0/24
```

Use `python network_scanner.py --help` to see all options. IPv4 CIDR input is
required; malformed input, IPv6 networks, missing prefixes, and targets larger
than `/16` are rejected before any scan starts.

## Tests

The automated tests use dependency injection and mocked Scapy objects. They do
not open sockets or send network packets, and Scapy is not required to run
them:

```bash
python -m unittest discover -s tests -v
```

![Network scanner example](https://user-images.githubusercontent.com/52016269/220776670-2a8e3575-c2b9-4113-8716-3e59588f41de.png)

## Automated defensive development

The [Automated defensive improvement](.github/workflows/automated-defensive-improvement.yml) workflow uses GitHub Actions and the official `openai/codex-action` to propose one small defensive cybersecurity improvement at a time.

Its first scheduled opportunity is **27 October 2026 at approximately 15:15 South African Standard Time** (13:15 UTC). GitHub cron runs once a day at that time, while a tested date guard permits work only on every second calendar day from that anchor. The daily trigger plus calendar-day guard preserves the 48-hour cadence across month boundaries. GitHub may delay scheduled jobs during busy periods.

On each eligible run, the workflow:

1. exits before calling the API if another `codex/defensive-improvement-*` pull request is open;
2. gives Codex workspace-only filesystem access and no direct network access;
3. asks for exactly one narrow improvement, prioritizing inventory, defensive analysis, input validation, privacy-conscious reporting, and tests;
4. rejects changes to trusted `.github` automation, patches without both implementation and tests, binary/link changes, suspicious credential patterns, and oversized patches;
5. runs compilation and pytest inside an isolated network namespace with socket access disabled; and
6. pushes and opens a pull request only after all checks pass.

The workflow never auto-merges. A maintainer must review every proposal. It also prohibits live scans, private-data uploads, offensive functionality, fabricated results or contributors, and credentials in code. The API key is passed only from the `OPENAI_API_KEY` Actions secret to the official action and is never stored in this repository.

### Required GitHub setup

In this repository on GitHub:

1. Open **Settings → Secrets and variables → Actions → New repository secret**. Create `OPENAI_API_KEY` with an OpenAI API key that has an appropriate project budget and rotation policy.
2. Open **Settings → Actions → General → Workflow permissions**. Select **Read and write permissions**, enable **Allow GitHub Actions to create and approve pull requests**, and save. The workflow still narrows each job to only the permissions it needs and never approves a PR.
3. If Actions are restricted under **Settings → Actions → General → Actions permissions**, allow GitHub-authored actions plus `openai/codex-action`. The workflow pins every action to a reviewed commit SHA.
4. Keep branch protection/rulesets on `main` configured to require a pull request and any desired human approvals. Do not configure a separate bot or ruleset to auto-merge these PRs. Disabling **Settings → General → Pull Requests → Allow auto-merge** provides a repository-wide additional safeguard if auto-merge is not otherwise needed.

Organization policy can override repository settings. Public repositories may have scheduled workflows disabled by GitHub after prolonged repository inactivity; GitHub displays a notice when this happens.

### Manual testing

Open **Actions → Automated defensive improvement → Run workflow** on the `main` branch.

- Leave **Run Codex and create a PR** unchecked for a free guard-only smoke test. The `gate` job should succeed, explain that Codex/PR creation was skipped, and consume no OpenAI API tokens.
- Check it for a full end-to-end test. This intentionally overrides only the date guard. It still stops if an earlier automation PR is open, enforces all safety validation, runs tests offline, and leaves an unmerged PR for review.
- To test the duplicate-PR guard, leave that generated PR open and request another full manual run. The second run should stop successfully in the `gate` job and link the existing PR.

A failed full run creates no pull request. Open the failed workflow run and inspect the first red step; the job summary links the run and explains common guard failures. Missing secrets are reported explicitly without printing their values.

### AI assistance, limitations, and cost

Every automation PR is explicitly identified as AI-assisted. Codex can make mistakes, miss security issues, or propose a change that passes tests but is unsuitable in context. Network isolation and deterministic checks reduce risk but do not replace human code review, authorization checks, branch protection, or broader security testing. This workflow is defensive maintenance, not a vulnerability scanner or a substitute for professional assessment.

Full runs call the OpenAI API and incur usage charges for the configured API project. They also consume GitHub Actions minutes according to the repository's plan; guard-only runs use a small amount of Actions time but no OpenAI tokens. Review current OpenAI API pricing and GitHub Actions billing, set project budgets/alerts, and rotate or revoke the secret when the automation is no longer used.
