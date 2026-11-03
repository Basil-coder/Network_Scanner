You are maintaining Basil-coder/Network_Scanner in an automated GitHub Actions run.

Implement exactly ONE meaningful, safe defensive cybersecurity improvement. Inspect the repository first and choose a narrowly scoped change that is appropriate for its current state. Prioritize, in order:

1. accurate network inventory and safe parsing,
2. defensive analysis,
3. input validation,
4. useful and privacy-conscious reporting,
5. test coverage for those areas.

Hard requirements:

- Make a real implementation change and add or update focused offline tests for it.
- Keep the patch small, reviewable, and backward-compatible where practical.
- Use only the Python standard library and dependencies already installed in the runner (pytest, pytest-socket, and scapy). Do not add a new dependency.
- Do not run the scanner or make any network request. Do not probe hosts, send packets, resolve names, download content, call remote APIs, or access private data.
- Do not add exploitation, credential attack, persistence, evasion, payload, vulnerability-scanning, or other offensive capabilities.
- Do not invent findings, devices, scan results, test results, contributors, or changelog claims.
- Do not expose credentials or sensitive data. Keep test fixtures synthetic and use documentation-only IP ranges where addresses are needed.
- Do not modify anything under .github/, this automation's policy, or its validators.
- Do not commit, push, open a pull request, or alter git configuration. The workflow handles those actions after validation.
- Do not merely reformat, rename, or update documentation. The run must contain one substantive defensive improvement plus its directly related tests and minimal documentation if useful.

Before finishing, run only local/offline checks that cannot initiate network activity. In your final message, state the single improvement made, the tests added or changed, and any limitation a human reviewer should examine. If a safe meaningful improvement is not possible, make no changes and explain why; the workflow will fail closed and create no pull request.

## Future video-inspired backlog (review issue #7)

The owner has queued four larger demonstrations in this order **after** the current safe network inventory / Python defensive improvements. Track their scope and readiness in https://github.com/Basil-coder/Network_Scanner/issues/7:

1. Threat-model case study: accurate Mermaid architecture and data-flow diagrams, trust boundaries, STRIDE threats, selected MITRE ATT&CK references, and mitigations, backed by testable validation or code where possible.
2. Vulnerability identification + verified remediation in a **deliberately vulnerable local, synthetic lab app** with tests proving the fix. Never assess unapproved targets.
3. Small DevSecOps CI/CD demo with safe simulated failing security gate (prefer separate repo/workflow, PHP only if proper runtime and review are provisioned).
4. A secure end-to-end sample app with authentication and access control, documented SDLC security and Mermaid diagrams (separate repo, incremental human-reviewed milestones).

**Do not override any hard requirements above.** This existing repository-specific automation may select only one small, substantive, permitted Python improvement in its current environment. For tracks 3–4 and anything requiring a new dependency, network access, separate repository, deployment, or modifications to workflow policy, do not attempt it automatically: leave a specific scope/implementation recommendation for a human-approved follow-up rather than modifying or weakening guardrails. Do not claim that the future backlog is implemented or that this workflow is live until the workflow PR has been merged into the default branch.
