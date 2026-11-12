# Offline Firewall Rule Audit

A small **defensive inventory review** utility for IT support and junior SOC portfolio demonstrations. It reviews **exported CSV rules only**: it does not read local firewall settings, connect to hosts, scan networks, or claim to verify actual internet exposure.

## Run

Python 3.10+ standard library only:

```bash
python portfolio/firewall_rule_audit.py portfolio/examples/synthetic_firewall_rules.csv
python portfolio/firewall_rule_audit.py portfolio/examples/synthetic_firewall_rules.csv --output report.json
```

For tests, install `pytest` in a local test environment and run:

```bash
python -m pytest -q portfolio/tests/test_firewall_rule_audit.py
```

## CSV contract

Exact header: `rule_id,enabled,action,direction,protocol,source,destination,port`.

- `enabled`: true/false, yes/no, or 1/0
- `action`: allow/deny; `direction`: inbound/outbound
- `protocol`: tcp/udp/icmp/any
- `source`, `destination`: `any` or IPv4/IPv6 CIDR/address
- `port`: `any`, 1–65535, or an inclusive range for TCP/UDP; `any` for ICMP/any protocol

Maximum input 2 MB, 10,000 rules. The parser rejects malformed rows, duplicate IDs, symlink inputs, invalid networks and ports. All sample addresses are documentation-only.

## Findings and decisions

| Heuristic | Severity | Rationale |
| --- | --- | --- |
| Enabled inbound allow from `any` to `any` for protocol `any` | High | Broad unrestricted rule warrants review |
| Enabled inbound TCP allow from `any` for `any`, 22, 3389 or 445 | Medium | Remote administration or SMB exposure may be unintended |

Disabled, deny, outbound, and other rules are still counted but do not trigger these two heuristics. Results contain rule IDs and review reasons, not copied customer network details. Rules may be safe due to upstream controls, network isolation, address translation, or compensating safeguards. A finding **is not a vulnerability confirmation**. This version does not calculate rule ordering, port-range containment, firewall precedence, or NAT reachability; those require vendor-specific models.

## Interview demonstration

Run the synthetic CSV, explain why the two sample rules merit review, then show how modifying a rule to disable it or narrow its source changes the report. Discuss why an analyst must verify the firewall's real effective policy before recommending a change. No real infrastructure is required.
