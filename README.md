# Linux Security Audit Tool

A read-only Python tool that checks common Linux security settings and creates an explainable security score plus text and JSON reports.

## Features

- Sensitive file permissions
- Unexpected SUID executables
- Running-service inventory
- Open listening ports
- Failed-login records
- Password-policy configuration
- Host firewall status
- Administrative users
- World-writable files
- Available package updates
- Basic SSH hardening
- Final 0–100 score and remediation report

> The score is a learning and prioritization aid, not proof that a system is secure or compliant.

## Requirements

- Python 3.9+
- Linux for live audits (Ubuntu/Debian recommended)
- No third-party Python packages

## Quick start on any operating system

Run the safe bundled sample:

```bash
python linux_security_audit.py --mode sample
```

Generated files appear in `reports/`. Sample mode intentionally contains several problems so you can study the findings.

## Audit your own Linux machine

```bash
python3 linux_security_audit.py --mode live
```

The tool uses read-only commands and does not request elevated privileges. Some evidence may be unavailable without additional access. For a focused lab scan:

```bash
python3 linux_security_audit.py --mode live --scan-root /etc --scan-root /usr/bin
```

Only audit systems that you own or have explicit permission to assess.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Score interpretation

| Score | Rating | Meaning |
|---:|---|---|
| 85–100 | Good | No major issues found by these limited checks |
| 65–84 | Needs attention | Review and prioritize warnings |
| 0–64 | High risk | Critical or multiple important findings |

Each deduction is printed in the report. A pass never adds bonus points, and the score never drops below zero.

## Repository structure

```text
linux-security-audit/
├── linux_security_audit.py
├── sample_data/sample_host.json
├── tests/test_audit.py
├── docs/
│   ├── ARCHITECTURE.md
│   └── PROJECT_PROPOSAL.md
├── reports/.gitkeep
├── README.md
├── SECURITY.md
├── LICENSE
└── .gitignore
```

## Limitations

- Designed primarily for Ubuntu/Debian; some checks also recognize Fedora-style tools.
- SUID allowlisting and port-count thresholds are simple demonstrations.
- Effective PAM, included SSH configuration, containers, SELinux/AppArmor, and distribution-specific controls need deeper inspection.
- A clean report does not guarantee absence of compromise or vulnerabilities.

## Future improvements

- CIS Benchmark profiles with explicit control references
- AppArmor/SELinux and auditd checks
- Package-signature and kernel-hardening review
- HTML report and historical score comparison
- Distribution adapters and integration tests in containers

## Learning outcomes

This project demonstrates Linux administration, operating-system security, permissions and users, processes and services, security hardening, Python automation, testing, and responsible defensive reporting.
