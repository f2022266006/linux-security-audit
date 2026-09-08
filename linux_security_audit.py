#!/usr/bin/env python3
"""Read-only Linux security auditing tool."""

from __future__ import annotations

import argparse
import json
import os
import platform
import pwd
import re
import shutil
import socket
import stat
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable


@dataclass
class Finding:
    check: str
    status: str
    title: str
    evidence: str
    recommendation: str
    deduction: int = 0


class CommandRunner:
    def run(self, command: list[str]) -> tuple[int, str]:
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=15, check=False)
            return result.returncode, (result.stdout + result.stderr).strip()
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return 127, str(exc)


def finding(check: str, ok: bool, title: str, evidence: str,
            recommendation: str, deduction: int = 5, critical: bool = False) -> Finding:
    return Finding(check, "PASS" if ok else ("CRITICAL" if critical else "WARNING"),
                   title, evidence, recommendation, 0 if ok else deduction)


def parse_ss_listeners(text: str) -> list[str]:
    ports = set()
    for line in text.splitlines():
        if not line.strip() or line.lower().startswith(("netid", "state")):
            continue
        match = re.search(r"(?:\[.*?\]|\S+):(\d+)\s", line + " ")
        if match:
            ports.add(match.group(1))
    return sorted(ports, key=int)


def parse_failed_logins(text: str) -> int:
    return sum(1 for line in text.splitlines()
               if re.search(r"failed password|authentication failure|invalid user", line, re.I))


def parse_sshd_config(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            values[parts[0].lower()] = parts[1].strip().lower()
    return values


def check_important_permissions(paths: Iterable[str]) -> Finding:
    expected = {"/etc/passwd": 0o644, "/etc/shadow": 0o640, "/etc/ssh/sshd_config": 0o600}
    problems, checked = [], 0
    for name in paths:
        if name not in expected or not os.path.exists(name):
            continue
        checked += 1
        mode = stat.S_IMODE(os.stat(name).st_mode)
        if mode & ~expected[name]:
            problems.append(f"{name}={mode:04o}")
    ok = not problems
    return finding("permissions", ok, "Sensitive file permissions",
                   ", ".join(problems) if problems else f"{checked} sensitive files checked",
                   "Restrict sensitive files to the least permissions required.", 8)


def find_files(roots: Iterable[str], predicate: Callable[[os.stat_result], bool], limit: int = 50) -> list[str]:
    results = []
    for root in roots:
        if not os.path.exists(root):
            continue
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in {"proc", "sys", "dev", "run", "snap"}]
            for name in files:
                path = os.path.join(current, name)
                try:
                    if predicate(os.lstat(path)):
                        results.append(path)
                        if len(results) >= limit:
                            return results
                except (OSError, PermissionError):
                    continue
    return results


def audit_live(scan_roots: list[str], runner: CommandRunner) -> list[Finding]:
    if platform.system() != "Linux":
        raise RuntimeError("Live mode requires Linux. Use --mode sample on Windows or macOS.")
    findings = [check_important_permissions(["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config"])]

    suid = find_files(scan_roots, lambda s: bool(s.st_mode & stat.S_ISUID))
    known = {"sudo", "su", "passwd", "mount", "umount", "chsh", "chfn", "newgrp"}
    unexpected = [p for p in suid if Path(p).name not in known]
    findings.append(finding("suid", not unexpected, "Unexpected SUID executables",
                            f"Found: {', '.join(unexpected[:10])}" if unexpected else f"{len(suid)} known/none found",
                            "Verify each SUID binary against the operating-system package database.", 10, True))

    rc, services = runner.run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend"])
    service_names = [line.split()[0] for line in services.splitlines() if line.strip() and ".service" in line]
    findings.append(finding("services", rc == 0, "Running services inventoried",
                            f"{len(service_names)} running: {', '.join(service_names[:8])}" if rc == 0 else services[:200],
                            "Review every enabled service and disable unnecessary ones.", 4))

    rc, listeners = runner.run(["ss", "-lntup"])
    ports = parse_ss_listeners(listeners) if rc == 0 else []
    findings.append(finding("ports", rc == 0 and len(ports) <= 15, "Listening ports",
                            f"Ports: {', '.join(ports) or 'none detected'}" if rc == 0 else listeners[:200],
                            "Confirm each listening port has a documented business purpose.", 8))

    failed_text = ""
    for command in (["journalctl", "--since", "24 hours ago", "-u", "ssh", "--no-pager"],
                    ["journalctl", "--since", "24 hours ago", "-u", "sshd", "--no-pager"]):
        rc, out = runner.run(list(command))
        if rc == 0:
            failed_text += "\n" + out
    failed = parse_failed_logins(failed_text)
    findings.append(finding("failed_logins", failed < 10, "Failed logins in last 24 hours",
                            f"{failed} matching records", "Investigate repeated failures and consider rate limiting.", 8))

    login_defs = Path("/etc/login.defs").read_text(errors="replace") if Path("/etc/login.defs").exists() else ""
    max_days = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", login_defs, re.M)
    min_len = re.search(r"^\s*PASS_MIN_LEN\s+(\d+)", login_defs, re.M)
    policy_ok = bool(max_days and int(max_days.group(1)) <= 365 and min_len and int(min_len.group(1)) >= 12)
    findings.append(finding("password_policy", policy_ok, "Password policy",
                            f"PASS_MAX_DAYS={max_days.group(1) if max_days else 'unset'}, PASS_MIN_LEN={min_len.group(1) if min_len else 'unset'}",
                            "Set an appropriate password lifetime and enforce length through PAM/pwquality.", 9))

    fw_ok, fw_evidence = False, "No supported firewall command found"
    for cmd in (["ufw", "status"], ["firewall-cmd", "--state"], ["nft", "list", "ruleset"]):
        if shutil.which(cmd[0]):
            rc, out = runner.run(list(cmd)); fw_evidence = out[:250]
            fw_ok = rc == 0 and bool(re.search(r"active|running|table", out, re.I)); break
    findings.append(finding("firewall", fw_ok, "Host firewall status", fw_evidence,
                            "Enable and configure a host firewall using an approved policy.", 10, True))

    admins = []
    for entry in pwd.getpwall():
        groups = {g.gr_name for g in __import__("grp").getgrall() if entry.pw_name in g.gr_mem}
        if entry.pw_uid == 0 or groups.intersection({"sudo", "wheel"}):
            admins.append(entry.pw_name)
    findings.append(finding("admins", len(admins) <= 3, "Administrative users",
                            f"Accounts: {', '.join(sorted(set(admins)))}", "Review administrative membership regularly.", 8))

    world = find_files(scan_roots, lambda s: bool(s.st_mode & stat.S_IWOTH))
    findings.append(finding("world_writable", not world, "World-writable files",
                            f"Found {len(world)}: {', '.join(world[:10])}" if world else "None found in selected roots",
                            "Remove world-write permission unless it is explicitly required.", 10, True))

    updates_ok, update_count, update_evidence = False, 0, "Unsupported package manager"
    if shutil.which("apt-get"):
        rc, out = runner.run(["apt-get", "-s", "upgrade"])
        update_count = len(re.findall(r"^Inst ", out, re.M)); updates_ok = rc == 0 and update_count == 0
        update_evidence = f"{update_count} package updates available"
    elif shutil.which("dnf"):
        rc, out = runner.run(["dnf", "check-update", "--security", "-q"])
        update_count = len([x for x in out.splitlines() if re.match(r"\S+\.\S+\s", x)])
        updates_ok = rc == 0; update_evidence = f"{update_count} security updates reported"
    findings.append(finding("updates", updates_ok, "Available security updates", update_evidence,
                            "Install tested security updates promptly.", 10))

    ssh_text = Path("/etc/ssh/sshd_config").read_text(errors="replace") if Path("/etc/ssh/sshd_config").exists() else ""
    ssh = parse_sshd_config(ssh_text)
    ssh_ok = ssh.get("permitrootlogin", "prohibit-password") in {"no", "prohibit-password"} and ssh.get("passwordauthentication", "yes") == "no"
    findings.append(finding("ssh", ssh_ok, "Basic SSH configuration",
                            f"PermitRootLogin={ssh.get('permitrootlogin', 'default')}, PasswordAuthentication={ssh.get('passwordauthentication', 'default')}",
                            "Disable direct root and password authentication after configuring tested SSH keys.", 10))
    return findings


def audit_sample(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    specs = [
        ("permissions", not data["permission_issues"], "Sensitive file permissions", str(data["permission_issues"]), 8),
        ("suid", not data["unexpected_suid"], "Unexpected SUID executables", str(data["unexpected_suid"]), 10),
        ("services", True, "Running services inventoried", ", ".join(data["running_services"]), 0),
        ("ports", len(data["listening_ports"]) <= 15, "Listening ports", str(data["listening_ports"]), 8),
        ("failed_logins", data["failed_logins"] < 10, "Failed logins", str(data["failed_logins"]), 8),
        ("password_policy", data["password_policy_ok"], "Password policy", data["password_policy_evidence"], 9),
        ("firewall", data["firewall_active"], "Host firewall status", str(data["firewall_active"]), 10),
        ("admins", len(data["admin_users"]) <= 3, "Administrative users", ", ".join(data["admin_users"]), 8),
        ("world_writable", not data["world_writable_files"], "World-writable files", str(data["world_writable_files"]), 10),
        ("updates", data["security_updates"] == 0, "Available security updates", str(data["security_updates"]), 10),
        ("ssh", data["ssh_secure"], "Basic SSH configuration", data["ssh_evidence"], 10),
    ]
    return [finding(k, ok, title, evidence, "Review the related hardening guidance in the report.", deduction, k in {"suid", "firewall", "world_writable"})
            for k, ok, title, evidence, deduction in specs]


def score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(item.deduction for item in findings))


def rating(value: int) -> str:
    return "Good" if value >= 85 else "Needs attention" if value >= 65 else "High risk"


def write_reports(findings: list[Finding], report_dir: Path, mode: str) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()
    value = score(findings)
    payload = {"generated_at": now, "hostname": socket.gethostname(), "mode": mode,
               "score": value, "rating": rating(value), "findings": [asdict(x) for x in findings]}
    json_path = report_dir / "security_audit.json"
    text_path = report_dir / "security_audit.txt"
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    lines = ["LINUX SECURITY AUDIT REPORT", f"Generated: {now}", f"Mode: {mode}",
             f"Score: {value}/100 ({rating(value)})", ""]
    for item in findings:
        lines += [f"[{item.status}] {item.title}", f"Evidence: {item.evidence}",
                  f"Recommendation: {item.recommendation}", f"Score deduction: {item.deduction}", ""]
    text_path.write_text("\n".join(lines), encoding="utf-8")
    return text_path, json_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Linux security audit tool")
    parser.add_argument("--mode", choices=("live", "sample"), default="sample")
    parser.add_argument("--sample", type=Path, default=Path("sample_data/sample_host.json"))
    parser.add_argument("--scan-root", action="append", default=[], help="Live-mode root; repeatable")
    parser.add_argument("--report-dir", type=Path, default=Path("reports"))
    args = parser.parse_args()
    try:
        roots = args.scan_root or ["/etc", "/usr/bin", "/usr/sbin", "/var/tmp"]
        findings = audit_sample(args.sample) if args.mode == "sample" else audit_live(roots, CommandRunner())
        text_path, json_path = write_reports(findings, args.report_dir, args.mode)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"[ERROR] {exc}")
        return 2
    value = score(findings)
    print(f"[RESULT] Security score: {value}/100 ({rating(value)})")
    print(f"[REPORT] {text_path}\n[REPORT] {json_path}")
    return 0 if value >= 65 else 1


if __name__ == "__main__":
    raise SystemExit(main())
