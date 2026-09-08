# Project Proposal: Linux Security Audit Tool

## Problem statement

Linux systems expose many security-relevant settings across files, users, services, ports, logs, firewalls, packages, and SSH. Manual review is slow and inconsistent for beginners. This project provides one transparent, read-only audit that gathers evidence and turns it into an understandable report.

## Objectives

1. Inspect eleven common Linux security areas without changing the host.
2. Clearly separate passes, warnings, and critical findings.
3. Produce repeatable text and JSON reports with UTC timestamps.
4. Calculate an explainable 0–100 learning score based on documented deductions.
5. Support synthetic sample analysis on non-Linux development computers.
6. Validate parsing, scoring, and reporting with automated tests.

## Scope

The first version targets Ubuntu/Debian-style Linux and performs a lightweight configuration review. It is not a vulnerability scanner, compliance certification, malware detector, or replacement for professional tools. Results require human verification.

## Expected result

A beginner-friendly command-line tool that inventories the host, highlights risky settings, recommends hardening actions, and preserves evidence in two report formats.

## Timeline

| Week | Work |
|---|---|
| 1 | Requirements, Linux security concepts, sample evidence |
| 2 | Checks, parsers, scoring, reporting |
| 3 | Tests, error handling, Linux VM evaluation |
| 4 | Documentation, screenshots, GitHub release |
