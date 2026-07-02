# Architecture

## Overview

LinSpec is a modular C99-based kernel hardening audit tool. It is the triage layer in the SYNTROPY forensic ecosystem — lightweight, dependency-free, and focused on deterministic security baseline verification.

---

## Components

### main.c

Entry point. Parses CLI flags with getopt-style string comparison. Supports json/csv/html export, remediation, profile loading, and watch mode. Dispatches to the appropriate subsystem based on flags.

### system_audit.c

Core audit engine. Contains:
- **Check definition table**: 29 checks across 7 categories, each with path, expected value, comparison operator, CVE mappings, and remediability
- **Generic sysctl checker**: Reads int values from /proc/sys, applies operator comparison
- **Custom check functions**: For entropy, CPU vulnerabilities (spectre_v2, meltdown, l1tf, mds), and core_pattern analysis
- **Remediation engine**: Writes hardened sysctl values with backup and verification
- **Profile parser**: Minimal JSON parser for custom baselines
- **Export generators**: JSON, CSV, and self-contained HTML report generators
- **Watch loop**: Continuous monitoring with configurable interval

### checks.h

Type definitions: result_t, category_t, op_t, check_def_t, check_result_t, profile_t. Function declarations for all public APIs.

---

## Data Flow

```
CLI (main.c)
  |
  v
run_all_checks()
  |
  +---> For each check in table:
  |       |---> Generic int reader (most checks)
  |       |---> Custom function pointer (CPU vulns, entropy)
  |       |---> Profile override (if --profile specified)
  |
  v
print_results() / export_*()
  |
  +---> Terminal UI (ANSI colored)
  +---> JSON report (report.json)
  +---> CSV report (report.csv)
  +---> HTML report (report.html)
  |
  v
apply_remediation()  [if --apply]
  |
  +---> Backup current value
  +---> Write sysctl
  +---> Verify by readback
```

---

## Data Sources

- `/proc/sys` — kernel runtime parameters (sysctl interface)
- `/sys/devices/system/cpu/vulnerabilities` — hardware mitigation status

---

## Design Principles

- **Zero dependencies**: Pure C99 with standard libc only
- **Forensic safety**: Read-only by default; writes only with explicit --apply
- **Deterministic evaluation**: Fixed baseline comparison, reproducible results
- **Operational integrity**: Stateless execution leaves no kernel configuration footprint

---

## The Audit Contract

The main architectural output is `report.json`. It contains:
- Tool name and version
- Timestamp
- Per-check results with current/expected values
- CVE references for failed checks
- Remediation metadata
- Summary statistics

This contract feeds S.I.R.E.N (acquisition) and K-Scanner (analysis) in the SYNTROPY ecosystem.
