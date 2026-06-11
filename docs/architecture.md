# Architecture

## Overview

LinSpec is a modular C-based auditing tool built for real-time kernel hardening checks and forensic triage. It's the intelligence layer in the forensic ecosystem — lightweight, focused, and dependency-free.

---

## Components

### main.c

The entry point. It handles command-line arguments, sets things up, then orchestrates the audit modules and report generation.

### memory_audit.c

Handles integrity checks for ASLR, NX stack, and KASLR state. Also inspects kernel pointer visibility through `kptr_restrict`.

### system_audit.c

Audits sysctl parameters, sandboxing flags, and kexec status. On the hardware side, it checks CPU-level defenses against Spectre and Meltdown.

### checks.h

Contains the security thresholds and evaluation logic. This is where PASS, WARN, and VULN boundaries are defined.

---

## Data Sources

LinSpec uses a passive inspection model — it only reads, never writes. It pulls data from:

- `/proc/sys` — kernel runtime configuration and security parameters
- `/sys/devices/system/cpu/vulnerabilities` — hardware mitigation status
- `/proc/kallsyms` — address space layout for ASLR/KASLR validation

---

## Execution Flow

1. **Initialization** — set up the environment and baseline parameters
2. **Data Collection** — read kernel and hardware interfaces sequentially
3. **Logic Evaluation** — compare live state against the defined security standard
4. **Report Generation** — output to the terminal UI and export the Audit Contract (JSON/CSV)

---

## The Audit Contract (Integration Layer)

The main architectural output is `report.json`. It acts as a contract between tools in the ecosystem:

- **S.I.R.E.N Integration:** The acquisition engine parses the JSON to detect Kernel Lockdown or restricted pointers, then picks the right extraction method (``/dev/mem`` vs ``/proc/kcore``).
- **K-Scanner Integration:** The analysis layer gets ASLR/KASLR state from the report, which helps calculate accurate memory offsets during pattern matching.

---

## Design Principles

- **Zero Dependencies:** Pure C99 with standard libc only
- **Forensic Safety:** Strictly read-only — no system state gets modified
- **Operational Integrity:** Stateless execution means the audit leaves no footprint on kernel configuration

---

*LinSpec provides the foundational intelligence for automated forensic pipelines.*
