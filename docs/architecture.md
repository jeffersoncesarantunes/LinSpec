#  ● Architecture

## ● Overview

LinSpec is a modular C-based auditing tool.

---

## ● Components

### main.c
- Entry point
- Orchestrates audit flow

### memory_audit.c
- Memory protection checks

### system_audit.c
- Kernel/system parameters

---

## ● Data Sources

- /proc/sys → runtime kernel parameters
- /sys → hardware + CPU info

---

## ● Execution Flow

1. Initialize audit engine
2. Collect kernel parameters
3. Evaluate against baseline
4. Print structured report

---

## ● Design Principles

- Minimal dependencies
- Deterministic output
- Read-only interaction
- Forensic safety

---

## ● Future Extensions

- JSON output module
- API integration (S.I.R.E.N)
- Automated hardening scripts
