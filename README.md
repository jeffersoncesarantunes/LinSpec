# LinSpec

Lightweight kernel hardening audit tool for Linux forensic triage and security baseline verification.

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![Language-C99](https://img.shields.io/badge/Language-C99-A8B9CC?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/)
[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00FF41?style=flat-square)](#-roadmap)
[![Tested-on](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square&logo=arch-linux)](https://security.archlinux.org/)
[![Domain](https://img.shields.io/badge/Domain-Digital%20Forensics-8A2BE2?style=flat-square)](./docs/forensic_methodology.md)

---

## Etymology

**LinSpec** = **Linux** + **Inspection (Specification)**.

A forensic entry-point that checks whether kernel-level protections are enforced before deeper analysis.

---

## Overview

LinSpec audits the Linux kernel's security posture in real time. It reads from `/proc/sys` and `/sys/devices`, classifies parameters as **PASS / WARN / VULN**, and produces structured reports.

**29 security checks** across 7 categories:

| Category | Checks |
|----------|--------|
| Memory | ASLR, mmap_min_addr |
| Kernel | kptr_restrict, ptrace_scope, dmesg_restrict, userns_clone, kexec_disabled, perf_event_paranoid, unpriv_bpf, ftrace_enabled, core_uses_pid, sysrq |
| Network | bpf_jit_harden, tcp_syncookies, ip_forward, rp_filter, tcp_rfc1337, icmp_ignore_bogus, arp_ignore, arp_announce |
| Filesystem | protected_symlinks, protected_hardlinks, core_pattern |
| CPU | spectre_v2, meltdown, l1tf, mds |
| Crypto | entropy_avail |
| Exec | core_dump_safety |

---

## Features

- 29 kernel security checks with CVE mapping
- Automated remediation (`--apply`)
- Watch mode with configurable interval (`--watch`)
- Customizable profiles (JSON-based baselines)
- HTML / JSON / CSV report export
- Pure C99, zero dependencies
- Passive inspection (read-only by default)
- PIE + RELRO + FORTIFY hardened binary

---

## Quick Start

```bash
git clone https://github.com/jeffersoncesarantunes/LinSpec.git
cd LinSpec
make clean && make
sudo ./linspec --json --csv --html
```

---

## Usage

```
LinSpec v2.0.0 - Kernel Hardening Audit Tool
Usage: linspec [options]

Options:
  -j, --json            Export JSON report
  -c, --csv             Export CSV report
  -H, --html            Export HTML report
  -o, --output-dir DIR  Output directory (default: reports/)
  -p, --profile FILE    Load custom audit profile
  -a, --apply           Apply remediation for VULN/WARN checks
  -f, --force           Skip confirmation prompt for --apply
  -w, --watch SEC       Watch mode with interval in seconds
  -V, --version         Show version
  -h, --help            Show this help
```

### Examples

```bash
# Full audit with all reports
sudo ./linspec -j -c -H

# Custom output directory
sudo ./linspec -j -o /tmp/audit

# Use a custom profile
sudo ./linspec -j -p profiles/cis_benchmark.json

# Apply fixes automatically
sudo ./linspec -j -a -f

# Watch mode (check every 300 seconds)
sudo ./linspec -w 300 -j
```

---

## Remediation

The `--apply` flag writes hardened sysctl values for remediable checks:

- Backs up the current value before changing
- Verifies the write by reading back
- Confirms each change unless `--force` is used
- Requires root privileges

---

## Profiles

Profiles allow customizing the expected baseline. Format:

```json
{
  "name": "My Profile",
  "description": "Custom hardened baseline",
  "version": "1.0.0",
  "checks": {
    "aslr": { "expected": 2, "op": "eq" },
    "kptr_restrict": { "expected": 2, "op": "ge" }
  }
}
```

Built-in profiles:
- `profiles/default.json` — LinSpec default baseline
- `profiles/cis_benchmark.json` — CIS Benchmark aligned

---

## Reports

| Format | File | Content |
|--------|------|---------|
| JSON | `report.json` | Machine-readable with CVE mappings |
| CSV | `report.csv` | Tabular for analysis |
| HTML | `report.html` | Self-contained dark-themed report |

---

## The Forensic Ecosystem

LinSpec is Phase 1 (Audit) of a three-stage forensic workflow:

```
Phase 1: LinSpec (Audit)      --> report.json
Phase 2: S.I.R.E.N (Acquire)  --> memory dump + SHA256
Phase 3: K-Scanner (Analyze)  --> RWX detection + YARA
```

---

## Roadmap

- [x] High-performance C99 Core Engine
- [x] 29 Security Checks Across 7 Categories
- [x] Side-channel Vulnerability Detection (Spectre/Meltdown/L1TF/MDS)
- [x] Automated Remediation with Verification
- [x] Customizable Profile System
- [x] HTML / JSON / CSV Export
- [x] Watch Mode (Continuous Monitoring)
- [x] CVE Mapping Per Check
- [x] Ecosystem Integration (S.I.R.E.N / K-Scanner)
- [x] CI/CD (CodeQL + Gitleaks)
- [x] Docker Container Image
- [x] Test Suite (Shell-based)

---

## Build

```bash
make              # production build (stripped, hardened)
make debug        # debug build with symbols
make test         # run test suite
make lint         # static analysis (cppcheck + clang)
make docker       # build Docker image
make install      # install to /usr/local/bin
```

---

## Security

See [SECURITY.md](SECURITY.md) for the security policy and known limitations.

---

## Documentation

[![Docs-Architecture](https://img.shields.io/badge/Architecture-Design-00599C?style=flat-square&logo=linux&logoColor=white)](docs/architecture.md)
[![Docs-Audit](https://img.shields.io/badge/Audit-Reference-8A2BE2?style=flat-square)](docs/audit_reference.md)
[![Docs-Methodology](https://img.shields.io/badge/Forensic-Methodology-444444?style=flat-square&logo=gnu-bash&logoColor=white)](docs/forensic_methodology.md)
[![Docs-ThreatModel](https://img.shields.io/badge/Threat-Model-CC0000?style=flat-square&logo=opensourceinitiative&logoColor=white)](docs/threat_model.md)

---

## License

[![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=opensourceinitiative&logoColor=white)](LICENSE)

*This project is licensed under the MIT License.*
