# Audit Reference

## Overview

This document is a technical reference for every kernel parameter and hardware security feature LinSpec checks. Use it to interpret forensic results and understand what each security mechanism actually does.

---

## Memory Protection

### ASLR (kernel.randomize_va_space)

- **Path:** `/proc/sys/kernel/randomize_va_space`
- **Expected Value:** `2` (Full Randomization)
- **Forensic Evidence:** When enabled, the stack, vDSO page, and shared memory regions all get randomized.
- **Risk:**
  - **Disabled (0) or Partial (1):** Predictable memory layout.
  - **Impact:** Makes ROP and ret2libc exploitation significantly easier.

---

## Kernel Hardening

### kptr_restrict

- **Path:** `/proc/sys/kernel/kptr_restrict`
- **Expected Value:** `2`
- **Forensic Evidence:** With this set, `/proc/kallsyms` shows kernel addresses as zeros (`0000000000000000`) for unprivileged users.
- **Risk:**
  - **Leakage:** Kernel symbol addresses get exposed.
  - **Impact:** Direct KASLR bypass — the attacker knows exactly where things live in memory.

### dmesg_restrict

- **Path:** `/proc/sys/kernel/dmesg_restrict`
- **Expected Value:** `1`
- **Risk:**
  - **Information Disclosure:** Unprivileged users can read kernel logs, which may leak sensitive system info.

---

## System Controls

### ptrace_scope (Yama)

- **Path:** `/proc/sys/kernel/yama/ptrace_scope`
- **Expected Value:** `1` (Restricted Ptrace) or higher.
- **Risk:**
  - **Process Injection:** A malicious process can attach to and inject code into other running processes owned by the same user.

### unprivileged_userns_clone

- **Path:** `/proc/sys/kernel/unprivileged_userns_clone`
- **Expected Value:** `0` (Disabled)
- **Risk:**
  - **Sandbox Escape:** Unprivileged users can create new namespaces, a common vector for privilege escalation.

---

## Network Stack

### tcp_syncookies

- **Path:** `/proc/sys/net/ipv4/tcp_syncookies`
- **Expected Value:** `1`
- **Risk:**
  - **Denial of Service:** Without SYN cookies, the system is vulnerable to SYN flood attacks that can exhaust resources and take down network services.

### bpf_jit_harden

- **Path:** `/proc/sys/net/core/bpf_jit_harden`
- **Expected Value:** `2`
- **Risk:**
  - **JIT Spraying:** Attackers can exploit the BPF JIT compiler to execute arbitrary code in the kernel.

---

## CPU Mitigations

### Hardware Vulnerabilities (Spectre, Meltdown, L1TF, etc.)

- **Source:** `/sys/devices/system/cpu/vulnerabilities/`
- **Forensic States:**
  - **Mitigated:** The kernel has active software or hardware defenses in place.
  - **Vulnerable:** The system is susceptible to side-channel attacks.
  - **Not affected:** The CPU hardware itself isn't vulnerable to this specific issue.

---

## Status Logic Summary

LinSpec compares each value against a hardened baseline and reports one of three states:

| Status | Meaning | Forensic Significance |
| :--- | :--- | :--- |
| **PASS** | Secure configuration | Aligned with the hardened baseline |
| **WARN** | Potential risk | Deviates from strict hardening but may be needed for compatibility |
| **VULN** | Exploitable condition | Critical gap -- high priority for remediation |
