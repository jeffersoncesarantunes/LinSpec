#  ● Audit Reference

## ● Overview

This document describes all kernel parameters audited by LinSpec.

---

## ● Memory Protection

### ASLR (kernel.randomize_va_space)

- **Path:** /proc/sys/kernel/randomize_va_space
- **Expected:** 2
- **Risk:**
  - Disabled → predictable memory layout
  - Enables exploitation (ROP, ret2libc)

---

## ● Kernel Hardening

### kptr_restrict

- **Path:** /proc/sys/kernel/kptr_restrict
- **Expected:** 2
- **Risk:**
  - Kernel address leakage
  - KASLR bypass

---

### dmesg_restrict

- **Path:** /proc/sys/kernel/dmesg_restrict
- **Expected:** 1
- **Risk:**
  - Information disclosure

---

## ● System Controls

### ptrace_scope

- **Path:** /proc/sys/kernel/yama/ptrace_scope
- **Expected:** 1 or higher
- **Risk:**
  - Process injection

---

## ● Network Stack

### tcp_syncookies

- **Path:** /proc/sys/net/ipv4/tcp_syncookies
- **Expected:** 1
- **Risk:**
  - SYN Flood vulnerability

---

### bpf_jit_harden

- **Path:** /proc/sys/net/core/bpf_jit_harden
- **Expected:** 2
- **Risk:**
  - JIT spray / kernel exploitation

---

## ● CPU Mitigations

### Spectre / Meltdown

- **Source:** /sys/devices/system/cpu/vulnerabilities/
- **Evaluation:**
  - Mitigated
  - Vulnerable
  - Not affected

---

## ● Status Logic

| Status | Meaning |
|--------|--------|
| PASS   | Secure configuration |
| WARN   | Potential risk |
| VULN   | Exploitable condition |
