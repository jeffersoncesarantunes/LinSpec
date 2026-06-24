# Audit Reference

## Overview

Technical reference for every kernel parameter and hardware security feature LinSpec checks.

---

## Memory Protection

### ASLR (kernel.randomize_va_space)
- **Path:** `/proc/sys/kernel/randomize_va_space`
- **Expected:** `2` (Full Randomization)
- **Risk:** Disabled (0) or Partial (1) makes ROP exploitation easier
- **CVE:** CVE-2014-4910

### mmap_min_addr (vm.mmap_min_addr)
- **Path:** `/proc/sys/vm/mmap_min_addr`
- **Expected:** `>= 65536`
- **Risk:** Low values allow mmap-based privilege escalation via NULL pointer dereference
- **CVE:** CVE-2012-0056

---

## Kernel Hardening

### kptr_restrict
- **Path:** `/proc/sys/kernel/kptr_restrict`
- **Expected:** `>= 1` (preferred: `2`)
- **Risk:** Kernel symbol addresses leaked via /proc/kallsyms, enabling KASLR bypass
- **CVE:** CVE-2015-1333

### dmesg_restrict
- **Path:** `/proc/sys/kernel/dmesg_restrict`
- **Expected:** `1`
- **Risk:** Unprivileged users can read kernel logs, leaking sensitive addresses
- **CVE:** CVE-2018-10124

### ptrace_scope (Yama)
- **Path:** `/proc/sys/kernel/yama/ptrace_scope`
- **Expected:** `>= 1`
- **Risk:** Process injection via ptrace across same-user processes
- **CVE:** CVE-2019-11477

### unprivileged_userns_clone
- **Path:** `/proc/sys/kernel/unprivileged_userns_clone`
- **Expected:** `0` (Disabled)
- **Risk:** Sandbox escape and privilege escalation via user namespaces
- **CVE:** CVE-2021-22555, CVE-2022-0185

### kexec_load_disabled
- **Path:** `/proc/sys/kernel/kexec_load_disabled`
- **Expected:** `1`
- **Risk:** Arbitrary kernel code loading via kexec
- **CVE:** CVE-2022-29582

### perf_event_paranoid
- **Path:** `/proc/sys/kernel/perf_event_paranoid`
- **Expected:** `>= 2` (CIS: `3`)
- **Risk:** Performance monitoring exposes sensitive CPU state to unprivileged users
- **CVE:** CVE-2023-2166

### unprivileged_bpf_disabled
- **Path:** `/proc/sys/kernel/unprivileged_bpf_disabled`
- **Expected:** `1`
- **Risk:** BPF JIT spraying and kernel exploits via unprivileged BPF
- **CVE:** CVE-2020-8835

### ftrace_enabled
- **Path:** `/proc/sys/kernel/ftrace_enabled`
- **Expected:** `0`
- **Risk:** Ftrace can be abused to trace kernel functions and leak information

### core_uses_pid
- **Path:** `/proc/sys/kernel/core_uses_pid`
- **Expected:** `1`
- **Risk:** Without PID naming, core dumps can overwrite each other

### sysrq
- **Path:** `/proc/sys/kernel/sysrq`
- **Expected:** `0` (or `4` for secure)
- **Risk:** Magic SysRq allows direct hardware manipulation from console

---

## Network Stack

### bpf_jit_harden (net.core.bpf_jit_harden)
- **Path:** `/proc/sys/net/core/bpf_jit_harden`
- **Expected:** `2`
- **Risk:** JIT spraying allows arbitrary code execution in kernel context

### tcp_syncookies (net.ipv4.tcp_syncookies)
- **Path:** `/proc/sys/net/ipv4/tcp_syncookies`
- **Expected:** `1`
- **Risk:** SYN flood DoS attacks exhaust connection resources

### ip_forward (net.ipv4.ip_forward)
- **Path:** `/proc/sys/net/ipv4/ip_forward`
- **Expected:** `0`
- **Risk:** Enables IP forwarding, useful for pivoting in network attacks

### Reverse Path Filter (rp_filter)
- **Path:** `/proc/sys/net/ipv4/conf/{all,default}/rp_filter`
- **Expected:** `1`
- **Risk:** IP spoofing without strict reverse path filtering

### tcp_rfc1337 (net.ipv4.tcp_rfc1337)
- **Path:** `/proc/sys/net/ipv4/tcp_rfc1337`
- **Expected:** `1`
- **Risk:** TIME-WAIT assassination attacks against TCP connections

### icmp_ignore_bogus_error_responses
- **Path:** `/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses`
- **Expected:** `1`
- **Risk:** Bogus ICMP errors can be used for network mapping

### ARP Settings
- **arp_ignore:** `/proc/sys/net/ipv4/conf/all/arp_ignore` — Expected: `>= 1`
- **arp_announce:** `/proc/sys/net/ipv4/conf/all/arp_announce` — Expected: `>= 2`
- **Risk:** ARP spoofing and network mapping

---

## CPU Mitigations

### Spectre V2
- **Path:** `/sys/devices/system/cpu/vulnerabilities/spectre_v2`
- **Expected:** "Mitigation" or "Not affected"
- **CVE:** CVE-2017-5715, CVE-2017-5753

### Meltdown
- **Path:** `/sys/devices/system/cpu/vulnerabilities/meltdown`
- **Expected:** "Mitigation" or "Not affected"
- **CVE:** CVE-2017-5754

### L1TF (L1 Terminal Fault)
- **Path:** `/sys/devices/system/cpu/vulnerabilities/l1tf`
- **Expected:** "Mitigation" or "Not affected"
- **CVE:** CVE-2018-3620, CVE-2018-3646

### MDS (Microarchitectural Data Sampling)
- **Path:** `/sys/devices/system/cpu/vulnerabilities/mds`
- **Expected:** "Mitigation" or "Not affected"
- **CVE:** CVE-2018-12126, CVE-2018-12130, CVE-2018-12127, CVE-2019-11091

---

## Filesystem

### protected_symlinks
- **Path:** `/proc/sys/fs/protected_symlinks`
- **Expected:** `1`
- **Risk:** Symlink race conditions enabling privilege escalation
- **CVE:** CVE-2018-1000001

### protected_hardlinks
- **Path:** `/proc/sys/fs/protected_hardlinks`
- **Expected:** `1`
- **Risk:** Hardlink race conditions

---

## Crypto

### entropy_avail (kernel.random.entropy_avail)
- **Path:** `/proc/sys/kernel/random/entropy_avail`
- **Expected:** `> 200`
- **Risk:** Low entropy degrades cryptographic randomness quality

---

## Status Logic

| Status | Meaning |
|--------|---------|
| **PASS** | Secure configuration, aligned with baseline |
| **WARN** | Deviates from strict hardening, may be needed for compat |
| **VULN** | Critical gap, exploitable condition, high priority |
| **SKIP** | Check unavailable (kernel config or container restriction) |
