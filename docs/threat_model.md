# Threat Model

## Objective

Map attacker capabilities and attack vectors to LinSpec's defensive checks. Shows how resilient a system is against local and remote threats.

---

## Assumed Attacker Capabilities

- **Local Access:** Unprivileged shell access
- **Code Execution:** Can compile and run arbitrary binaries
- **Exploitation Knowledge:** Familiar with modern kernel exploitation techniques

---

## Evaluated Attack Vectors

### 1. Information Disclosure (Reconnaissance)
- **Vector:** Kernel symbol addresses via /proc/kallsyms, dmesg, perf events
- **Goal:** Bypass KASLR by determining kernel base address
- **LinSpec Defense:** kptr_restrict, dmesg_restrict, perf_event_paranoid

### 2. Privilege Escalation
- **Vector:** Ptrace injection, user namespaces, BPF exploitation
- **Goal:** Root access
- **LinSpec Defense:** ptrace_scope, userns_clone, unpriv_bpf, ftrace_enabled

### 3. Kernel Space Exploitation
- **Vector:** JIT spraying via BPF, kexec module loading, mmap low address
- **Goal:** Ring 0 code execution
- **LinSpec Defense:** bpf_jit_harden, kexec_disabled, mmap_min_addr

### 4. Side-Channel Attacks
- **Vector:** CPU pipeline flaws (Spectre, Meltdown, L1TF, MDS)
- **Goal:** Cross-boundary data leakage (keys, passwords)
- **LinSpec Defense:** CPU vulnerability interface checks

### 5. Network-Based Attacks
- **Vector:** SYN flood, IP spoofing, ARP poisoning, TCP injection
- **Goal:** DoS, man-in-the-middle, network reconnaissance
- **LinSpec Defense:** tcp_syncookies, rp_filter, arp_ignore/announce, tcp_rfc1337

### 6. Arbitrary Code Execution via Core Dumps
- **Vector:** Core dump piped to attacker-controlled handler
- **Goal:** Privilege escalation via crafted core dump
- **LinSpec Defense:** core_pattern analysis

---

## Defensive Mapping Matrix

| Attack Type | Criticality | Checks | Mitigation |
|-------------|-------------|--------|------------|
| Info Leak | Medium | kptr_restrict, dmesg_restrict, perf_event_paranoid | KASLR preservation |
| Code Injection | High | ptrace_scope, userns_clone, unpriv_bpf | Prevent process hijacking |
| DoS | Low | tcp_syncookies, icmp_ignore_bogus | Resource availability |
| Kernel Exploit | Critical | bpf_jit_harden, kexec_disabled, mmap_min_addr | Kernel runtime integrity |
| Side-channel | High | CPU vulnerability checks | Hardware-level isolation |
| Network Pivot | Medium | ip_forward, rp_filter, arp_* | Network segmentation |

---

## Key Insight

LinSpec evaluates attack feasibility. Multiple VULN ratings indicate significantly lower attack cost. In a forensic context, these findings reveal the probable attack path.
