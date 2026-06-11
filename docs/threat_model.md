# Threat Model

## Objective

This document lays out the attacker capabilities and attack vectors that LinSpec evaluates. By mapping defensive configurations to known exploitation techniques, LinSpec shows you how resilient a system actually is against both local and remote threats.

---

## Assumed Attacker Capabilities

- **Local Access:** Unprivileged shell access on the box.
- **Code Execution:** Can compile and run arbitrary binaries or scripts (Python, C, etc.).
- **Exploitation Knowledge:** Familiar with modern kernel exploitation — ROP chains, heap spraying, side-channel analysis.

---

## Evaluated Attack Vectors

### 1. Information Disclosure (Reconnaissance)

- **Vector:** Kernel symbol addresses leak through `/proc/kallsyms` or sensitive data in `dmesg`.
- **Attacker Goal:** Bypass KASLR by figuring out the kernel's base address in memory.
- **LinSpec Defense:** Audits `kptr_restrict` and `dmesg_restrict`.

### 2. Privilege Escalation and Persistence

- **Vector:** Abuse ptrace to inject code into high-privilege processes, or use unprivileged user namespaces to break out of containers and sandboxes.
- **Attacker Goal:** Root access or a persistent backdoor.
- **LinSpec Defense:** Audits `ptrace_scope` and `unprivileged_userns_clone`.

### 3. Kernel Space Exploitation

- **Vector:** Exploit the BPF JIT compiler through JIT spraying, or load malicious modules via `kexec`.
- **Attacker Goal:** Execute arbitrary code in Ring 0 — the kernel context.
- **LinSpec Defense:** Audits `bpf_jit_harden` and `kexec_load_disabled`.

### 4. Side-Channel and Microarchitectural Attacks

- **Vector:** Exploit hardware flaws in the CPU pipeline (Spectre, Meltdown).
- **Attacker Goal:** Read sensitive data across security boundaries — passwords, keys, etc.
- **LinSpec Defense:** Audits CPU vulnerability mitigation status.

---

## Defensive Mapping Matrix

| Attack Type | Criticality | LinSpec Audit Focus | Mitigation Goal |
| :--- | :--- | :--- | :--- |
| **Info Leak** | Medium | `kptr_restrict`, `dmesg_restrict` | Entropy preservation (KASLR) |
| **Code Injection** | High | `ptrace_scope`, `nx_stack` | Prevent process hijacking |
| **Denial of Service** | Low | `tcp_syncookies` | Resource availability during SYN floods |
| **Kernel Exploit** | Critical | `bpf_jit_harden`, `kexec_disabled` | Kernel runtime integrity |
| **Side-channel** | High | CPU vulnerability interfaces | Hardware-level isolation |

---

## Key Insight

LinSpec evaluates attack feasibility.

A system with multiple VULN ratings isn't necessarily compromised. What it means is that the cost of attack is significantly lower. In a forensic context, these findings hint at which paths an intruder probably took to gain control.
