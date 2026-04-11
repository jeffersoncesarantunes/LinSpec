# Threat Model

## ● Objective

Define the attacker capabilities that LinSpec helps to evaluate.

---

## ● Assumed Attacker Capabilities

- Local user access (unprivileged)
- Ability to execute code
- Knowledge of kernel exploitation techniques

---

## ● Attack Vectors

### Kernel Info Leak

- Weak `kptr_restrict`
- dmesg exposure

### Code Injection

- Weak ptrace restrictions
- User namespace abuse

### Network Attacks

- SYN flood (DoS)
- BPF JIT exploitation

### Microarchitectural Attacks

- Spectre
- Meltdown

---

## ● Defensive Mapping

| Attack Type       | LinSpec Check             |
|-------------------|---------------------------|
| Info Leak         | kptr_restrict             |
| Injection         | ptrace_scope              |
| DoS               | tcp_syncookies            |
| Kernel Exploit    | bpf_jit_harden            |
| Side-channel      | CPU mitigations           |

---

## ● Key Insight

LinSpec evaluates **attack feasibility**, not just configuration.

It provides an estimation of how difficult it would be for an attacker to successfully exploit the system.
