# LinSpec Forensic Methodology

## Purpose

LinSpec fills the role of the Initial Triage Layer (Phase 0) in a digital forensic investigation.

Before capturing volatile memory, you need to know whether the environment is safe to work with. LinSpec checks whether the kernel's defensive posture has been compromised and hands off the technical intelligence needed for safe memory acquisition.

---

## Forensic Philosophy

- **Non-Intrusive Analysis:** User-space operation with read-only access to /proc and /sys. No forensic footprints, no risk of altering evidence.
- **Deterministic Evaluation:** Fixed security baseline means results are reproducible and verifiable.
- **Ecosystem Symbiosis:** Machine-readable contracts (report.json) drive automated acquisition tool behavior.

---

## Investigation Flow

### 1. Baseline Validation
Detect critical deviations from hardened kernel configs. ASLR disabled? Kernel pointers leaking? CPU mitigations missing?

### 2. Exposure Mapping
Map the attack surface — unprivileged user namespaces, missing CPU mitigations, permissive sysctl settings that enable privilege escalation.

### 3. Intelligence for Acquisition (S.I.R.E.N Integration)
Reports dictate the acquisition strategy:
- Lockdown detection → S.I.R.E.N switches to /proc/kcore
- Pointer state baseline → detect if memory reads are being spoofed

---

## Integration with the Forensic Ecosystem

```
Phase 1: LinSpec (Audit)      --> report.json
Phase 2: S.I.R.E.N (Acquire)  --> memory dump + SHA256
Phase 3: K-Scanner (Analyze)  --> RWX detection + YARA
```

---

## Forensic Value Matrix

| Phase | Tool | Output |
|-------|------|--------|
| Triage (Phase 0) | LinSpec | Kernel security baseline, JSON audit contract | 
| Acquisition (Phase 1) | S.I.R.E.N | Validated forensic memory dump |
| Analysis (Phase 2) | K-Scanner | Threat identification, rootkit detection |

---

## Remediation in Forensic Context

The --apply flag enables **containment** during live response:
- Immediately close known kernel attack surfaces
- Block privilege escalation paths identified during triage
- Document the pre-remediation state in the report before applying changes
- Every remediation is backed up and verified

In forensic contexts, remediating a live system should only be done when the chain of custody is already established and the pre-remediation state is fully documented.
