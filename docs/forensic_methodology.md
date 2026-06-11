# LinSpec Forensic Methodology

## Purpose

LinSpec fills the role of the Initial Triage Layer (Phase 0) in a digital forensic investigation.

Before you capture volatile memory, you need to know whether the environment is safe to work with. LinSpec checks whether the kernel's defensive posture has been compromised and hands off the technical intelligence needed for safe memory acquisition.

---

## Forensic Philosophy

Three core principles drive the design:

- **Non-Intrusive Analysis:** It runs strictly in user-space with read-only access to `/proc` and `/sys`. No forensic footprints, no risk of altering evidence on the system.
- **Deterministic Evaluation:** A fixed security baseline means results are reproducible and verifiable every time.
- **Ecosystem Symbiosis:** The machine-readable contract (`report.json`) drives how automated acquisition tools behave.

---

## Investigation Flow

### 1. Baseline Validation

Look for critical deviations from hardened kernel configs. ASLR disabled? Kernel pointers leaking? That's what this step catches.

### 2. Exposure Mapping

Map the attack surface by finding weak points — unprivileged user namespaces, missing CPU mitigations, anything that could've helped an attacker escalate privileges.

### 3. Intelligence for Acquisition (S.I.R.E.N Integration)

The reports dictate the acquisition strategy. A couple of examples:

- **Lockdown Detection:** If LinSpec finds Kernel Lockdown active, S.I.R.E.N switches to `/proc/kcore`.
- **Integrity Baseline:** The expected pointer state gives S.I.R.E.N a way to detect if memory reads are being spoofed or padded with NULL bytes.

---

## Key Insight

LinSpec is a post-mortem and live triage tool. It doesn't look for malware signatures. Instead, it answers a more fundamental question:

> "Did the system's runtime configuration make it possible for an exploit to succeed, and how do we safely extract evidence?"

---

## Integration with the Forensic Ecosystem

LinSpec anchors a three-stage workflow:

1. **LinSpec (Audit):** Establishes the security baseline and acquisition parameters.
2. **S.I.R.E.N (Acquisition):** Adaptive memory capture based on LinSpec's triage artifacts.
3. **K-Scanner (Analysis):** Scans for malicious artifacts, patterns, and memory anomalies.

---

## Forensic Value Matrix

| Phase | Tool | Forensic Output |
| :--- | :--- | :--- |
| **Triage (Phase 0)** | **LinSpec** | Kernel security baseline, lockdown status, JSON audit contract |
| **Acquisition (Phase 1)** | **S.I.R.E.N** | Validated forensic memory dump (.bin) and integrity manifest |
| **Analysis (Phase 2)** | **K-Scanner** | Threat identification, rootkit detection, pattern-matched artifacts |

---

## Data Integrity and Chain of Custody

LinSpec generates `report.json` and `report.csv` as structured artifacts. These should be hashed right alongside the memory dump to keep a clear chain of custody and establish the environmental context at the moment of acquisition.
