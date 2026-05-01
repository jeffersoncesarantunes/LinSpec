# ● LinSpec Forensic Methodology

## ● Purpose

LinSpec operates as the **Initial Triage Layer** (Phase 0) in a digital forensic investigation. 

Before volatile memory is captured or disk images are created, LinSpec evaluates the environment's integrity. Its primary goal is to determine if the kernel's defensive posture was compromised or bypassed, providing immediate context for the subsequent phases of the investigation.

---

## ● Forensic Philosophy

LinSpec adheres to three core principles designed for operational security:

- **Non-Intrusive Analysis**: Operates strictly in user-space with read-only access to `/proc` and `/sys` interfaces, ensuring no "forensic footprints" are left that could alter system evidence.
- **Deterministic Evaluation**: Uses a fixed security baseline to ensure that audit results are reproducible and verifiable.
- **Evidence Chain Preparation**: Generates structured artifacts (JSON/CSV) that can be ingested by automated forensic pipelines.

---

## ● Investigation Flow

### 1. Baseline Validation
Identify critical deviations from hardened kernel configurations (e.g., ASLR disabled or Kernel Pointer leakage).

### 2. Exposure Mapping
Map the attack surface by detecting weak points—such as unprivileged user namespaces or lack of CPU mitigations—that could have facilitated lateral movement or privilege escalation.

### 3. Artifact Generation & Integration
Produce machine-readable reports that inform the **Acquisition Phase**. For example, identifying a lack of KASLR informs the analyst that memory offsets in a **S.I.R.E.N** dump will be static and easier to map in **K-Scanner**.

---

## ● Key Insight

LinSpec is a **Post-Mortem & Live Triage** tool. It does not look for malware signatures; instead, it answers the fundamental forensic question:

> "Did the system's runtime configuration provide an environment where an exploit could succeed?"

---

## ● Integration with the Forensic Ecosystem

LinSpec is the foundational pillar of a three-stage specialized workflow:

1. **LinSpec (Audit)**: Identifies structural weaknesses and establishes the security baseline.
2. **S.I.R.E.N (Acquisition)**: Performs surgical memory capture based on the triage findings.
3. **K-Scanner (Analysis)**: Scans for malicious artifacts and memory anomalies.

---

## ● Forensic Value Matrix

| Phase | Tool | Forensic Output |
| :--- | :--- | :--- |
| **Triage** | **LinSpec** | Kernel security baseline & exposure report. |
| **Acquisition** | **S.I.R.E.N** | Forensic memory dump (.raw / .mem). |
| **Analysis** | **K-Scanner** | Identification of threats and kernel rootkits. |

---

## ● Data Integrity

To ensure the integrity of the audit, LinSpec generates a **SHA-256 hash** suggestion for its reports, allowing investigators to maintain a clear chain of custody for the generated `report.json` and `report.csv` files.
