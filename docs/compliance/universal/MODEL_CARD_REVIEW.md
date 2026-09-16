# AI Model Card Review Procedure

**Document ID:** POL-UNIV-MCR-001  
**Frameworks:** ISO/IEC 42001 §A.6, NIST AI RMF MAP 1.1 / MANAGE 2.1  
**Assurance Posture:** ILLUSTRATIVE_REFERENCE  
**Status:** Active  

## 1. Scope and Purpose
This procedure defines the governance verification criteria required prior to registering or modifying foundation models or safety-classifier weights in the CAGE Gateway catalog.

## 2. Review Gate Criteria
All candidate models must provide verified documentation and artifacts covering:
1. **Intended Task Domain & Operational Boundaries:** Clear operational design domain (ODD) specifications.
2. **Attribution & Provenance:** Cryptographic digest or Software Bill of Materials (SBOM) tracking training data and base checkpoints.
3. **Safety Baseline:** Evaluated benchmark rates for toxic/jailbreak prompt injection and alignment with Control Barrier Function (CBF) constraints.
4. **Execution Route Compliance:** Explicit compatibility with `SubjectMetadata.consequence_ceiling`.
