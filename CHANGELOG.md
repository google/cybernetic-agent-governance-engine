# Changelog

All notable changes to CAGE (Cybernetic Agentic Governance Engine) are documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Added
- Public OSS release preparation

---

## [2.0.0] — 2026-07-08

### Added
- Full NIST SP 800-53 Rev 5 compliance coverage via OSCAL and Lula validation
- EU AI Act Article 9 risk management system implementation
- MAS FEAT and MAS Notice 655 compliance posture for APAC deployments
- GDPR Article 22 automated decision-making safeguards
- DORA Article 10 ICT resilience controls
- ISO/IEC 42001 AI management system alignment
- NeMo Guardrails integration with CBRN content filtering
- STPA (System-Theoretic Process Analysis) compiler and validator
- Causal gatekeeper with Control Barrier Function (CBF) safety enforcement
- Confabulation scorer for LLM output reliability assessment
- HITL (Human-in-the-Loop) escalation with TOCTOU revalidation
- KMS-backed evidence signing for audit trail integrity
- PII sanitizer with regional data residency enforcement
- Token quota proxy with fiscal limit guard
- OPA policy engine integration with LangGraph harness
- AgentSight observability UI with real-time governance dashboard
- Compliance Bridge with automated OSCAL artifact generation
- Multi-region deployment support (US_FED, EU_ECB, APAC_MAS)
- Governed Financial Advisor reference implementation

### Security
- Prompt injection detection and mitigation
- Routing seal with HMAC integrity verification
- CMEK (Customer-Managed Encryption Keys) support
- mTLS enforcement via Linkerd service mesh
- Pod Security Admission enforcement

---

## [Prior versions]

Internal pre-release development history is not included in the public changelog.
The public release history begins at v2.0.0.

[Unreleased]: https://github.com/your-org/cybernetic-governance-engine/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/your-org/cybernetic-governance-engine/releases/tag/v2.0.0
