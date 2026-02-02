# Requirements Document — requirements-audit

## Introduction

Requirements derived from the traceability matrix gap analysis (`traceability-matrix.md`) and audit plan (`plan.md`). Each requirement traces to a specific gap identified during the security audit of the OpenClaw Secure Stack.

**Project**: OpenClaw Secure Stack
**Feature**: requirements-audit
**Date**: 2026-02-02

---

## Functional Requirements

### FR-1: Container Hardening

**Source Gap**: FR-1 Partial — proxy image uses full Alpine; no image-hardening validation.

**Requirements**:

1. The proxy container image SHALL use a minimal or distroless base image with no unnecessary packages installed. *(Ubiquitous)*
2. `install.sh` SHALL validate that the OpenClaw image meets hardening criteria (no shell in production, no SUID binaries, non-root user). *(Ubiquitous)*

**Acceptance Criteria**:
- [ ] Proxy Dockerfile uses a minimal base (e.g., `alpine:latest` with `--no-cache` and explicit package removal, or distroless)
- [ ] `install.sh` includes an image-hardening check that fails on violation
- [ ] No container runs as root in default configuration

---

### FR-2: Network Isolation

**Source Gap**: FR-2 Partial — ports are not published but documentation of egress policy is incomplete.

**Requirements**:

1. No container SHALL publish ports to the host unless explicitly configured by the operator. *(Ubiquitous)*
2. WHEN egress restrictions change THEN the documentation (`README.md` or dedicated network doc) SHALL be updated to reflect the current policy. *(Event-Driven)*

**Acceptance Criteria**:
- [ ] `docker-compose.yml` exposes no host ports by default (only internal networks)
- [ ] Egress policy is documented and matches the actual CoreDNS/firewall configuration
- [ ] Changing an egress rule without updating docs causes an audit script warning

---

### FR-3: Skill Pinning & Trust Score

**Source Gap**: FR-3 Partial — skills are scanned but not pinned by hash; trust score not persisted.

**Requirements**:

1. WHEN a skill is scanned THEN the scanner SHALL verify the skill content against a pinned cryptographic hash. *(Event-Driven)*
2. The system SHALL persist a trust score for each skill in the quarantine database. *(Ubiquitous)*

**Acceptance Criteria**:
- [ ] Skill manifest includes SHA-256 hash for each skill file
- [ ] Scanner rejects skills whose content does not match the pinned hash
- [ ] Trust score is stored in the quarantine DB and queryable

---

### FR-4: Quarantine Runtime Enforcement

**Source Gap**: FR-4 Partial — quarantine DB exists but runtime enforcement is not verified.

**Requirements**:

1. WHILE a skill is quarantined THE system SHALL prevent its execution and return a clear rejection message. *(State-Driven)*

**Acceptance Criteria**:
- [ ] Attempting to invoke a quarantined skill returns an error indicating quarantine status
- [ ] No code path bypasses the quarantine check
- [ ] Integration test confirms quarantined skill cannot execute

---

### FR-5: Audit Log Hardening

**Source Gap**: FR-10 Partial — audit logging exists but lacks append-only enforcement and tamper detection.

**Requirements**:

1. Audit logs SHALL be append-only with configurable rotation and retention policies. *(Ubiquitous)*
2. IF a log file is tampered with THEN the system SHALL detect the tampering and alert the operator. *(Unwanted Behavior)*

**Acceptance Criteria**:
- [ ] Log files are opened in append-only mode
- [ ] Rotation and retention are configurable via environment variables or config file
- [ ] Tamper detection mechanism exists (e.g., checksums, chattr +a, or integrity monitor)
- [ ] Alert is generated on tamper detection

---

### FR-6: Security Audit Script

**Source Gap**: NFR-2 Gap — no automated OWASP-aligned security validation exists.

**Requirements**:

1. `scripts/audit.py` SHALL exist and perform OWASP-aligned security checks against the running stack. *(Ubiquitous)*
2. The audit script SHALL exit with code 0 only when zero findings are reported. *(Ubiquitous)*

**Acceptance Criteria**:
- [ ] `scripts/audit.py` exists and is executable
- [ ] Script checks at minimum: container hardening, network isolation, secret management, log integrity
- [ ] Exit code 0 = pass (no findings); non-zero = fail
- [ ] Script output is human-readable and CI-friendly

---

## Non-Functional Requirements

### NFR-1: Performance Validation

**Source Gap**: NFR-1 Partial — no startup-time or latency benchmarks defined.

**Requirements**:

1. The stack SHALL start within a defined startup-time threshold (configurable, default 60s). *(Ubiquitous)*
2. WHEN the proxy receives a request THEN it SHALL respond within the configured latency threshold (default 500ms p95). *(Event-Driven)*

**Acceptance Criteria**:
- [ ] Startup time is measured and compared against threshold in CI
- [ ] Latency p95 is measurable via health-check or smoke test
- [ ] Thresholds are configurable via environment variables

---

### NFR-2: CI / Maintainability

**Source Gap**: NFR-4 Partial — no documented rebuild strategy; base images not pinned.

**Requirements**:

1. All Dockerfiles SHALL pin base image versions using digest or explicit tag. *(Ubiquitous)*
2. The rebuild strategy (when and how to rebuild images) SHALL be documented. *(Ubiquitous)*

**Acceptance Criteria**:
- [ ] No Dockerfile uses `:latest` without a pinned digest
- [ ] `README.md` or `MAINTENANCE.md` documents the rebuild strategy
- [ ] CI pipeline validates base image pinning

---

### NFR-3: Usability / Documentation

**Source Gap**: NFR-3 Partial — troubleshooting section incomplete.

**Requirements**:

1. The documentation SHALL include a troubleshooting section covering common failure modes. *(Ubiquitous)*

**Acceptance Criteria**:
- [ ] Troubleshooting section exists in README or dedicated doc
- [ ] Covers at minimum: startup failures, DNS resolution issues, certificate errors, quarantine behavior
- [ ] Each entry includes symptom, cause, and resolution

---

## Out of Scope

- GUI / web dashboard
- Multi-tenancy
- Kubernetes deployment
- Windows native support

## Success Criteria

Every row in the traceability matrix (`traceability-matrix.md`) reaches status **Met**.
