# Requirements Traceability Matrix

## Scope

This report maps requirements from `openclaw-secure-stack/requirements.md` to evidence in the current codebase. Status values: Met, Partial, Gap.

## Functional Requirements

| ID | Requirement | Evidence | Status | Notes |
| --- | --- | --- | --- | --- |
| FR-1 | Secure Container Runtime | `docker-compose.yml`, `Dockerfile` | Partial | Non-root user, read-only FS, dropped caps, no-new-privileges set. Runtime image is `python:3.12-slim` (not distroless). OpenClaw image hardening not verified. |
| FR-2 | Network Isolation | `docker-compose.yml`, `config/egress-allowlist.conf`, `install.sh`, `docker/egress/Dockerfile` | Partial | Internal network + DNS allowlist in CoreDNS. `openclaw` publishes port 3000 to host (violates “no unnecessary ports”). |
| FR-3 | Skills Supply-Chain Scanner | `src/scanner/scanner.py`, `src/scanner/rules/*`, `config/scanner-rules.json`, `tests/security/test_malicious_skills.py` | Partial | Scanner detects dangerous APIs, network exfil, FS abuse; findings include path/line; duration tracked. Skill pinning and external allowlist integration missing; trust score computed but not stored/used. |
| FR-4 | Skills Quarantine | `src/quarantine/manager.py`, `src/scanner/cli.py` | Partial | Quarantine and override with acknowledgment + audit logs implemented. Runtime enforcement in OpenClaw not wired; relies on CLI/manual flow. |
| FR-5 | One-Click Deployment | `install.sh`, `.env.example` | Met | Checks Docker/Compose versions, creates `.env`, generates token, builds and launches stack. |
| FR-6 | Authentication | `src/proxy/auth_middleware.py`, `src/proxy/app.py`, `tests/unit/test_auth_middleware.py` | Met | Bearer auth, 401/403, constant-time compare. Token from `.env` via env var. |
| FR-7 | Secrets Management | `.gitignore`, `.env.example`, `install.sh`, `docker-compose.yml` | Met | `.env` ignored; tokens stored in env; `.env.example` documented. |
| FR-8 | Prompt Injection Mitigation | `src/sanitizer/sanitizer.py`, `config/prompt-rules.json`, `config/indirect-injection-rules.json`, `src/proxy/app.py` | Met | Sanitizer detects/strips/rejects with configurable rules; indirect scanner for responses. |
| FR-9 | Egress Allowlist Management | `config/egress-allowlist.conf`, `install.sh`, `docker-compose.yml` | Met | Allowlist file exists; CoreDNS zone generated; changes apply after restart. |
| FR-10 | Security Audit Logging | `src/audit/logger.py`, `src/models.py`, `src/proxy/auth_middleware.py`, `src/sanitizer/sanitizer.py`, `src/scanner/scanner.py`, `src/quarantine/manager.py` | Partial | JSONL logs with event type, risk, action. No rotation/retention; tamper-evident and read-only not enforced beyond container FS. |

## Non-Functional Requirements

| ID | Requirement | Evidence | Status | Notes |
| --- | --- | --- | --- | --- |
| NFR-1 | Performance | `src/scanner/scanner.py` | Partial | Scanner tracks duration; no automated startup time or latency checks. |
| NFR-2 | Security | None found (`scripts/audit.py` missing) | Gap | No audit script or OWASP mapping; CVE scan not present. |
| NFR-3 | Usability | `README.md`, `docs/quickstart-user.md`, `docs/quickstart-dev.md` | Partial | Docs exist; verify troubleshooting completeness and setup time claim. |
| NFR-4 | Maintainability | `Dockerfile`, `config/scanner-rules.json`, `docs/quickstart-dev.md` | Partial | Multi-stage build and external rules; no CI schedule or base image rebuild workflow. |

## Out of Scope Checks

Out-of-scope items (GUI, multi-tenancy, Kubernetes, Windows native) are not implemented, as expected.
