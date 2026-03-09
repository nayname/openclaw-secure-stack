# Changelog

All notable changes to the Execution Plan schema will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this schema adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-08

### Design Decisions

- `allow_unplanned` is `const: false` — executor cannot deviate from plan
- All verification conditions must be deterministic (no natural language)
- Field provenance documented (LLM-generated vs inherited vs system-generated)

#### Strictness vs. extensibility

- The schema is intentionally strict (`additionalProperties: false`) for execution-affecting structures to prevent unexpected fields from influencing behavior.
- This schema is currently shipped as a reference artifact and is not yet wired into the runtime planner/executor. Until migration, LLM output validation behavior remains governed by the legacy schema.
- When the runtime migrates to v1.x, we will use an explicit strategy for handling extra fields commonly produced by LLMs:
  - either reject unknown properties strictly, or
  - canonicalize plans by dropping unknown properties before validation and execution.

### Added

Initial stable release.

#### Required Fields
- `version` — Schema version (const "1.0.0")
- `plan_id` — UUID for binding and audit
- `created_at` — Plan creation timestamp
- `execution_mode` — execution strategy for the plan

    Allowed values:

  - `governance_driven` — execution strictly controlled by the governance executor
  - `agent_guided` — execution performed by an LLM agent but constrained by the plan
  - `hybrid` — governance executor orchestrates execution with limited agent participation


- `description_for_user` — User-facing confirmation text
- `surface_effects` — What resources are touched/modified/created/deleted
- `intent` — Summary, category, risk_level, five_w_one_h
- `steps[]` — Executable steps with do/verify/on_fail/audit
- `constraints` — Hard execution limits
- `abort_conditions` — Global abort triggers

#### Optional Fields
- `id` — Human-readable plan type identifier
- `session_id` — Session binding
- `expires_at` — Plan TTL
- `user_context` — Actor information
- `scope` — Target system and environment boundaries
- `invariants` — Must-hold conditions and preconditions
- `metadata` — Generation info, quality score, tags

#### Step Structure
- `step` — Step number (identifier, not execution order)
- `action` — Human-readable action label
- `depends_on` — Step dependencies
- `parallel` — Concurrent execution flag
- `inputs` — Required and optional inputs with types
- `do` — Tool, operation, target, parameters, allow/deny patterns
- `verify` — Deterministic checks with pass conditions
- `on_fail` — Behavior on failure, refuse_if conditions
- `audit` — Outputs to record

#### Pattern Matching
- `AllowDenyPatterns` for commands, paths, urls, args
- Pattern types: exact, glob, regex
- ArgPattern supports range matching (min/max)

### Design Decisions

- `allow_unplanned` is `const: false` — executor cannot deviate from plan
- All verification conditions must be deterministic (no natural language)
- Field provenance documented (LLM-generated vs inherited vs system-generated)
- Schema uses `additionalProperties: false` throughout for strictness