#!/usr/bin/env python3
"""Generate synthetic intents for schema refinement.

This script generates ~500 diverse intents across all categories to:
1. Test the current classification/planning pipeline
2. Identify missing schema fields
3. Work out user profile vs action details split

Usage:
    python scripts/generate_synthetic_intents.py --count 500 --output data/synthetic_intents.json
"""

import argparse
import json
import random
from collections import defaultdict
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Any, Set

from openai import OpenAI

# --- Templates for each category ---

CATEGORIES = {
    "security_operations": 0.06,
    "monitoring_and_alerting": 0.06,
    "incident_response": 0.05,
    "infrastructure_and_cloud": 0.06,
    "kubernetes_operations": 0.05,
    "database_operations": 0.05,
    "service_management": 0.04,
    "network_operations": 0.04,
    "identity_and_access_management": 0.05,
    "compliance_and_risk": 0.04,
    "backup_and_disaster_recovery": 0.03,
    "release_and_deployment": 0.05,
    "software_development": 0.06,
    "quality_assurance_and_testing": 0.04,
    "data_engineering": 0.04,
    "data_analysis_and_bi": 0.03,
    "ml_operations": 0.03,
    "customer_support_and_success": 0.05,
    "sales_operations": 0.04,
    "marketing_operations": 0.03,
    "finance_and_accounting": 0.04,
    "procurement_and_vendor_management": 0.03,
    "legal_and_contracts": 0.02,
    "hr_and_people_operations": 0.03,
    "facilities_and_workplace": 0.02,
    "project_and_program_management": 0.04,
    "product_management": 0.04,
    "executive_operations": 0.02,
    "knowledge_management_and_documentation": 0.03,
    "it_helpdesk_and_end_user_support": 0.04
}

# --- User profiles for context ---

USER_PROFILES = [
    # Engineering
    {"id": "dev-senior-backend", "role": "senior_developer", "trust_level": "high", "team": "backend",
     "domain": "payments", "access_tier": "prod-read", "oncall": True},
    {"id": "dev-junior-frontend", "role": "junior_developer", "trust_level": "medium", "team": "frontend",
     "domain": "web", "access_tier": "dev", "oncall": False},
    {"id": "sre-oncall", "role": "site_reliability_engineer", "trust_level": "high", "team": "sre",
     "domain": "platform", "access_tier": "prod-admin", "oncall": True},
    {"id": "platform-eng", "role": "platform_engineer", "trust_level": "high", "team": "platform", "domain": "infra",
     "access_tier": "prod-write", "oncall": False},
    {"id": "security-eng", "role": "security_engineer", "trust_level": "high", "team": "security", "domain": "iam",
     "access_tier": "prod-admin", "oncall": False},
    {"id": "qa-engineer", "role": "qa_engineer", "trust_level": "medium", "team": "qa", "domain": "release",
     "access_tier": "staging", "oncall": False},
    {"id": "data-eng", "role": "data_engineer", "trust_level": "medium", "team": "data", "domain": "pipelines",
     "access_tier": "prod-read", "oncall": False},
    {"id": "ml-ops", "role": "mlops_engineer", "trust_level": "high", "team": "ml", "domain": "inference",
     "access_tier": "prod-write", "oncall": False},

    # Business / Operations
    {"id": "support-agent", "role": "customer_support_agent", "trust_level": "low", "team": "support",
     "domain": "tickets", "access_tier": "support-tools", "oncall": False},
    {"id": "customer-success", "role": "customer_success_manager", "trust_level": "medium", "team": "cs",
     "domain": "accounts", "access_tier": "crm", "oncall": False},
    {"id": "sales-ops", "role": "sales_operations", "trust_level": "medium", "team": "sales", "domain": "pipeline",
     "access_tier": "crm-admin", "oncall": False},
    {"id": "marketing-ops", "role": "marketing_operations", "trust_level": "medium", "team": "marketing",
     "domain": "campaigns", "access_tier": "marketing-tools", "oncall": False},
    {"id": "finance-analyst", "role": "finance_analyst", "trust_level": "medium", "team": "finance",
     "domain": "billing", "access_tier": "finance-systems", "oncall": False},
    {"id": "accountant", "role": "accountant", "trust_level": "high", "team": "finance", "domain": "close",
     "access_tier": "finance-admin", "oncall": False},
    {"id": "procurement", "role": "procurement_specialist", "trust_level": "medium", "team": "procurement",
     "domain": "vendors", "access_tier": "erp", "oncall": False},
    {"id": "legal-counsel", "role": "legal_counsel", "trust_level": "high", "team": "legal", "domain": "contracts",
     "access_tier": "contracts", "oncall": False},
    {"id": "hr-generalist", "role": "hr_generalist", "trust_level": "medium", "team": "hr", "domain": "people_ops",
     "access_tier": "hr-systems", "oncall": False},
    {"id": "facilities", "role": "facilities_manager", "trust_level": "medium", "team": "facilities",
     "domain": "workplace", "access_tier": "facilities-tools", "oncall": False},

    # Leadership / PM
    {"id": "pm", "role": "product_manager", "trust_level": "high", "team": "product", "domain": "roadmap",
     "access_tier": "read-only", "oncall": False},
    {"id": "proj-mgr", "role": "project_manager", "trust_level": "high", "team": "pmo", "domain": "delivery",
     "access_tier": "read-only", "oncall": False},
    {"id": "eng-manager", "role": "engineering_manager", "trust_level": "high", "team": "platform",
     "domain": "execution", "access_tier": "prod-read", "oncall": False},
    {"id": "exec-assistant", "role": "executive_assistant", "trust_level": "medium", "team": "execops",
     "domain": "scheduling", "access_tier": "calendar", "oncall": False},
    {"id": "cxo", "role": "executive", "trust_level": "high", "team": "leadership", "domain": "strategy",
     "access_tier": "read-only", "oncall": False},

    # IT / External
    {"id": "it-admin", "role": "it_admin", "trust_level": "high", "team": "it", "domain": "endpoints",
     "access_tier": "corp-admin", "oncall": False},
    {"id": "external-contractor", "role": "contractor", "trust_level": "low", "team": "external", "domain": "limited",
     "access_tier": "sandbox", "oncall": False},
]

# --- Scenarios (why is user doing this?) ---

SCENARIOS = [
    "debugging production issue",
    "responding to an alert",
    "post_incident followup",
    "routine maintenance",
    "security audit",
    "access request fulfillment",
    "deployment preparation",
    "release rollback",
    "cost reduction review",
    "quarterly compliance reporting",
    "customer escalation",
    "onboarding a new employee",
    "offboarding an employee",
    "vendor renewal decision",
    "month_end close",
    "budget planning",
    "contract review",
    "policy update",
    "documentation update",
    "training and enablement",
]

URGENCY_LEVELS = ["low", "medium", "high", "sev1"]

DATA_SENSITIVITY = ["public", "internal", "confidential", "regulated"]

EXECUTION_CONSTRAINT_SETS = [
    "read_only",
    "safe_write",
    "destructive_requires_approval",
    "no_external_network",
    "no_prod_access",
]

TARGET_SYSTEMS = [
    "filesystem",
    "database",
    "kubernetes",
    "cloud_console",
    "ci_cd",
    "monitoring",
    "iam",
    "crm",
    "erp",
    "hris",
    "ticketing",
    "docs_wiki",
    "email_calendar",
]

APPROVAL_MODELS = [
    "none",
    "manager_approval",
    "security_approval",
    "two_person_rule",
]

GENERATING_PROMPT = f"""
You are generating a dataset of operational intents. Output MUST be valid JSON only. No markdown.

INPUT:
- category: $$CATEGORY$$

You have access to the following option pools (choose from them):
- USER_PROFILES:{USER_PROFILES}
- SCENARIOS:{SCENARIOS}
- URGENCY_LEVELS:{URGENCY_LEVELS}
- DATA_SENSITIVITY:{DATA_SENSITIVITY}
- EXECUTION_CONSTRAINT_SETS:{EXECUTION_CONSTRAINT_SETS}
- TARGET_SYSTEMS:{TARGET_SYSTEMS}
- APPROVAL_MODELS:{APPROVAL_MODELS}

TASK:
1) Select ONE user_profile that is realistic for the given category.
2) Select context fields that are realistic for the chosen user_profile + category:
   - scenario (required)
   - urgency (required)
   - target_system (required)
   - execution_constraints (required)
   - data_sensitivity (optional; include when relevant to the category)
   - approval_model (optional; include when constraints imply approval or the category suggests governance)
3) Generate ONE intent object with EXACT structure:

{{
  "id": "<category>.<snake_case_task_name>",
  "category": "<category>",
  "name": "<short human name>",
  "description": "<2-3 sentences, plain language, consistent with selected context>",
  "user_profile": {{
    "id": "...",
    "role": "...",
    "trust_level": "...",
    "team": "...",
    "access_tier": "...",
    "... optional fields only if relevant (domain, oncall) ..."
  }},
  "context": {{
    "scenario": "...",
    "urgency": "...",
    "target_system": "...",
    "execution_constraints": "...",
    "... optional fields only if relevant (data_sensitivity, approval_model) ..."
  }},
  "steps": [
    {{"step": 1, "action": "...", "verify": "..."}},
    ...
  ],
  "abort_conditions": ["..."]
}} 

RULES:
- Choose ONLY values that exist in the provided option pools.
- Steps must be tool-agnostic: DO NOT include commands (no kubectl, rm, SQL, curl, terraform, etc.).
- Each step action must be atomic and declarative. Avoid branching words like "if", "maybe", "as needed".
- Each step must include a "verify" clause describing observable evidence (dashboard check, ticket updated, document approved, metric improved, etc.).
- Step count:
  - incident_response / monitoring_and_alerting / security_operations: 10–16 steps
  - infrastructure_and_cloud / kubernetes_operations / database_operations / release_and_deployment: 8–14 steps
  - business/ops categories (finance, hr, legal, procurement, sales/marketing ops, exec ops): 6–12 steps
  - knowledge_management_and_documentation: 5–9 steps
- abort_conditions: 1–3 items, clear stop conditions (e.g., verification fails, approval denied, unsafe environment).
- Never output secrets, credentials, private URLs, or real identifiers.

Now generate the intent JSON for category=$$CATEGORY$$.
"""

HARDENING_PROMPT = """
You are a **governance and execution-hardening engine**.

You are given a JSON ARRAY of operational intent objects.
Each intent represents a task that will later be executed by a **deterministic, non-LLM executor**.
The JSON produced by this process will serve as the **single source of truth for execution**.

---

## Goal

Produce a **PROPOSED EDITED JSON SCHEMA** that evolves the existing intent structure so that **each intent and each step** is:

* deterministic
* predictable
* auditable
* safe
* fully constrained by the JSON itself

The executor must not make decisions, infer intent, or fill gaps.

---

## Strict rules

* Output **VALID JSON ARRAY ONLY**
* Output **a proposed edited version of the input JSON structure**
* **Do NOT remove any existing fields**
* **Do NOT change the business meaning or task goal**
* **Do NOT introduce tool-specific commands**
* Assume the executor follows the JSON **literally**

---

## Allowed edits

You MAY **add or refine fields** to make execution explicit and controlled.

### Context hardening

You MAY add or refine fields in `context` when missing or underspecified, especially:

* `execution_constraints`
* `approval_model`
* `data_sensitivity`
* additional guardrail-style fields that:

  * constrain blast radius
  * restrict environment or scope
  * define preconditions and invariants
  * define refusal conditions

### Step hardening

You MAY add or refine fields inside `steps[]` so that **each step fully specifies execution**:

Each step must explicitly describe:

* constraints
* allowed scope and boundaries
* required inputs and expected outputs
* validation and verification criteria
* guardrails and refusal conditions

Rules for steps:

* No decisions are left to the executor
* No ambiguous language (e.g. “review”, “check”, “ensure” without criteria)
* No implied judgment or discretion
* No branching or conditional logic

---

## Forbidden behavior

* **Do NOT add new steps** unless absolutely required for determinism
  (prefer redefining existing steps)
* **Do NOT remove steps**
* **Do NOT introduce branching or conditional execution**
* **Do NOT infer missing intent or add new goals**

---

## Editing mindset

* Treat this as **policy and execution hardening**, not task design
* Prefer **explicit constraints** over flexibility
* Prefer **refusal** over guesswork
* If something is underspecified, **constrain it**

---

## Output contract

Return only the edited JSON ARRAY.

---

## INPUT JSON

$$$PASTE JSON ARRAY HERE$$$
"""

client = OpenAI()


def _weighted_random_category(dist: Dict[str, float]) -> str:
    categories = list(dist.keys())
    weights = list(dist.values())
    return random.choices(categories, weights=weights, k=1)[0]


def generate_intent(intent_id: int):
    category = _weighted_random_category(CATEGORIES)

    response = client.chat.completions.create(
        model="gpt-4.1",  # default, stable choice
        temperature=0.6,
        messages=[
            {"role": "system", "content": GENERATING_PROMPT.replace("$$CATEGORY$$", category)},
        ],
    )

    raw_text = response.choices[0].message.content.strip()

    try:
        intent_json = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned invalid JSON: {e}\n\nRaw output:\n{raw_text}")
    return intent_json

    # return SyntheticIntent(
    #     id=f"intent-{intent_id:04d}",
    #     category=category,
    #     tool_call={"name": tool, "arguments": args},
    #     user_profile=random.choice(USER_PROFILES),
    #     scenario=random.choice(SCENARIOS),
    #     risk_indicators=risk_indicators,
    #     expected_decision=expected,
    # )


def generate_all(count: int) -> list[dict]:
    """Generate count synthetic intents across all categories."""

    intents = []
    for i in range(150):
        intent = generate_intent(len(intents))
        intents.append(intent)
        with open("intents", "w") as f:  # opening a file handler to create new file
            json.dump(intents, f)

    return intents


def harden_intents_in_batches(
        _intents: List[Dict[str, Any]],
        p_intents: List[Dict[str, Any]],
        batch_size: int = 5,
        model: str = "gpt-5.1"
) -> List[Dict[str, Any]]:
    """
    Takes a list of intent JSON objects, processes them in batches,
    and returns a new list of intents with hardened / edited schemas.

    The LLM is instructed to:
    - Treat the intent JSON as a single source of truth
    - Propose additions or refinements ONLY to:
        * context (e.g. execution_constraints, approval_model, data_sensitivity)
        * steps[].action / steps[].verify (more explicit, deterministic wording)
    - Improve guardrails, determinism, and executor control
    - Preserve original meaning and business intent
    - Never remove fields, only refine or add where missing
    - Output valid JSON ONLY
    """

    hardened_intents: List[Dict[str, Any]] = p_intents
    intents = []
    for _i in _intents:
        found = False
        for i in hardened_intents:
            if i['id'] == _i['id']:
                found = True

        if not found:
            intents.append(_i)
    print(len(intents))

    for i in range(0, len(intents), batch_size):
        batch = intents[i: i + batch_size]

        response = client.chat.completions.create(
            model=model,
            temperature=0.3,
            messages=[
                {"role": "system",
                 "content": HARDENING_PROMPT.replace('$$$PASTE JSON ARRAY HERE$$$', json.dumps(batch, indent=2))},
            ],
        )

        raw_text = response.choices[0].message.content.strip()

        try:
            edited_batch = json.loads(raw_text)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"LLM returned invalid JSON while hardening batch starting at index {i}: {e}\n\n"
                f"Raw output:\n{raw_text}"
            )

        if not isinstance(edited_batch, list):
            raise ValueError("Expected a JSON array as output from the hardening step.")

        if len(edited_batch) != len(batch):
            raise ValueError(
                "Output batch length mismatch. "
                f"Expected {len(batch)}, got {len(edited_batch)}."
            )

        hardened_intents.extend(edited_batch)
        with open("proposed_intents", "w") as f:
            json.dump(hardened_intents, f, indent=2)

    return hardened_intents


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic intents")
    parser.add_argument("--count", type=int, default=500, help="Number of intents to generate")
    parser.add_argument("--output", type=str, default="data/synthetic_intents.json", help="Output file")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)

    intents = generate_all(args.count)

    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(intents, f, indent=2)

    # Print summary
    categories = {}
    # decisions = {}
    for intent in intents:
        cat = intent["category"]
        # dec = intent["expected_decision"]
        categories[cat] = categories.get(cat, 0) + 1
        # decisions[dec] = decisions.get(dec, 0) + 1

    print(f"Generated {len(intents)} synthetic intents to {args.output}")
    print("\nBy category:")
    for cat, count in sorted(categories.items()):
        print(f"  {cat}: {count}")
    # print("\nBy expected decision:")
    # for dec, count in sorted(decisions.items()):
    #     print(f"  {dec}: {count}")


def get_type_signature(value: Any) -> str:
    """Get a type signature for a value."""
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return "boolean"
    elif isinstance(value, int):
        return "integer"
    elif isinstance(value, float):
        return "number"
    elif isinstance(value, str):
        return "string"
    elif isinstance(value, list):
        if not value:
            return "array<empty>"
        # Get unique types in array
        item_types = sorted(set(get_type_signature(item) for item in value))
        return f"array<{','.join(item_types)}>"
    elif isinstance(value, dict):
        return "object"
    else:
        return type(value).__name__


def collect_field_paths(obj: Any, prefix: str = "") -> dict[str, list[str]]:
    """Recursively collect all field paths and their types."""
    paths = defaultdict(list)

    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            type_sig = get_type_signature(value)
            paths[path].append(type_sig)

            # Recurse into nested structures
            if isinstance(value, dict):
                nested = collect_field_paths(value, path)
                for k, v in nested.items():
                    paths[k].extend(v)
            elif isinstance(value, list) and value:
                # Sample first item for structure (and any dict items)
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        nested = collect_field_paths(item, f"{path}[]")
                        for k, v in nested.items():
                            paths[k].extend(v)
                        break  # Just analyze first dict item for structure

    return paths


def extract_schema_shape(obj: dict, max_depth: int = 10) -> dict:
    """Extract the structural shape of an object (keys and types, no values)."""
    if max_depth <= 0:
        return {"_truncated": True}

    shape = {}
    for key, value in obj.items():
        if isinstance(value, dict):
            shape[key] = extract_schema_shape(value, max_depth - 1)
        elif isinstance(value, list):
            if not value:
                shape[key] = []
            elif isinstance(value[0], dict):
                shape[key] = [extract_schema_shape(value[0], max_depth - 1)]
            else:
                shape[key] = [get_type_signature(value[0])]
        else:
            shape[key] = get_type_signature(value)
    return shape


def hash_shape(shape: dict) -> str:
    """Create a hashable string from a shape for deduplication."""
    return json.dumps(shape, sort_keys=True)


def analyze_plans(plans: list[dict]) -> dict:
    """Analyze a list of execution plans for schema variants."""

    # Collect all field paths across all plans
    all_paths = defaultdict(list)

    # Collect unique shapes for each major section
    section_shapes = defaultdict(lambda: defaultdict(list))

    # Track field presence
    field_presence = defaultdict(int)

    for plan in plans:
        plan_id = plan.get("id", "unknown")

        # Collect paths
        paths = collect_field_paths(plan)
        for path, types in paths.items():
            all_paths[path].extend(types)
            field_presence[path] += 1

        # Analyze top-level sections
        for section in ["user_profile", "context", "steps"]:
            if section in plan:
                shape = extract_schema_shape({section: plan[section]})
                shape_hash = hash_shape(shape)
                section_shapes[section][shape_hash].append(plan_id)

        # Analyze step structures individually
        if "steps" in plan:
            for i, step in enumerate(plan["steps"]):
                step_shape = extract_schema_shape(step)
                shape_hash = hash_shape(step_shape)
                section_shapes["step_variants"][shape_hash].append(f"{plan_id}:step_{i + 1}")

    # Build analysis output
    analysis = {
        "summary": {
            "total_plans": len(plans),
            "total_unique_paths": len(all_paths),
        },
        "field_catalog": {},
        "section_variants": {},
        "step_schema_variants": [],
    }

    # Field catalog with types and presence
    for path, types in sorted(all_paths.items()):
        unique_types = sorted(set(types))
        analysis["field_catalog"][path] = {
            "types_observed": unique_types,
            "occurrences": len(types),
            "presence_count": field_presence[path],
            "presence_rate": round(field_presence[path] / len(plans), 2),
        }

    # Section shape variants
    for section, shapes in section_shapes.items():
        if section == "step_variants":
            continue
        variants = []
        for shape_hash, plan_ids in shapes.items():
            variants.append({
                "shape": json.loads(shape_hash),
                "used_by": plan_ids,
                "count": len(plan_ids),
            })
        analysis["section_variants"][section] = {
            "unique_shapes": len(variants),
            "variants": sorted(variants, key=lambda x: -x["count"]),
        }

    # Step schema variants
    step_variants = []
    for shape_hash, step_refs in section_shapes["step_variants"].items():
        step_variants.append({
            "shape": json.loads(shape_hash),
            "used_by_count": len(step_refs),
            "examples": step_refs[:5],  # First 5 examples
        })
    analysis["step_schema_variants"] = sorted(step_variants, key=lambda x: -x["used_by_count"])
    analysis["summary"]["unique_step_shapes"] = len(step_variants)

    return analysis


def print_summary(analysis: dict):
    """Print a human-readable summary."""
    print("\n" + "=" * 70)
    print("SCHEMA VARIANT ANALYSIS")
    print("=" * 70)

    summary = analysis["summary"]
    print(f"\nTotal plans analyzed: {summary['total_plans']}")
    print(f"Unique field paths: {summary['total_unique_paths']}")
    print(f"Unique step shapes: {summary['unique_step_shapes']}")

    print("\n" + "-" * 70)
    print("SECTION VARIANTS")
    print("-" * 70)

    for section, data in analysis["section_variants"].items():
        print(f"\n{section}: {data['unique_shapes']} unique shape(s)")
        for v in data["variants"][:3]:  # Show top 3
            print(f"  - Used by {v['count']} plan(s): {v['used_by'][:3]}...")

    print("\n" + "-" * 70)
    print("STEP SCHEMA VARIANTS (Top 5)")
    print("-" * 70)

    for v in analysis["step_schema_variants"][:5]:
        print(f"\nUsed by {v['used_by_count']} step(s)")
        print(f"  Examples: {v['examples'][:3]}")
        print(f"  Keys: {list(v['shape'].keys())}")

    print("\n" + "-" * 70)
    print("FIELDS WITH MULTIPLE TYPES")
    print("-" * 70)

    multi_type = {k: v for k, v in analysis["field_catalog"].items()
                  if len(v["types_observed"]) > 1}
    for path, data in list(multi_type.items())[:10]:
        print(f"  {path}: {data['types_observed']}")

    print("\n" + "-" * 70)
    print("OPTIONAL FIELDS (< 100% presence)")
    print("-" * 70)

    optional = {k: v for k, v in analysis["field_catalog"].items()
                if v["presence_rate"] < 1.0}
    for path, data in list(optional.items())[:15]:
        print(f"  {path}: {data['presence_rate'] * 100:.0f}% ({data['presence_count']}/{summary['total_plans']})")


def sre_enrich():
    with open('sre_intents.json', 'r') as f:
        intents = json.load(f)

    for i in intents:
        for t in i['tasks']:
            print(t['task_name'])


# if __name__ == "__main__":
#     main()
with open('data/schema_analyzed.json') as f:
    schema_analyzed = json.load(f)

composed = {}
for v in schema_analyzed["section_variants"]["steps"]["variants"]:
    for k, v in v["shape"]["steps"][0].items():
        if k not in composed.keys():
            composed[k] = v
print(composed)
# if not isinstance(plans, list):
#     plans = [plans]
#
# print(f"Loaded {len(plans)} plan(s)")
#
# # Analyze
# analysis = analyze_plans(plans)
#
# # Save
# with open('data/schema_analyzed.json', "w") as f:
#     json.dump(analysis, f, indent=2)
#
# # Print summary
# print_summary(analysis)
