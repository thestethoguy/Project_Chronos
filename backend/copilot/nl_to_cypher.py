# backend/copilot/nl_to_cypher.py
import os
import re

MODEL = "groq/llama-3.3-70b-versatile"  # uses GROQ_API_KEY from the environment
RESULT_LIMIT = 50

SCHEMA_DESCRIPTION = """
Graph schema:
(:Device {id, name, ip, ports, os, cves}) -[:PART_OF_SUBNET]-> (:Subnet {id, scope})
(:Device) -[:CONNECTS_TO {type}]-> (:Device)
Subnet ids are 'public_dmz' and 'internal_core'.
"""

COPILOT_SYSTEM_PROMPT = f"""
You translate a security analyst's plain-English question into a single,
READ-ONLY Cypher query against this schema:
{SCHEMA_DESCRIPTION}
Rules:
- Only generate MATCH / RETURN queries. Never generate CREATE, MERGE, DELETE,
  SET, REMOVE, CALL, LOAD CSV or FOREACH.
- One statement only. No semicolons.
- Return ONLY the Cypher query, with no explanation and no markdown formatting.
"""

FORBIDDEN = re.compile(
    r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|CALL|LOAD|FOREACH|APOC)\b",
    re.IGNORECASE,
)
FORBIDDEN_KEYWORDS = FORBIDDEN  # alias used by the Phase 2 guide / tests
_STRING_LITERAL = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
_FENCE = re.compile(r"^```(?:cypher)?\s*|\s*```$", re.IGNORECASE)


def validate_cypher(query: str) -> str:
    """Raise ValueError unless query is a single read-only MATCH query."""
    query = _FENCE.sub("", query.strip()).strip()
    if not query:
        raise ValueError("Model returned an empty query.")
    # Ignore string literals so a device named 'SETUP' is not a false positive.
    code_only = _STRING_LITERAL.sub("''", query)
    if ";" in code_only:
        raise ValueError("Multiple statements are not allowed.")
    if not code_only.upper().startswith("MATCH"):
        raise ValueError("Generated query did not start with MATCH.")
    if FORBIDDEN.search(code_only):
        raise ValueError("Generated query contained a disallowed keyword.")
    if "RETURN" not in code_only.upper():
        raise ValueError("Generated query has no RETURN clause.")
    if not re.search(r"\bLIMIT\s+\d+", code_only, re.IGNORECASE):
        query = f"{query}\nLIMIT {RESULT_LIMIT}"
    return query


def llm_available() -> bool:
    """True when a Groq key is configured and litellm can be imported."""
    if not (os.environ.get("GROQ_API_KEY") or "").strip():
        return False
    import importlib.util

    return importlib.util.find_spec("litellm") is not None


def llm_chat(system: str, user: str) -> str:
    import importlib

    litellm = importlib.import_module("litellm")  # lazy: installed with CrewAI, absent in offline envs

    resp = litellm.completion(
        model=MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0,
        timeout=20,
    )
    return resp.choices[0].message.content.strip()


def generate_cypher(question: str) -> str:
    """Validated read-only Cypher: Groq when available, otherwise the offline rule-based translator."""
    if llm_available():
        try:
            return validate_cypher(llm_chat(COPILOT_SYSTEM_PROMPT, question))
        except ValueError:
            raise
        except Exception:  # noqa: BLE001 - network/auth/etc: fall back to offline rules
            pass
    from backend.copilot.offline import rule_based_plan
    from backend.db import topology_store

    plan = rule_based_plan(question, topology_store.get_topology()["devices"])
    return validate_cypher(plan["cypher"])