# backend/copilot/answer.py
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from backend.copilot.nl_to_cypher import (
    COPILOT_SYSTEM_PROMPT,
    llm_available,
    llm_chat,
    validate_cypher,
)
from backend.copilot.offline import rule_based_plan, run_on_mirror, summarize_offline
from backend.db import topology_store

logger = logging.getLogger("chronos.copilot")

SUMMARY_PROMPT = (
    "You are the Project Chronos SOC Copilot — an intelligent, conversational cybersecurity "
    "analyst assistant. Answer the analyst's question in 2 to 4 clear, friendly, everyday "
    "sentences grounded strictly in the provided topology data, Cypher query results, and "
    "live simulation state. Do not invent any device ID that is not in the data."
)


def answer_question(
    driver: Any,
    question: str,
    topology_override: Optional[dict] = None,
    session_context: Optional[dict] = None,
) -> dict:
    """Answer a read-only topology or behavioral SOC question.

    `driver` may be None (Neo4j unconfigured/unreachable) -> the in-memory topology mirror is used.
    Every Cypher string, from Groq or from the offline rules, passes `validate_cypher` first;
    ValueError (-> HTTP 422) is raised for unsafe or untranslatable questions.
    """
    topology = (
        topology_override
        if (isinstance(topology_override, dict) and isinstance(topology_override.get("devices"), list))
        else topology_store.get_topology()
    )

    # Always compute the rule-based plan first so destructive requests are caught deterministically
    # and conversational / multi-hop intents have full topology + session context.
    plan = rule_based_plan(
        question,
        devices=topology.get("devices", []),
        topology=topology,
        session_context=session_context,
    )
    validated_plan_cypher = validate_cypher(plan["cypher"])  # raises ValueError on write intents!

    use_llm = llm_available()
    cypher: Optional[str] = None
    conversational_intents = {"greeting", "behavioral_explain", "risk_and_hardening", "multi_device_analysis"}

    if use_llm and plan.get("intent") not in conversational_intents:
        try:
            device_hint = ", ".join(
                f"{d['id']} ({d.get('name', d['id'])}, subnet={d.get('subnet', 'internal_core')})"
                for d in topology.get("devices", [])[:25]
            )
            prompt_with_devices = (
                f"{COPILOT_SYSTEM_PROMPT}\n"
                f"Currently loaded devices in the topology: {device_hint}\n"
            )
            cypher = validate_cypher(llm_chat(prompt_with_devices, question))
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("Groq unavailable (%s); using dynamic topology rules.", type(exc).__name__)
            use_llm = False

    if cypher is None:
        cypher = validated_plan_cypher

    records, data_source = None, "mirror"
    if driver is not None and topology_override is None and plan.get("intent") not in conversational_intents:
        try:
            import importlib

            _neo4j: Any = importlib.import_module("neo4j")
            _neo4j_exc: Any = importlib.import_module("neo4j.exceptions")

            try:
                with driver.session(default_access_mode=_neo4j.READ_ACCESS) as session:
                    records = [dict(r) for r in session.run(cypher)]
                data_source = "neo4j"
            except _neo4j_exc.Neo4jError as exc:
                raise ValueError(f"Query could not be run: {exc.code}") from exc
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("Neo4j query failed (%s); answering from topology mirror.", type(exc).__name__)

    if records is None:
        records = run_on_mirror(plan, topology)

    offline_answer = summarize_offline(
        question,
        plan,
        records,
        topology=topology,
        session_context=session_context,
    )

    summary = None
    if use_llm:
        try:
            summary = llm_chat(
                SUMMARY_PROMPT,
                (
                    f"Question: {question}\n"
                    f"Cypher: {cypher}\n"
                    f"Query Result: {json.dumps(records, default=str)}\n"
                    f"Deterministic Baseline Analysis: {offline_answer}"
                ),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Groq summary failed (%s); using dynamic offline summary.", type(exc).__name__)

    if not summary:
        summary = offline_answer

    return {
        "cypher_query": cypher,
        "raw_result": records,
        "answer": summary,
        "mode": "groq" if use_llm else "offline",
        "data_source": data_source,
    }
