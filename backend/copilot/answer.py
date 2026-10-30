# backend/copilot/answer.py
import json
import logging

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
    "Summarize this Cypher query result in one or two plain-language "
    "sentences for a security analyst. Do not invent any device or fact "
    "not present in the data. If the result is empty, say nothing matched."
)


def answer_question(driver, question: str) -> dict:
    """Answer a read-only topology question.

    `driver` may be None (Neo4j unconfigured/unreachable) -> the in-memory topology mirror is used.
    Every Cypher string, from Groq or from the offline rules, passes `validate_cypher` first;
    ValueError (-> HTTP 422) is raised for unsafe or untranslatable questions.
    """
    use_llm = llm_available()
    plan, cypher = None, None

    if use_llm:
        try:
            cypher = validate_cypher(llm_chat(COPILOT_SYSTEM_PROMPT, question))
        except ValueError:
            raise  # unsafe / empty model output
        except Exception as exc:  # noqa: BLE001
            logger.warning("Groq unavailable (%s); using offline rules.", type(exc).__name__)
            use_llm = False

    topology = topology_store.get_topology()
    if cypher is None:
        plan = rule_based_plan(question, topology["devices"])
        cypher = validate_cypher(plan["cypher"])  # destructive intents are rejected here

    records, data_source = None, "mirror"
    if driver is not None:
        try:
            from neo4j import READ_ACCESS
            from neo4j.exceptions import Neo4jError

            try:
                # Read-only session: Neo4j itself rejects writes, even if validation missed one.
                with driver.session(default_access_mode=READ_ACCESS) as session:
                    records = [dict(r) for r in session.run(cypher)]
                data_source = "neo4j"
            except Neo4jError as exc:
                raise ValueError(f"Query could not be run: {exc.code}") from exc
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001 - connection dropped etc.: fall back to the mirror
            logger.warning("Neo4j query failed (%s); answering from topology mirror.", type(exc).__name__)

    if records is None:
        if plan is None:  # LLM cypher can't run on the mirror: execute the equivalent rule-based intent
            plan = rule_based_plan(question, topology["devices"])
            cypher = validate_cypher(plan["cypher"])
        records = run_on_mirror(plan, topology)

    summary = None
    if use_llm:
        try:
            summary = llm_chat(
                SUMMARY_PROMPT,
                f"Question: {question}\nCypher: {cypher}\nResult: {json.dumps(records, default=str)}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Groq summary failed (%s); using offline summary.", type(exc).__name__)
    if summary is None:
        summary = summarize_offline(question, plan, records)

    return {
        "cypher_query": cypher,
        "raw_result": records,
        "answer": summary,
        "mode": "groq" if use_llm else "offline",
        "data_source": data_source,
    }