# backend/copilot/answer.py
from __future__ import annotations

import json
import logging
import os
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
    "analyst assistant. Answer the analyst's question in 2 to 5 clear, friendly, everyday "
    "sentences grounded strictly in the provided topology data, Cypher query results, and "
    "live simulation state. Do not invent any device ID that is not in the data."
)

CHRONOS_SPECIALIST_SYSTEM_PROMPT = """You are the **Project Chronos AI SOC Copilot**, an articulate, friendly, and deeply knowledgeable cybersecurity & system-architecture assistant built for **Project Chronos (Phase 2)**.

1. IDENTITY & TONE:
- You understand casual human conversation ("how are you", "hey", "thanks"), cybersecurity jargon, behavioral questions, and deep technical graph questions.
- Always respond in clear, engaging, easy-to-understand language. Never respond with robotic error messages.

2. FULL PROJECT CHRONOS ARCHITECTURE KNOWLEDGE:
- **Red Agent (Offensive Adversary Emulation)**: CrewAI agent simulating APT29/APT41 lateral movement (MITRE ATT&CK T1550.002 Pass-the-Hash). Starts at a `public_dmz` foothold and calls `graph_scan_neighbors(node_id)` so it only traverses real edges in the topology without hallucinating nodes.
- **Blue Agent (Bounded-Authority SOAR Defense)**: CrewAI agent following a mandatory 4-step protocol:
  (Step 1) `ml_score_anomaly` using a Scikit-Learn Isolation Forest model (`anomaly_score` in [0, 1]),
  (Step 2) `rag_retrieve_incidents` over 16 historical cyber incidents using a 768-dim local vector embedding store (MongoDB Atlas / deterministic fallback) wrapped in `<retrieved_incident_context>` prompt-injection delimiters,
  (Step 3) AWS Cloud Remediation Drafting (`draft_iam_policy_diff` removing `iam:PassRole` and `draft_ec2_isolation_plan` with `executed: false`),
  (Step 4) **Human-in-the-Loop (HITL) Approval Gate** (`status = awaiting_approval`), pausing before `graph_cut_connection` until a human analyst clicks **Approve & Sever Link** (`POST /approve_action`) or **Reject Proposal** (`POST /reject_action`).
- **Data Layer**: Neo4j AuraDB + in-memory topology mirror (`GET /topology`, `POST /upload_topology`) and MongoDB session store.

3. STRICT GROUNDING:
- Ground all topology answers strictly in the LIVE ASSIGNED TOPOLOGY and DETERMINISTIC GRAPH ANALYSIS provided below. Never invent device IDs that are not in the topology.
"""

GEMINI_MODELS = (
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
    "gemini-2.0-flash",
)


def _call_gemini_copilot(
    question: str,
    topology: dict,
    session_context: Optional[dict],
    cypher_query: str,
    raw_result: list[dict],
    offline_answer: str,
    history: Optional[list[dict]] = None,
    api_key_override: Optional[str] = None,
) -> Optional[str]:
    """Call Google Gemini (gemini-2.5-flash with fallback) when an API key is available."""
    # Skip live network calls during automated pytest runs unless explicitly testing with an override
    if os.getenv("PYTEST_CURRENT_TEST") and not api_key_override:
        return None

    api_key = (api_key_override or os.getenv("GEMINI_API_KEY") or "").strip().strip('"').strip("'")
    if not api_key or api_key.startswith("<"):
        return None

    try:
        import httpx  # type: ignore
    except Exception:  # noqa: BLE001
        return None

    devices = topology.get("devices", [])
    conns = topology.get("connections", [])
    compact_devices = [
        {
            "id": d.get("id"),
            "name": d.get("name"),
            "ip": d.get("ip"),
            "subnet": d.get("subnet"),
            "os": d.get("os"),
            "ports": d.get("ports", []),
            "cves": d.get("cves", []),
        }
        for d in devices[:30]
    ]
    compact_conns = [
        f"{c.get('source')} -> {c.get('target')} ({c.get('type', 'NETWORK_LINK')})"
        for c in conns[:40]
    ]

    history_lines: list[str] = []
    for item in (history or [])[-6:]:
        if isinstance(item, dict) and item.get("text"):
            role = "Analyst" if item.get("role") == "user" else "SOC Copilot"
            history_lines.append(f"{role}: {item.get('text')}")
    history_block = "\n".join(history_lines) if history_lines else "None (first turn)"

    user_prompt = (
        f"LIVE ASSIGNED TOPOLOGY ({len(devices)} devices, {len(conns)} connections):\n"
        f"Devices: {json.dumps(compact_devices)}\n"
        f"Connections: {json.dumps(compact_conns)}\n\n"
        f"LIVE SIMULATION TELEMETRY:\n{json.dumps(session_context or {}, default=str)}\n\n"
        f"EXECUTED READ-ONLY CYPHER QUERY:\n{cypher_query}\n\n"
        f"DETERMINISTIC GRAPH & BEHAVIORAL ANALYSIS:\n{offline_answer}\n\n"
        f"RECENT CONVERSATION HISTORY:\n{history_block}\n\n"
        f"ANALYST QUESTION: {question}\n\n"
        "Respond directly to the analyst in a clear, helpful, conversational tone (2 to 6 sentences, or bullet points if listing devices/paths)."
    )

    payload = {
        "system_instruction": {"parts": [{"text": CHRONOS_SPECIALIST_SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {"temperature": 0.25, "maxOutputTokens": 600},
    }

    for model_name in GEMINI_MODELS:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.post(
                    url,
                    params={"key": api_key},
                    json=payload,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates") or []
                    if candidates:
                        parts = (candidates[0].get("content") or {}).get("parts") or []
                        text = "".join(str(p.get("text", "")) for p in parts).strip()
                        if text:
                            return text
        except Exception as exc:  # noqa: BLE001
            logger.debug("Gemini model %s call failed (%s)", model_name, type(exc).__name__)
            continue

    return None


def answer_question(
    driver: Any,
    question: str,
    topology_override: Optional[dict] = None,
    session_context: Optional[dict] = None,
    history: Optional[list[dict]] = None,
    gemini_api_key: Optional[str] = None,
) -> dict:
    """Answer a read-only topology, architectural, or conversational SOC question.

    `driver` may be None (Neo4j unconfigured/unreachable) -> the in-memory topology mirror is used.
    Every Cypher string passes `validate_cypher` first; ValueError (-> HTTP 422) is raised ONLY
    for destructive/write commands or pure non-language gibberish.
    """
    is_standby = (session_context or {}).get("topology_mode") == "standby" or (
        isinstance(topology_override, dict)
        and isinstance(topology_override.get("devices"), list)
        and len(topology_override.get("devices", [])) == 0
    )

    if is_standby:
        topology = {"devices": [], "connections": []}
    elif isinstance(topology_override, dict) and isinstance(topology_override.get("devices"), list):
        topology = topology_override
    else:
        topology = topology_store.get_topology()

    # 1. Deterministic plan & read-only guardrail check
    plan = rule_based_plan(
        question,
        devices=topology.get("devices", []),
        topology=topology,
        session_context=session_context,
    )
    validated_plan_cypher = validate_cypher(plan["cypher"])  # raises ValueError on write intents!

    if is_standby:
        return {
            "cypher_query": "MATCH (d:Device) RETURN count(d) AS loaded_devices\nLIMIT 50",
            "raw_result": [],
            "answer": (
                "SOC Copilot is currently on Standby because no network topology blueprint is loaded yet. "
                "Please select either 'Load 20-Node Enterprise Demo' or upload a Custom Topology (.json) file "
                "first to initialize the Digital Twin and unlock graph analysis."
            ),
            "mode": "offline",
            "data_source": "mirror",
            "conversational": True,
        }

    conversational_intents = {
        "greeting",
        "chronos_arch",
        "network_overview",
        "conversational_general",
        "behavioral_explain",
        "risk_and_hardening",
        "multi_device_analysis",
    }
    is_conversational = plan.get("intent") in conversational_intents

    use_groq = llm_available() and not bool(os.getenv("PYTEST_CURRENT_TEST"))
    cypher: Optional[str] = None

    if use_groq and not is_conversational:
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
        except Exception as exc:  # noqa: BLE001
            # Never turn an LLM "INVALID" output on a safe question into a false HTTP 422!
            # `validated_plan_cypher` already verified the question is safe & read-only.
            logger.info("Groq Cypher fallback to rule plan (%s).", type(exc).__name__)
            cypher = validated_plan_cypher

    if cypher is None:
        cypher = validated_plan_cypher

    records, data_source = None, "mirror"
    if driver is not None and topology_override is None and not is_conversational:
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

    # 2. Try Live Google Gemini (gemini-2.5-flash) first if key is available
    mode = "offline"
    summary = _call_gemini_copilot(
        question=question,
        topology=topology,
        session_context=session_context,
        cypher_query=cypher,
        raw_result=records,
        offline_answer=offline_answer,
        history=history,
        api_key_override=gemini_api_key,
    )
    if summary:
        mode = "gemini"

    # 3. Otherwise try Groq LLM summary if configured
    if not summary and use_groq:
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
            if summary:
                mode = "groq"
        except Exception as exc:  # noqa: BLE001
            logger.warning("Groq summary failed (%s); using dynamic offline summary.", type(exc).__name__)

    if not summary:
        summary = offline_answer

    return {
        "cypher_query": cypher,
        "raw_result": records,
        "answer": summary,
        "mode": mode,
        "data_source": data_source,
        "conversational": is_conversational,
    }
