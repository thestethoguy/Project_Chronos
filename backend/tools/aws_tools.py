# backend/tools/aws_tools.py
import copy
import fnmatch
import json
import os
import re
from pathlib import Path

from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv


def _fallback_tool(name: str) -> Any:
    def deco(fn: Any) -> Any:
        fn.name = name
        fn.func = fn
        fn.run = lambda *a, **kw: fn(*a, **kw)
        return fn
    return deco


tool: Any = _fallback_tool
try:
    import importlib

    tool = importlib.import_module("crewai.tools").tool
except Exception:  # noqa: BLE001
    pass


ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(dotenv_path=ENV_PATH)

REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
# Demo default: fall back to labelled mock data. Set CHRONOS_USE_MOCK_AWS=false
# to get an explicit error instead whenever AWS can't be reached.
USE_MOCK_FALLBACK = os.environ.get("CHRONOS_USE_MOCK_AWS", "true").lower() == "true"

_cfg = Config(connect_timeout=3, read_timeout=3, retries={"max_attempts": 1})
iam_client = boto3.client("iam", region_name=REGION, config=_cfg)
ec2_client = boto3.client("ec2", region_name=REGION, config=_cfg)

POLICY_NAME = "default-policy"
INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
PERMISSION_RE = re.compile(r"^[A-Za-z0-9-]+:[A-Za-z0-9*?]+$")  # e.g. iam:PassRole
MOCK_WARNING = "MOCK DATA: this was NOT read from AWS. Do not present it as the real configuration."

MOCK_DEFAULT_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": ["s3:GetObject", "sts:AssumeRole"], "Resource": "*"}
    ],
}

MOCK_ROLE_POLICIES = {
    "DomainAdminRole": {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow",
             "Action": ["iam:PassRole", "sts:AssumeRole", "ec2:*"],
             "Resource": "*"}
        ],
    }
}

SUMMARIES = {
    "revoked": "Removed '{p}' from the inspected policy of {r}.",
    "not_present": "'{p}' is not granted by the inspected policy of {r}. No change.",
    "still_granted_by_wildcard": (
        "'{p}' remains covered by wildcard action(s) in the inspected policy of {r}. "
        "The role's effective permissions have not been fully evaluated; "
        "the wildcard must be narrowed first."
    ),
    "unsupported_statement_present": (
        "The inspected policy of {r} contains NotAction statements this tool cannot "
        "evaluate. Treat this diff as unverified."
    ),
}


def _dump(obj: dict) -> str:
    return json.dumps(obj, indent=2)


def _aws_error_reason(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return f"ClientError:{exc.response['Error']['Code']}"
    return type(exc).__name__


def _revoke_action(policy: dict, permission: str):
    """Return (new_policy, analysis). Never claims a revocation that did not happen."""
    perm = permission.lower()
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    new_statements, removed_exact, covering, unsupported = [], False, [], False
    for stmt in statements:
        stmt = copy.deepcopy(stmt)
        if stmt.get("Effect") == "Allow":
            if "NotAction" in stmt:
                unsupported = True
            elif "Action" in stmt:
                actions = stmt["Action"]
                if isinstance(actions, str):
                    actions = [actions]
                kept = []
                for a in actions:
                    if isinstance(a, str):
                        if a.lower() == perm:
                            removed_exact = True
                            continue
                        if fnmatch.fnmatchcase(perm, a.lower()):
                            covering.append(a)
                    kept.append(a)
                if not kept:
                    continue  # statement is now empty
                if len(kept) != len(actions):
                    stmt["Action"] = kept
        new_statements.append(stmt)

    if unsupported:
        status = "unsupported_statement_present"
    elif covering:
        status = "still_granted_by_wildcard"
    elif removed_exact:
        status = "revoked"
    else:
        status = "not_present"

    analysis = {"status": status, "removed_exact": removed_exact, "still_granted_by": covering}
    return {**policy, "Statement": new_statements}, analysis


@tool("draft_iam_policy_diff")
def draft_iam_policy_diff(role_name: str, permission_to_revoke: str) -> str:
    """Draft a before/after IAM policy diff revoking one permission (e.g. iam:PassRole) from a role."""
    if not isinstance(role_name, str) or not role_name.strip():
        return _dump({"status": "invalid_input", "error": "role_name must be a non-empty string", "executed": False})
    if not isinstance(permission_to_revoke, str) or not PERMISSION_RE.match(permission_to_revoke.strip()):
        return _dump({"status": "invalid_input",
                      "error": "permission_to_revoke must look like 'service:Action', e.g. 'iam:PassRole'",
                      "executed": False})
    role_name, permission_to_revoke = role_name.strip(), permission_to_revoke.strip()

    data_source, fallback_reason = "aws", None
    try:
        current = iam_client.get_role_policy(
            RoleName=role_name, PolicyName=POLICY_NAME
        )["PolicyDocument"]
    except (ClientError, BotoCoreError) as exc:
        reason = _aws_error_reason(exc)
        if not USE_MOCK_FALLBACK:
            return _dump({"status": "aws_error", "error": reason, "executed": False})
        current = MOCK_ROLE_POLICIES.get(role_name, MOCK_DEFAULT_POLICY)
        data_source, fallback_reason = "mock", reason

    proposed, analysis = _revoke_action(current, permission_to_revoke)

    result = {
        "role_name": role_name,
        "before": current,
        "after": proposed,
        "change_summary": SUMMARIES[analysis["status"]].format(p=permission_to_revoke, r=role_name),
        "analysis": analysis,
        "scope": f"inline policy '{POLICY_NAME}' only; managed policies, other inline policies, "
                 "Deny statements, conditions, permission boundaries and SCPs not examined",
        "data_source": data_source,
        "fallback_reason": fallback_reason,
        "executed": False,
    }
    if data_source == "mock":
        result["warning"] = MOCK_WARNING
    return _dump(result)


@tool("draft_ec2_isolation_plan")
def draft_ec2_isolation_plan(instance_id: str) -> str:
    """Draft a security-group change that would isolate an EC2 instance's traffic."""
    if not isinstance(instance_id, str):
        return _dump({"status": "invalid_input", "error": "instance_id must be a string", "executed": False})
    instance_id = instance_id.strip()

    data_source, fallback_reason = "aws", None
    current_sg_ids, vpc_id = [], None

    if not INSTANCE_ID_RE.match(instance_id):
        # Graph device ids (e.g. "dc-01") are not EC2 ids; only mock data is possible.
        data_source, fallback_reason = "mock", "not_an_ec2_instance_id"
        current_sg_ids = ["sg-mock12345"]
    else:
        try:
            resp = ec2_client.describe_instances(InstanceIds=[instance_id])
            instances = [i for r in resp.get("Reservations", []) for i in r.get("Instances", [])]
            if not instances:
                return _dump({"status": "instance_not_found", "instance_id": instance_id, "executed": False})
            for i in instances:
                vpc_id = i.get("VpcId")
                current_sg_ids += [g["GroupId"] for g in i.get("SecurityGroups", [])]
        except (ClientError, BotoCoreError) as exc:
            reason = _aws_error_reason(exc)
            if not USE_MOCK_FALLBACK:
                return _dump({"status": "aws_error", "error": reason, "executed": False})
            data_source, fallback_reason = "mock", reason
            current_sg_ids = ["sg-mock12345"]

    result = {
        "instance_id": instance_id,
        "current_security_groups": current_sg_ids,
        "isolation_group": {
            "name": "chronos-quarantine",
            "vpc_id": vpc_id,
            "ingress_rules": [],
            "egress_rules": [],
            "exists_in_aws": False,
            "note": "Must be created in the instance's VPC. New groups include an "
                    "allow-all egress rule that has to be explicitly revoked.",
        },
        "rationale": "Swap the instance onto a deny-all group, keeping it running for forensics.",
        "caveats": [
            "Existing tracked connections may persist until they time out.",
            "Network ACLs, instance role credentials and SSM access are unaffected.",
            "Isolation group is a proposal; it has not been created or verified.",
        ],
        "data_source": data_source,
        "fallback_reason": fallback_reason,
        "executed": False,
    }
    if data_source == "mock":
        result["warning"] = MOCK_WARNING
    return _dump(result)