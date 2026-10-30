"""Person C - RAG ingestion (Guide Section 8.4, Steps 1 & 2).

Run:  python -m backend.rag.ingest_incidents            (from <repo_root>)
      python -m backend.rag.ingest_incidents --force    (wipe + reseed the starter corpus)
"""
from __future__ import annotations

import logging
import re
import sys
from datetime import datetime, timezone

if __package__ in (None, ""):  # allow `python ingest_incidents.py` from backend/rag
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import _bootstrap  # noqa: F401

from backend.db.mongo import incident_logs_collection
from backend.rag.embeddings import EMBEDDING_DIM, embed_text

logger = logging.getLogger("chronos.rag.ingest")

STARTER_SOURCE = "starter_corpus"
MAX_CHUNK_CHARS = 1200

STARTER_INCIDENTS: list[dict] = [
    {
        "title": "Incident 2024-11: Pass-the-hash via backup service account",
        "mitre_tactic": "Lateral Movement",
        "body": (
            "On 2024-11-14 an attacker who had phished a junior admin dumped NTLM hashes from the backup_portal "
            "host and replayed the svc_backup service account hash (T1550.002 Pass the Hash) against dc01 over SMB. "
            "The account had no logon restrictions and was a member of Backup Operators, which let the attacker "
            "read the NTDS.dit shadow copy.\n\n"
            "Detection came from an ML anomaly score of 0.81 on a service account logging in at 02:40 UTC from an "
            "unusual source. Containment: severing the backup_portal -> dc01 route, disabling svc_backup and "
            "rotating its credentials. Hardening: enforce SMB signing, restrict svc_backup to the backup VLAN, "
            "enable Protected Users and LAPS."
        ),
    },
    {
        "title": "Incident 2025-02: Reverse Proxy Credential Replay & Lateral Movement to Core Auth",
        "mitre_tactic": "Lateral Movement",
        "body": (
            "At 03:17 UTC an attacker who had compromised proxy_ingress through a spear-phished workstation replayed "
            "a cached NTLM hash (Pass-the-Hash, T1550.002) against auth_controller. The proxy logged 20 failed logins "
            "within four minutes, then a successful relay and abnormal SMB lateral movement toward dc01 and "
            "db_classified. About 50,000 bytes were exfiltrated after hours from db_classified to the proxy tier.\n\n"
            "The Isolation Forest scored the event 0.87 (ANOMALY): off-hours, high transfer volume, many failed "
            "logins. Containment cut the proxy_ingress -> auth_controller and proxy_ingress -> dc01 CONNECTS_TO "
            "edges and wrote an audit log with tactic Lateral Movement. Hardening: MFA on the proxy VLAN, disable "
            "NTLM where possible, segment proxy_ingress from the core and alert on bursts of failed logins."
        ),
    },
    {
        "title": "Incident 2024-03: Credential stuffing against auth_controller",
        "mitre_tactic": "Credential Access",
        "body": (
            "Between 01:00 and 03:30 UTC a botnet submitted roughly 14,000 leaked username/password pairs to the "
            "auth_controller LDAP bind endpoint via proxy_ingress (T1110.004 Credential Stuffing). Distributed "
            "source IPs kept each address under the per-IP lockout threshold, and 37 accounts were taken over.\n\n"
            "Detection: aggregate failed-login rate and a spike in distinct usernames per minute. Response: "
            "temporary rate limiting at proxy_ingress, forced password reset for affected users and enabling MFA. "
            "Hardening: breached-password screening and per-account rather than per-IP lockout."
        ),
    },
    {
        "title": "Incident 2024-06: Golden Ticket forged on dc01 after KRBTGT compromise",
        "mitre_tactic": "Credential Access",
        "body": (
            "After a DCSync from a compromised admin_ws session, the attacker obtained the krbtgt hash from dc01 and "
            "forged Kerberos Golden Tickets (T1558.001) valid for ten years. Tickets showed anomalous lifetimes and "
            "TGS requests without a prior TGT request in the dc01 logs.\n\n"
            "Containment required resetting the krbtgt password twice, ten hours apart, and isolating admin_ws. "
            "Hardening: restrict replication rights, monitor Event ID 4769 anomalies and tier the administration "
            "model so domain admins never log onto workstations."
        ),
    },
    {
        "title": "Incident 2024-08: SMB lateral movement across smb_pool",
        "mitre_tactic": "Lateral Movement",
        "body": (
            "A compromised workstation used admin shares (T1021.002 SMB/Windows Admin Shares) and PsExec to copy a "
            "payload to eleven file servers in smb_pool within 20 minutes. Detection was an unusual fan-out of "
            "SMB connections from a single source node and a burst of Event ID 5145 on ADMIN$.\n\n"
            "Containment: cutting every CONNECTS_TO edge from the source into smb_pool and quarantining the host. "
            "Hardening: block SMB between workstations, disable administrative shares where unneeded and deploy "
            "host firewall rules limiting smb_pool to approved clients."
        ),
    },
    {
        "title": "Incident 2024-09: Unauthorized SQL dump of db_classified",
        "mitre_tactic": "Exfiltration",
        "body": (
            "An application account with db_owner rights ran a full bcp export of the classified tables on "
            "db_classified at 04:05 UTC (T1048 Exfiltration Over Alternative Protocol, T1213 Data from Information "
            "Repositories). About 2.3 GB left the segment over an unencrypted channel to an external address.\n\n"
            "The ML engine flagged the anomalous transfer volume at an off-hours slot. Response: sever the outbound "
            "route from db_classified, revoke the account and preserve database audit logs. Hardening: least "
            "privilege for application accounts, database activity monitoring and egress allow-listing."
        ),
    },
    {
        "title": "Incident 2025-01: SSH brute force against bastion_host",
        "mitre_tactic": "Credential Access",
        "body": (
            "Over 9,000 failed SSH password attempts hit bastion_host in one hour from a hosting provider range "
            "(T1110.001 Password Guessing), followed by a successful login on a shared ops account with a weak "
            "password. The attacker then pivoted toward admin_ws and the internal management network.\n\n"
            "Response: block the source range, disable password authentication and lock the shared account. "
            "Hardening: key-only SSH with MFA, fail2ban, named accounts rather than shared ones and session "
            "recording on the bastion."
        ),
    },
    {
        "title": "Incident 2025-03: Privilege escalation via IAM PassRole misuse",
        "mitre_tactic": "Privilege Escalation",
        "body": (
            "A developer role with iam:PassRole on Resource * launched an EC2 instance with the DomainAdminRole "
            "instance profile and used the resulting credentials to call sts:AssumeRole across accounts "
            "(T1098 Account Manipulation, T1548 Abuse Elevation Control Mechanism). CloudTrail showed the "
            "RunInstances call with an unexpected IamInstanceProfile.\n\n"
            "Remediation: draft an IAM policy diff removing iam:PassRole from the inline policy, terminate the "
            "instance and rotate credentials. Hardening: scope PassRole to specific role ARNs, use permission "
            "boundaries and SCPs, and alert on PassRole to privileged roles. Human approval is required before "
            "applying any IAM change."
        ),
    },
    {
        "title": "Incident 2025-04: EC2 command-and-control beaconing from web_server_01",
        "mitre_tactic": "Command and Control",
        "body": (
            "An EC2 instance hosting web_server_01 beaconed every 60 seconds with +/-3 s jitter to a domain "
            "registered two days earlier over HTTPS (T1071.001 Web Protocols). VPC flow logs showed uniform small "
            "outbound packets, and the instance role was used to list S3 buckets.\n\n"
            "Response: draft an isolation plan that swaps the instance onto a deny-all security group while keeping "
            "it running for forensics, then snapshot the volume. Hardening: egress filtering, DNS allow-listing, "
            "IMDSv2 only and GuardDuty alerts routed to the SIEM."
        ),
    },
    {
        "title": "Incident 2025-05: DNS tunneling exfiltration through dns_ext",
        "mitre_tactic": "Exfiltration",
        "body": (
            "Long high-entropy TXT and CNAME queries from an internal host to attacker-controlled zones through "
            "dns_ext carried staged data out of the network (T1071.004 DNS, T1048.003). Query lengths averaged "
            "180 characters and volume was 40x the baseline for that host.\n\n"
            "Response: sinkhole the zone at dns_ext, isolate the source host and review for credential theft. "
            "Hardening: enforce an approved resolver, apply query-length and entropy analytics and block direct "
            "outbound port 53."
        ),
    },
    {
        "title": "Incident 2025-06: Ransomware staging detected in sandbox_stage",
        "mitre_tactic": "Impact",
        "body": (
            "Mass file renames with a new extension and deletion of volume shadow copies (T1486 Data Encrypted for "
            "Impact, T1490 Inhibit System Recovery) began on sandbox_stage after a malicious attachment was "
            "detonated, and the payload attempted to spread to smb_pool through mapped shares.\n\n"
            "Containment: immediately cut sandbox_stage from every neighbour, snapshot disks and block the "
            "attacker's hash across endpoints. Hardening: offline immutable backups, network isolation for "
            "detonation hosts and application control."
        ),
    },
    {
        "title": "Incident 2025-07: Insider payroll data access on payroll_engine",
        "mitre_tactic": "Collection",
        "body": (
            "A finance employee on leave authenticated to payroll_engine at 23:50 and queried salary records for "
            "the entire executive team (T1213 Data from Information Repositories, T1078 Valid Accounts). Records "
            "were copied to a personal cloud storage account through the proxy.\n\n"
            "Detection: behavioural baseline deviation on query volume and off-hours access. Response: suspend the "
            "account, review proxy logs and involve HR and legal. Hardening: just-in-time access, field-level "
            "masking and DLP rules on payroll exports."
        ),
    },
    {
        "title": "Incident 2025-08: SIEM log tampering on siem_logger",
        "mitre_tactic": "Defense Evasion",
        "body": (
            "After gaining admin rights, an attacker cleared Security event logs (T1070.001 Clear Windows Event "
            "Logs) and stopped the forwarding agent feeding siem_logger, creating a six-hour visibility gap. A "
            "gap in heartbeat events from the host was the only signal.\n\n"
            "Response: restore forwarding, reconstruct activity from network telemetry and treat the host as "
            "compromised. Hardening: write-once log storage, alerts on agent stoppage and Event ID 1102, and "
            "separate credentials for the logging infrastructure."
        ),
    },
    {
        "title": "Incident 2025-09: Web shell planted behind proxy_ingress",
        "mitre_tactic": "Initial Access",
        "body": (
            "An unpatched file-upload vulnerability on web_server_01 reachable through proxy_ingress allowed an "
            "attacker to place a web shell (T1190 Exploit Public-Facing Application, T1505.003 Web Shell). The "
            "shell ran reconnaissance commands and enumerated neighbours using the CONNECTS_TO graph.\n\n"
            "Response: take web_server_01 out of the proxy pool, remove the shell and patch the upload handler. "
            "Hardening: WAF rules for uploads, read-only web roots and file integrity monitoring."
        ),
    },
    {
        "title": "Incident 2025-10: Spear-phishing and LSASS credential dump on admin_ws",
        "mitre_tactic": "Credential Access",
        "body": (
            "A spear-phishing macro executed on admin_ws and dumped LSASS memory (T1003.001) with a renamed "
            "comsvcs.dll MiniDump call, exposing a cached domain admin token. The attacker attempted to reach dc01 "
            "and bastion_host within an hour using the stolen credentials.\n\n"
            "Response: isolate admin_ws, reset the exposed admin credentials and revoke tokens. Hardening: Credential "
            "Guard, attack surface reduction rules, privileged access workstations and no interactive admin logons "
            "from email-capable machines."
        ),
    },
    {
        "title": "Incident 2025-11: Kerberoasting of service accounts via auth_controller",
        "mitre_tactic": "Credential Access",
        "body": (
            "A low-privilege user requested service tickets for dozens of SPNs from auth_controller in a few "
            "seconds (T1558.003 Kerberoasting) using RC4 encryption, then cracked the payroll_engine service "
            "account password offline. The cracked account was later used for logons to db_classified.\n\n"
            "Response: rotate affected service passwords and move them to gMSAs. Hardening: enforce AES for "
            "Kerberos, use long random service-account passwords and alert on bulk TGS requests with RC4."
        ),
    },
]


def chunk_text(body: str, max_chars: int = MAX_CHUNK_CHARS) -> list[str]:
    """Split on paragraph boundaries (blank lines); merge small paragraphs up to `max_chars`."""
    paragraphs = [re.sub(r"\s+", " ", p).strip() for p in re.split(r"\n\s*\n", body or "")]
    paragraphs = [p for p in paragraphs if p]
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if current and len(current) + 1 + len(para) > max_chars:
            chunks.append(current)
            current = para
        else:
            current = f"{current} {para}".strip()
    if current:
        chunks.append(current)
    return chunks


def ingest_incident(title: str, mitre_tactic: str, body: str, source: str = "manual") -> dict:
    """Chunk, embed and store one incident write-up (one document per chunk)."""
    chunks = chunk_text(body)
    docs = [
        {
            "title": title,
            "mitre_tactic": mitre_tactic,
            "body": chunk,
            "chunk_index": i,
            "embedding": embed_text(f"{title}. {mitre_tactic}. {chunk}"),
            "source": source,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        }
        for i, chunk in enumerate(chunks)
    ]
    if docs:
        incident_logs_collection().insert_many(docs)
    return {"title": title, "mitre_tactic": mitre_tactic, "chunks": len(docs), "dimensions": EMBEDDING_DIM}


def seed_default_incidents(force_reseed: bool = False) -> int:
    """Insert the starter corpus when the collection is empty (or when force_reseed).

    Returns the number of incidents ingested (0 if the collection already had data)."""
    col = incident_logs_collection()
    if force_reseed:
        col.delete_many({"source": STARTER_SOURCE})
    elif col.count_documents({}) > 0:
        return 0
    all_docs: list[dict] = []
    now_iso = datetime.now(timezone.utc).isoformat()
    for inc in STARTER_INCIDENTS:
        title, mitre_tactic, body = inc["title"], inc["mitre_tactic"], inc["body"]
        for i, chunk in enumerate(chunk_text(body)):
            all_docs.append(
                {
                    "title": title,
                    "mitre_tactic": mitre_tactic,
                    "body": chunk,
                    "chunk_index": i,
                    "embedding": embed_text(f"{title}. {mitre_tactic}. {chunk}"),
                    "source": STARTER_SOURCE,
                    "ingested_at": now_iso,
                }
            )
    if all_docs:
        col.insert_many(all_docs)
    return len(STARTER_INCIDENTS)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    force = "--force" in (argv if argv is not None else sys.argv[1:])
    n = seed_default_incidents(force_reseed=force)
    total = incident_logs_collection().count_documents({})
    if n:
        print(f"Ingested {n} starter incidents ({total} chunk documents in incident_logs).")
    else:
        print(f"incident_logs already populated ({total} documents); nothing ingested. Use --force to reseed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
