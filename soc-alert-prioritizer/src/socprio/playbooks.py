"""First-response checklists shown next to an alert in the dashboard."""

from __future__ import annotations

PLAYBOOKS: dict[str, list[str]] = {
    "Ransomware": [
        "Isolate the host from the network immediately (EDR containment or switch port).",
        "Do not power off - preserve memory for forensics.",
        "Identify the patient-zero process and its parent chain.",
        "Check for shadow copy deletion and lateral spread over SMB.",
        "Escalate to incident response lead and start the IR runbook.",
    ],
    "Malware": [
        "Look up the hash/domain in the sandbox and threat intel results below.",
        "Check EDR telemetry for process tree, persistence and child processes.",
        "Search for the same indicator across all hosts (retro-hunt).",
        "Contain the host if execution is confirmed.",
        "Block the C2 indicators at proxy / firewall / DNS.",
    ],
    "Brute Force": [
        "Confirm whether any attempt from the source succeeded (look for accepted logins).",
        "Check if the targeted accounts are privileged or service accounts.",
        "Block the source IP at the perimeter if it is external.",
        "Reset credentials and enforce MFA if a login succeeded.",
    ],
    "Phishing": [
        "Pull the original message and headers; check SPF/DKIM/DMARC results.",
        "Find every recipient and whether anyone clicked or submitted credentials.",
        "Purge the message from mailboxes and block the sender/URL.",
        "Reset credentials of users who interacted.",
    ],
    "Exploit Attempt": [
        "Verify whether the target runs the vulnerable software/version.",
        "Check the response code and size - did the request succeed?",
        "Review web server and application logs around the timestamp.",
        "Patch or apply a virtual patch (WAF rule) if exposed.",
    ],
    "Data Exfiltration": [
        "Quantify the volume and destination of the transfer.",
        "Identify the user and process responsible.",
        "Check destination reputation and whether it is a sanctioned service.",
        "Involve the data owner / DPO if sensitive data may be affected.",
    ],
    "Privilege Escalation": [
        "Verify whether the privilege change was authorised (change ticket).",
        "Review the account's recent activity and group memberships.",
        "Revoke the elevated rights if unauthorised and reset credentials.",
    ],
    "Lateral Movement": [
        "Map every host the source touched in the time window.",
        "Check for remote service creation, WMI or PsExec artefacts.",
        "Contain the source host and the compromised account.",
    ],
    "Port Scan": [
        "Determine if the source is an approved scanner (vulnerability management).",
        "Check whether the scan was followed by exploitation attempts.",
        "Block external scanners at the perimeter if noisy.",
    ],
    "Suspicious Domain": [
        "Check domain age, registrar and passive DNS history.",
        "Identify which process on the host resolved the domain.",
        "Sinkhole or block the domain if malicious.",
    ],
    "Policy Violation": [
        "Confirm the activity with the user or their manager.",
        "Document and route to the policy owner if repeated.",
    ],
}

DEFAULT = [
    "Review the raw event and enrichment data.",
    "Correlate with other alerts from the same source and destination.",
    "Decide: escalate, monitor, or close with a verdict so the model learns from it.",
]


def playbook_for(alert_type: str) -> list[str]:
    return PLAYBOOKS.get(alert_type, DEFAULT)
