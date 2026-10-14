"""Shared fictional environment for all scenario packs.

Company: Contoso Bank (fictional). All IPs use reserved documentation ranges:
  198.51.100.0/24  -> Contoso egress / VPN (trusted)
  192.0.2.0/24     -> benign external SaaS
  203.0.113.0/24   -> attacker / malicious infrastructure
Domains ending in .example are reserved and never resolve on the internet.
"""

from datetime import datetime, timezone

AD_DOMAIN = "corp.contoso.local"
EMAIL_DOMAIN = "contoso.com"

# "Yesterday" for every scenario; analysts ask questions on 2026-10-14.
BASE_DATE = datetime(2026, 10, 13, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)

CORP_EGRESS_IP = "198.51.100.10"
CORP_VPN_IP = "198.51.100.20"

NETWORK = {
    "corp_egress": {"ip": CORP_EGRESS_IP, "country": "GB", "city": "London", "owner": "Contoso Bank"},
    "corp_vpn": {"ip": CORP_VPN_IP, "country": "GB", "city": "London", "owner": "Contoso Bank"},
    "internal_ranges": {
        "10.0.0.0/24": "Tier 0 - domain controllers",
        "10.0.1.0/24": "Servers",
        "10.0.2.0/24": "Admin jump hosts",
        "10.10.5.0/24": "User workstations",
    },
    "benign_external_range": "192.0.2.0/24",
    "attacker_range_note": "203.0.113.0/24 is used for all malicious infrastructure in scenarios",
}

# sam, display name, title, department, workstation, groups, manager, privileged, account type
_USERS = [
    ("j.smith", "John Smith", "Finance Analyst", "Finance", "WS-031", ["Finance-Users"], "r.okafor", False),
    ("s.khan", "Sara Khan", "Accounts Payable Clerk", "Finance", "WS-042", ["Finance-Users"], "r.okafor", False),
    ("p.garcia", "Pablo Garcia", "Treasury Analyst", "Treasury", "WS-044", ["Treasury-Users"], "r.okafor", False),
    ("k.osei", "Kwame Osei", "Relationship Manager", "Retail Banking", "WS-036", ["Retail-Users"], "f.rossi", False),
    ("a.patel", "Anika Patel", "Endpoint Engineer", "IT", "WS-015",
     ["IT-Admins", "SCCM-Operators", "Workstation-Admins"], "d.wright", True),
    ("r.okafor", "Ruth Okafor", "Finance Director", "Finance", "WS-007", ["Finance-Users", "Finance-Approvers"], None, False),
    ("m.chen", "Michael Chen", "Facilities Coordinator", "Facilities", "WS-058", ["Facilities-Users"], "c.dubois", False),
    ("e.moreau", "Elise Moreau", "Risk Analyst", "Risk", "WS-023", ["Risk-Users"], "f.rossi", False),
    ("t.berg", "Tomas Berg", "Marketing Specialist", "Marketing", "WS-019", ["Marketing-Users"], "c.dubois", False),
    ("l.nguyen", "Linh Nguyen", "Data Analyst", "Risk", "WS-033", ["Risk-Users"], "f.rossi", False),
    ("d.wright", "Daniel Wright", "Infrastructure Lead", "IT", "WS-002", ["Domain Admins", "IT-Admins"], None, True),
    ("h.ali", "Hamza Ali", "SOC Analyst L2", "Security", "WS-090", ["SOC-Analysts"], "d.wright", False),
    ("b.ito", "Bea Ito", "Procurement Officer", "Procurement", "WS-061", ["Procurement-Users"], "r.okafor", False),
    ("c.dubois", "Claire Dubois", "HR Business Partner", "HR", "WS-050", ["HR-Users"], None, False),
    ("f.rossi", "Franco Rossi", "Compliance Officer", "Compliance", "WS-047", ["Compliance-Users"], None, False),
    ("g.mensah", "Grace Mensah", "Payments Operations", "Payments", "WS-012", ["Payments-Users"], "r.okafor", False),
    ("n.sato", "Naomi Sato", "Payments Operations", "Payments", "WS-013", ["Payments-Users"], "r.okafor", False),
    ("o.brien", "Owen Brien", "Software Developer", "Engineering", "WS-070", ["Engineering-Users"], "d.wright", False),
    ("i.kowalski", "Iga Kowalski", "Credit Analyst", "Risk", "WS-080", ["Risk-Users"], "f.rossi", False),
    ("q.ahmed", "Qasim Ahmed", "Branch Manager", "Retail Banking", "WS-081", ["Retail-Users"], "f.rossi", False),
    ("v.silva", "Vera Silva", "Legal Counsel", "Legal", "WS-082", ["Legal-Users"], None, False),
    ("w.johnson", "Will Johnson", "Trader", "Markets", "WS-083", ["Markets-Users"], None, False),
    ("y.park", "Yuna Park", "Product Owner", "Engineering", "WS-084", ["Engineering-Users"], "d.wright", False),
    ("z.haddad", "Zain Haddad", "Auditor", "Internal Audit", "WS-085", ["Audit-Users"], None, False),
    ("u.adeyemi", "Uche Adeyemi", "Customer Service Lead", "Retail Banking", "WS-086", ["Retail-Users"], "q.ahmed", False),
    ("ja.morales", "Javier Morales", "Payments Analyst", "Payments", "WS-087", ["Payments-Users"], "r.okafor", False),
]

_SERVICE_ACCOUNTS = [
    ("svc-backup", "Backup service", "BKP01", ["Backup Operators"], "d.wright",
     "Runs nightly backup jobs on BKP01. Interactive logon not expected."),
    ("svc-sccm", "SCCM service", "SCCM01", ["SCCM-Operators"], "a.patel", "Software deployment service account."),
    ("svc-legacyapp", "Legacy payments app", "APP02", ["App-Service-Accounts"], "o.brien",
     "Service account for legacy payments app on APP02."),
]

SERVERS = [
    ("DC01", "10.0.0.10", "Domain controller", "tier0", "critical"),
    ("DC02", "10.0.0.11", "Domain controller", "tier0", "critical"),
    ("FS01", "10.0.1.20", "File server", "tier1", "high"),
    ("SQL01", "10.0.1.30", "Payments database", "tier1", "critical"),
    ("APP02", "10.0.1.42", "Legacy payments application", "tier1", "high"),
    ("BKP01", "10.0.1.50", "Backup server", "tier1", "high"),
    ("SCCM01", "10.0.1.60", "Software deployment (SCCM)", "tier1", "high"),
    ("JUMP01", "10.0.2.5", "Admin jump host", "tier0", "critical"),
]


def ws_ip(host: str) -> str:
    return f"10.10.5.{int(host.split('-')[1])}"


def _build():
    users, hosts = {}, {}
    for sam, name, title, dept, ws, groups, manager, priv in _USERS:
        users[sam] = {
            "sAMAccountName": sam,
            "userPrincipalName": f"{sam}@{EMAIL_DOMAIN}",
            "displayName": name,
            "title": title,
            "department": dept,
            "office": "London",
            "country": "GB",
            "manager": manager,
            "memberOf": groups + ["All-Staff"],
            "accountType": "user",
            "privileged": priv,
            "enabled": True,
            "mfaRegistered": True,
            "primaryWorkstation": ws,
            "description": "",
        }
        hosts[ws] = {
            "hostname": ws, "ip": ws_ip(ws), "type": "workstation", "os": "Windows 11 23H2",
            "owner": sam, "department": dept, "tier": "tier2", "criticality": "medium",
            "edr_agent": "online",
        }
    for sam, name, host, groups, owner, desc in _SERVICE_ACCOUNTS:
        users[sam] = {
            "sAMAccountName": sam, "userPrincipalName": f"{sam}@{AD_DOMAIN}", "displayName": name,
            "title": "Service account", "department": "IT", "office": None, "country": None,
            "manager": owner, "memberOf": groups, "accountType": "service", "privileged": True,
            "enabled": True, "mfaRegistered": False, "primaryWorkstation": host, "description": desc,
        }
    for name, ip, role, tier, crit in SERVERS:
        hosts[name] = {
            "hostname": name, "ip": ip, "type": "server", "os": "Windows Server 2022",
            "owner": "d.wright", "role": role, "tier": tier, "criticality": crit, "edr_agent": "online",
        }
    groups = {}
    for u in users.values():
        for g in u["memberOf"]:
            groups.setdefault(g, {"name": g, "members": []})["members"].append(u["sAMAccountName"])
    groups["All-Staff"]["type"] = "distribution"
    groups["All-Staff"]["member_count"] = 512  # whole bank; only a sample is modelled as users
    groups["All-Staff"]["email"] = f"all-staff@{EMAIL_DOMAIN}"
    for g in ("Domain Admins", "Backup Operators", "IT-Admins"):
        groups[g]["privileged"] = True
    return users, hosts, groups


USERS, HOSTS, GROUPS = _build()

BENIGN_DOMAINS = [
    ("login.microsoftonline.com", "192.0.2.11"), ("outlook.office365.com", "192.0.2.12"),
    ("teams.microsoft.com", "192.0.2.13"), ("contoso.sharepoint.com", "192.0.2.14"),
    ("www.bbc.co.uk", "192.0.2.21"), ("github.com", "192.0.2.22"), ("www.ft.com", "192.0.2.23"),
    ("www.reuters.com", "192.0.2.24"), ("update.googleapis.com", "192.0.2.25"),
    ("intranet.contoso.local", "10.0.1.80"),
]
