"""Event builder: produces SIEM / EDR events in one normalised (ECS-style) schema.

Events can carry an internal `_key` so scenarios can reference them as evidence;
keys are resolved to final event IDs in `finalize()` and stripped from the output.
"""

import hashlib
import random
from datetime import datetime, timedelta

from env import BASE_DATE, BENIGN_DOMAINS, CORP_EGRESS_IP, HOSTS, USERS


def at(hh: int, mm: int, ss: int = 0, day: int = 0) -> datetime:
    return BASE_DATE + timedelta(days=day, hours=hh, minutes=mm, seconds=ss)


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def sha256(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


# Well-known benign binaries share one hash across all scenarios.
BIN = {
    "explorer.exe": r"C:\Windows\explorer.exe",
    "OUTLOOK.EXE": r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    "WINWORD.EXE": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "EXCEL.EXE": r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    "chrome.exe": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "msedge.exe": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "ms-teams.exe": r"C:\Program Files\WindowsApps\MSTeams\ms-teams.exe",
    "powershell.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "rundll32.exe": r"C:\Windows\System32\rundll32.exe",
    "wscript.exe": r"C:\Windows\System32\wscript.exe",
    "cmd.exe": r"C:\Windows\System32\cmd.exe",
    "ntdsutil.exe": r"C:\Windows\System32\ntdsutil.exe",
    "mstsc.exe": r"C:\Windows\System32\mstsc.exe",
    "svchost.exe": r"C:\Windows\System32\svchost.exe",
    "OneDrive.exe": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
}


class Recorder:
    def __init__(self, code: str, seed: int):
        self.code = code
        self.rnd = random.Random(seed)
        self.siem: list[dict] = []
        self.edr: list[dict] = []
        self._pid = 3000 + self.rnd.randint(0, 2000)
        self.key_map: dict[str, str] = {}

    # ---------- helpers ----------
    def pid(self) -> int:
        self._pid += self.rnd.randint(8, 600)
        return self._pid

    def _add(self, store, t, dataset, category, action, outcome="success", key=None, **fields):
        ev = {
            "@timestamp": iso(t),
            "event": {"dataset": dataset, "category": category, "action": action, "outcome": outcome},
        }
        for k, v in fields.items():
            if v is not None:
                ev[k] = v
        if key:
            ev["_key"] = key
        store.append(ev)
        return ev

    @staticmethod
    def _host(name):
        h = HOSTS[name]
        return {"name": name, "ip": h["ip"]}

    # ---------- SIEM sources ----------
    def win_logon(self, t, user, host, src_ip, success=True, logon_type=2, key=None, reason=None):
        code = 4624 if success else 4625
        return self._add(self.siem, t, "windows.security", "authentication",
                         "logged-in" if success else "logon-failed", "success" if success else "failure", key,
                         host=self._host(host), user={"name": user}, source={"ip": src_ip},
                         winlog={"event_id": code, "logon_type": logon_type},
                         message=reason)

    def win_logoff(self, t, user, host, key=None):
        return self._add(self.siem, t, "windows.security", "authentication", "logged-off", "success", key,
                         host=self._host(host), user={"name": user}, winlog={"event_id": 4634})

    def group_change(self, t, actor, target, group, actor_host, key=None):
        return self._add(self.siem, t, "windows.security", "iam", "added-member-to-group", "success", key,
                         host=self._host("DC01"), user={"name": actor, "target": {"name": target}},
                         group={"name": group}, source={"ip": HOSTS[actor_host]["ip"]},
                         winlog={"event_id": 4728})

    def signin(self, t, user, ip, country, success=True, mfa="satisfied", app="Office 365",
               client="Browser", user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0",
               device=None, asn=None, error=None, key=None):
        return self._add(self.siem, t, "azuread.signin", "authentication",
                         "sign-in" if success else "sign-in-failed", "success" if success else "failure", key,
                         user={"name": user, "email": USERS[user]["userPrincipalName"] if user in USERS else user},
                         source={"ip": ip, "geo": {"country_iso_code": country}, "as": {"organization": asn}},
                         azure={"app": app, "client_app": client, "mfa_result": mfa,
                                "device": device or "unregistered", "error_code": error},
                         user_agent={"original": user_agent})

    def mfa(self, t, user, ip, country, result, key=None):
        return self._add(self.siem, t, "azuread.mfa", "authentication", "mfa-push", result, key,
                         user={"name": user}, source={"ip": ip, "geo": {"country_iso_code": country}},
                         azure={"mfa_method": "Authenticator push", "mfa_result": result})

    def email(self, t, sender, to, subject, url=None, attachment=None, verdict="delivered", spam_score=1,
              recipients_count=None, body_excerpt=None, key=None):
        f = {"from": {"address": sender}, "to": {"address": to}, "subject": subject}
        if attachment:
            f["attachments"] = [{"file": {"name": attachment[0], "hash": {"sha256": attachment[1]}}}]
        return self._add(self.siem, t, "email.gateway", "email", verdict, "success", key,
                         email=f, url={"full": url} if url else None,
                         message=body_excerpt,
                         gateway={"spam_score": spam_score, "recipients_count": recipients_count or 1})

    def mailbox(self, t, user, ip, action, details, key=None):
        return self._add(self.siem, t, "o365.audit", "configuration", action, "success", key,
                         user={"name": user}, source={"ip": ip}, o365=details)

    def proxy(self, t, user, host, url, domain, dest_ip, method="GET", allowed=True, category="Business",
              status=200, key=None, bytes_out=None):
        return self._add(self.siem, t, "proxy", "network", "allowed" if allowed else "blocked",
                         "success" if allowed else "failure", key,
                         host=self._host(host), user={"name": user}, source={"ip": HOSTS[host]["ip"]},
                         url={"full": url, "domain": domain}, destination={"ip": dest_ip},
                         http={"request": {"method": method}, "response": {"status_code": status}},
                         proxy={"category": category, "bytes_out": bytes_out})

    def dns(self, t, host, query, answer, key=None):
        return self._add(self.siem, t, "dns", "network", "dns-query", "success", key,
                         host=self._host(host), source={"ip": HOSTS[host]["ip"]},
                         dns={"question": {"name": query}, "answers": [{"data": answer}]})

    def firewall(self, t, src_ip, dst_ip, port, allowed, country=None, key=None):
        return self._add(self.siem, t, "firewall", "network", "allowed" if allowed else "denied",
                         "success" if allowed else "failure", key,
                         source={"ip": src_ip, "geo": {"country_iso_code": country}},
                         destination={"ip": dst_ip, "port": port}, network={"transport": "tcp"})

    # ---------- EDR telemetry ----------
    def proc(self, t, host, user, name, cmd, ppid, pname, pid=None, path=None, sha=None, signed=True,
             key=None):
        pid = pid or self.pid()
        self._add(self.edr, t, "edr.process", "process", "process-start", "success", key,
                  host=self._host(host), user={"name": user},
                  process={"pid": pid, "name": name, "executable": path or BIN.get(name, name),
                           "command_line": cmd, "hash": {"sha256": sha or sha256(name)},
                           "code_signature": {"trusted": signed},
                           "parent": {"pid": ppid, "name": pname}})
        return pid

    def net(self, t, host, user, pid, pname, dst_ip, port, domain=None, key=None):
        return self._add(self.edr, t, "edr.network", "network", "connection-attempted", "success", key,
                         host=self._host(host), user={"name": user},
                         process={"pid": pid, "name": pname},
                         destination={"ip": dst_ip, "port": port, "domain": domain})

    def file(self, t, host, user, pid, pname, path, sha, action="file-created", key=None):
        return self._add(self.edr, t, "edr.file", "file", action, "success", key,
                         host=self._host(host), user={"name": user}, process={"pid": pid, "name": pname},
                         file={"path": path, "hash": {"sha256": sha}})

    def registry(self, t, host, user, pid, pname, reg_key, value, data, key=None):
        return self._add(self.edr, t, "edr.registry", "registry", "registry-value-set", "success", key,
                         host=self._host(host), user={"name": user}, process={"pid": pid, "name": pname},
                         registry={"key": reg_key, "value": value, "data": data})

    def device(self, t, host, user, action, details, key=None):
        return self._add(self.edr, t, "edr.device", "host", action, "success", key,
                         host=self._host(host), user={"name": user}, device=details)

    def detection(self, t, host, user, name, severity, technique, pid=None, pname=None, key=None, desc=None):
        return self._add(self.edr, t, "edr.detection", "malware", "detection", "success", key,
                         host=self._host(host), user={"name": user},
                         process={"pid": pid, "name": pname} if pid else None,
                         rule={"name": name, "description": desc},
                         threat={"technique": technique}, severity=severity)

    # ---------- background noise ----------
    def noise(self, start: datetime, end: datetime, n: int, users: list[str] | None = None):
        """Benign activity so agents must separate signal from noise."""
        pool = users or [u for u, d in USERS.items() if d["accountType"] == "user"]
        span = (end - start).total_seconds()
        for _ in range(n):
            t = start + timedelta(seconds=self.rnd.uniform(0, span))
            u = self.rnd.choice(pool)
            host = USERS[u]["primaryWorkstation"]
            kind = self.rnd.choices(
                ["logon", "dns", "proxy", "signin", "proc", "net", "fail"], [2, 4, 4, 2, 3, 3, 1])[0]
            dom, dip = self.rnd.choice(BENIGN_DOMAINS)
            if kind == "logon":
                self.win_logon(t, u, host, HOSTS[host]["ip"], logon_type=self.rnd.choice([2, 3, 7]))
            elif kind == "fail":
                self.win_logon(t, u, host, HOSTS[host]["ip"], success=False, reason="Unknown user name or bad password")
            elif kind == "dns":
                self.dns(t, host, dom, dip)
            elif kind == "proxy":
                self.proxy(t, u, host, f"https://{dom}/", dom, dip)
            elif kind == "signin":
                self.signin(t, u, CORP_EGRESS_IP, "GB", device=host, asn="Contoso Bank")
            elif kind == "proc":
                name = self.rnd.choice(["chrome.exe", "OUTLOOK.EXE", "ms-teams.exe", "EXCEL.EXE", "OneDrive.exe"])
                self.proc(t, host, u, name, f'"{BIN[name]}"', 4120, "explorer.exe")
            else:
                name = self.rnd.choice(["chrome.exe", "ms-teams.exe", "OUTLOOK.EXE"])
                self.net(t, host, u, self.pid(), name, dip, 443, dom)

    # ---------- output ----------
    def finalize(self):
        for prefix, store in (("SIEM", self.siem), ("EDR", self.edr)):
            store.sort(key=lambda e: e["@timestamp"])
            for i, ev in enumerate(store, 1):
                eid = f"{self.code}-{prefix}-{i:05d}"
                ev["event"]["id"] = eid
                k = ev.pop("_key", None)
                if k:
                    if k in self.key_map:
                        raise ValueError(f"duplicate evidence key {k} in {self.code}")
                    self.key_map[k] = eid

    def ids(self, keys: list[str]) -> list[str]:
        missing = [k for k in keys if k not in self.key_map]
        if missing:
            raise KeyError(f"{self.code}: unknown evidence keys {missing}")
        return [self.key_map[k] for k in keys]
