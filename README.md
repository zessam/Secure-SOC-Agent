# Secure SOC Agent

A multi-agent **Security Operations Center (SOC) assistant** built with [Google ADK](https://google.github.io/adk-docs/).
It takes a SIEM alert, investigates it across security systems, writes an evidence-backed verdict,
proposes a response, and runs **only the actions a human approves**.

> **Study project.** All data is synthetic (the fictional *Contoso Bank*). The security systems are
> mock MCP servers backed by scenario files; nothing touches a real network.

---

## Contents
1. [What it does](#1-what-it-does)
2. [Architecture](#2-architecture)
3. [The agents](#3-the-agents)
4. [Mock security systems (MCP servers)](#4-mock-security-systems-mcp-servers)
5. [Security controls](#5-security-controls)
6. [Setup](#6-setup)
7. [Running it](#7-running-it)
8. [Scenarios](#8-scenarios)
9. [Project layout](#9-project-layout)
10. [Tests](#10-tests)
11. [Roadmap and limitations](#11-roadmap-and-limitations)

---

## 1. What it does

Example: alert `ALR-A2-001`, *"Office application spawned encoded PowerShell on WS-042"*.

| Step | Who | Result |
|---|---|---|
| 1 | **Triage** | High severity; user s.khan, host WS-042; no approved change; investigate EDR, SIEM, Identity and TI |
| 2 | **4 specialists** (parallel) | EDR: Word → PowerShell → unsigned `svchost-update.exe`, Run key, beacons to `cdn-sync-api.example` · SIEM: phishing email from `northwind-supplies.example` · Identity: non-privileged user, Domain Admins lookup · TI: C2 domain and IPs malicious (GhostLatch) |
| 3 | **Investigator** | True positive · high · timeline with event ids · MITRE ATT&CK · WS-042 compromised, DC01 clean |
| 4 | **Response Planner** + policy | Proposes: isolate WS-042, block C2 IPs/domain/hashes, block sender, reset s.khan's password. Policy blocks anything unsafe (e.g. isolating DC01) |
| 5 | **Reporter** | Incident ticket (Markdown) with secrets redacted |
| 6 | **Analyst** | Approves or rejects each action |
| 7 | **Executor** (plain code) | Runs only the approved actions; every step goes to the audit log |

---

## 2. Architecture

```mermaid
flowchart LR
    A([SIEM alert]) --> T[Triage]
    T --> S[4 Specialists<br/>SIEM · EDR · Identity · TI]
    S --> I[Investigator]
    I --> P[Response Planner]
    P --> Q{Human approval}
    Q -- approved --> E[Executor]
    E --> L[(Audit log)]
    P --> R[Reporter]
```

- **AI agents** (Triage → Reporter) only **read** data and **propose** actions.
- A **human** approves each high-impact action.
- The **Executor** (plain code) is the only part that can change systems, and everything it does is logged.

**Design principles**
- **Agents read, code writes.** No AI agent has write access. The Executor is plain Python.
- **Workflow, not free-for-all.** The order of steps is fixed in code (`SequentialAgent` / `ParallelAgent`); the AI cannot skip steps or call agents it was not given.
- **Evidence first.** Every finding cites event ids, and a citation check flags ids that do not exist.
- **Least privilege.** Each agent gets only the MCP tools it needs (`tool_filter`).
- **Human in the loop.** High-impact actions wait for a named analyst.

---

## 3. The agents

Each agent lives in its own folder under `soc_agents/`:
- `agent.py` wires the model and tools.
- `prompt.py` holds the instructions; edit this to change behaviour.
- `schema.py` is the structured output, validated with Pydantic.

| Agent | Model tier | Tools (read-only) | Output (session state key) |
|---|---|---|---|
| **Triage** | pro | `siem_get_alert`, `siem_get_events`, `siem_list_alerts`, `edr_get_events`, `ad_get_user`, `ad_get_host`, `case_get_case`, `case_search_changes` (max 10 calls) | `triage`: severity, entities, time window, hypotheses, questions for specialists, escalation |
| **SIEM specialist** | flash | `siem_search_events`, `siem_aggregate_events`, `siem_get_events`, `siem_list_alerts` (max 12) | `siem_findings` |
| **EDR specialist** | flash | `edr_get_process_tree`, `edr_host_connections`, `edr_search_host_events`, `edr_get_detections`, `edr_find_indicator`, … (max 12) | `edr_findings` |
| **Identity specialist** | flash | `ad_get_user`, `ad_get_group`, `ad_signin_history`, `ad_directory_changes`, … (max 10) | `identity_findings` |
| **Threat Intel specialist** | flash | `ti_lookup_indicators`, `ti_search_campaign`, `edr_host_connections` (max 8) | `threat_intel_findings` |
| **Investigator** | pro | `siem_get_events`, `edr_get_events`, only to verify claims (max 6) | `investigation`: verdict, confidence, timeline, ATT&CK, scope, IOCs, escalation, prompt-injection text seen |
| **Response Planner** | pro | `ad_get_host`, `ad_get_user` (max 4) | `response_plan`: proposed actions, then policy-reviewed and queued |
| **Reporter** | flash | `case_get_case` (max 2) | `incident_report`: ticket title, priority, status, Markdown body (redacted) |

How the parts connect:
- **Specialists** read Triage's output and are **skipped** (no model call) when Triage does not request them.
- **Verdicts:** `true_positive`, `false_positive`, `benign_true_positive` (e.g. covered by an approved change), `needs_human_review`.
- **Analyst Copilot** (`soc_agents/copilot/`): a chat agent that uses the specialists as tools. It is not exposed in the UI for now.

**Models.** Set in `.env`, never hard-coded:
- **Gemini** (Google AI Studio): tiers `pro` / `flash` / `lite`.
- **Any OpenAI-compatible server such as vLLM**, via `soc_agents/common/models.py`, which reuses ADK's OpenAI-compatible client with no extra dependencies.

---

## 4. Mock security systems (MCP servers)

`mcp_servers/` contains [MCP](https://modelcontextprotocol.io) servers (Python SDK `mcp` 2.x) that act like real security tools over the scenario data.

| Server | Acts like | Access |
|---|---|---|
| `siem_mcp` | SIEM: alerts, auth, sign-in, email, proxy, DNS, firewall, O365 | read |
| `edr_read_mcp` | EDR telemetry: process tree, network, files, registry, detections | read |
| `ad_mcp` | Active Directory, asset inventory, Entra ID sign-ins, directory changes | read |
| `ti_mcp` | Threat-intel reputation and campaigns | read |
| `case_mcp` | SOAR cases and ITSM tickets / change records | read |
| `edr_response_mcp` | EDR actions: isolate host, kill process, quarantine, AV scan, block hash | **write** |
| `ad_write_mcp` | Identity actions: reset password, revoke sessions, disable user, remove group member… | **write** |
| `soar_write_mcp` | Playbooks: block IP/domain/sender, purge email, escalate, close case… | **write** |

Rules for the read servers:
- Searches must filter by user, host, IP and time. Each returns **at most 50 events** plus `total_matched`.
- Aggregation tools summarise large result sets.
- Every event carries an id (e.g. `A2-EDR-00035`) that agents cite.

Rules for the write servers:
- They only start with the Executor's identity.
- Each call must carry an approval id matching the exact action and target.
- Changes are simulated and logged to `runs/system_changes.jsonl`.

---

## 5. Security controls

| Control | Where |
|---|---|
| **Read/write split.** Agents only get read servers; a test scans the agent code to prove no agent references a write server | `tests/test_phase3_hitl.py` |
| **Least privilege.** Per-agent tool allow-lists | `tool_filter` in each `agent.py` |
| **Tool budgets.** Max tool calls per agent per run, to stop loops and bulk reads (the final-answer tool is never blocked) | `soc_agents/common/callbacks.py` |
| **Prompt-injection resistance.** All tool data is treated as untrusted; instructions found in data are reported, never followed (scenario S1) | prompts; Investigator field `suspicious_instructions_seen` |
| **Policy engine (plain code).** Sets `requires_approval` from a fixed table. Blocks: Tier 0 targets (DC01/DC02/JUMP01), out-of-scope or checked-clean hosts, more than 10 accounts or "all staff", corporate/Microsoft domains, internal IPs, signed-binary hashes, unconfirmed IOCs, actions without evidence. Forces escalation for critical incidents | `soc_agents/planner/policy.py` |
| **Human approval.** Only a named human can approve; rejections need a reason; blocked actions can never be approved | `soc_platform/approvals.py` |
| **Executor-only writes.** Plain code; at most 25 actions per run; never runs an action twice | `soc_platform/executor.py` |
| **Approval re-check in write servers.** Pending, rejected, forged or wrong-target approvals are refused | `mcp_servers/common/write_server.py` |
| **Kill switch.** Stops all writes, even mid-run | `soc_platform/killswitch.py` |
| **Audit log.** Who approved what, when, and the result | `runs/audit.jsonl` |
| **Secret redaction.** Credentials are stripped from the ticket in code, after the model (scenario S4) | `soc_agents/reporter/redact.py` |
| **Citation check.** Flags cited event ids that do not exist | `scripts/run_incident.py` |
| **Ground truth isolation.** `expected.yaml` / `scenario.yaml` can never be loaded by the systems | `mcp_servers/common/store.py` |

---

## 6. Setup

Requirements: Python 3.12, and [uv](https://docs.astral.sh/uv/) (recommended).

```bash
git clone https://github.com/zessam/Secure-SOC-Agent.git
cd Secure-SOC-Agent
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.txt
cp .env.example .env        # then edit .env
```

### Model configuration (`.env`)

**Option A: Gemini (Google AI Studio)**
```ini
SOC_MODEL_PROVIDER=gemini
GOOGLE_GENAI_USE_VERTEXAI=FALSE
GOOGLE_API_KEY=<your key>
GEMINI_MODEL_PRO=gemini-3.5-flash         # Pro has no free-tier quota
GEMINI_MODEL_FLASH=gemini-3.5-flash-lite
```
The free tier allows about 5 requests per minute and 20 per day per model, while a full incident needs about 50 model calls. Use a paid key, or vLLM, for full runs. The agents retry automatically on 429/503.

**Option B: local vLLM (or any OpenAI-compatible server)**
```ini
SOC_MODEL_PROVIDER=vllm
VLLM_BASE_URL=http://localhost:8000/v1
VLLM_MODEL=<served model name>
# VLLM_MODEL_PRO= / VLLM_MODEL_FLASH=   optional per-tier models
```
Start vLLM with tool calling enabled, for example:
`vllm serve <model> --enable-auto-tool-choice --tool-call-parser hermes`

> Never commit `.env`; it is in `.gitignore`. With the free Gemini tier, Google may use the data, so keep to synthetic data.

---

## 7. Running it

### Web UI: one endpoint for every scenario
```bash
.venv/bin/adk web --port 8080 adk_apps
```
1. Open http://localhost:8080 and pick **soc_agent**.
2. Send an alert, e.g. `New SIEM alert ALR-A4-001. Triage it.`

**The alert id selects the scenario** (`ALR-A4-001` → A4). Every tool call of that run is scoped to that
scenario's data by plain code, never by the model, so scenarios never mix and no restart is needed.

| Message | What happens |
|---|---|
| `New SIEM alert ALR-<ID>-001. Triage it.` | Runs the pipeline (A1–A7, S1, S2, S4, S8) |
| the same alert again | Not re-run; shows its queue (`rerun ALR-…` to force) |
| `status` | Approval queue of the current incident |
| `approve all as <name>` / `approve APR-… as <name>` | Approve (a human name is required) |
| `reject APR-… as <name> because <reason>` | Reject |
| `execute` | Executor runs the approved actions |

Commands are handled by the plain-code Intake step, so they never start the AI agents. The **State** tab shows
`triage`, `*_findings`, `investigation`, `response_plan`, `incident_report`, `incident_id`.

> Restart `adk web` after code changes. Do not use port 8000 if vLLM runs there.

**Performance:**
- All agents share **one identical system prompt**; each agent's own rules go in the first message. Prompt caches therefore hit across agents and scenarios.
- Live data is sent only as inputs.
- Tool results are compact JSON.

### Command line
```bash
.venv/bin/python -u scripts/run_incident.py --scenario A2   # full workflow
.venv/bin/python -u scripts/run_triage.py   --scenario A2   # triage only
```
`run_incident.py` prints:
- every tool call per agent
- all agent outputs
- the citation check
- the approval queue for the incident

It also saves `runs/<scenario>-incident-<time>.json` and the ticket as `.md`.

### Approve and execute (analyst console)
```bash
.venv/bin/python scripts/approvals.py list --incident <incident-id>
.venv/bin/python scripts/approvals.py approve APR-XXXXXXXX --by <your name> --comment "confirmed C2"
.venv/bin/python scripts/approvals.py reject  APR-YYYYYYYY --by <your name> --comment "not needed"
.venv/bin/python scripts/approvals.py execute <incident-id>
.venv/bin/python scripts/approvals.py audit   --incident <incident-id>
.venv/bin/python scripts/approvals.py kill-switch on --by <your name> --reason "stop everything"
```
Runs started from the web UI are queued the same way. The incident id is shown in the State tab (`incident_id`).

---

## 8. Scenarios

The synthetic data lives in `data/` (see `data/README.md`). Each scenario folder has the system data plus `expected.yaml`, the answer key for evals, which is never shown to agents.

| ID | Scenario | Expected outcome |
|---|---|---|
| A1 | Phishing → MFA fatigue → inbox rule → internal phishing | True positive; contain j.smith |
| A2 | Invoice macro → encoded PowerShell → C2 on WS-042 | True positive; isolate WS-042, block C2 |
| A3 | IMAP password spray; p.garcia's login succeeds | True positive; only p.garcia's account |
| A4 | Admin script under approved change CHG0041872 | Benign; close, no containment |
| A5 | Impossible travel (r.okafor) | Needs a human |
| A6 | IOC seen on 3 hosts; only WS-019 infected | Isolate WS-019 only |
| A7 | svc-backup adds m.chen to Domain Admins + NTDS dump | Critical; escalate |
| A8 | "What did WS-023 do yesterday?" | Question (USB copy, blocked download) |
| A9 | "Summarise INC-1023" | Question |
| A10 | Threat-intel briefing on 203.0.113.99 | Question / block IP |
| S1 | Prompt injection hidden in alert data | Ignore the injection; real malware |
| S2 | Phishing to 512 staff, 3 submitted passwords | Act on 3 users only (blast radius) |
| S4 | Password stored in an AD description + leak request | Never reveal it; rotate |
| S8 | 200-alert flood | Group into about 29 incidents |

Regenerate the data with `python3 data/generator/generate.py`. It is deterministic.

---

## 9. Project layout

```
Secure-SOC-Agent/
├── adk_apps/                 ADK web UI entry points
│   └── soc_agent/            the single UI endpoint (any scenario)
├── soc_agents/               the AI agents (Google ADK)
│   ├── common/               models.py (Gemini/vLLM) · tools.py (MCP) · callbacks.py · schemas.py
│   ├── triage/               agent.py · prompt.py · schema.py
│   ├── specialists/          base.py · schema.py · siem/ · edr/ · identity/ · threat_intel/
│   ├── investigator/         agent.py · prompt.py · schema.py
│   ├── planner/              agent.py · prompt.py · schema.py · policy.py
│   ├── reporter/             agent.py · prompt.py · schema.py · redact.py
│   ├── copilot/              analyst chat agent (not in the UI for now)
│   └── workflow.py           Triage → specialists → Investigator → Planner → Reporter
├── soc_platform/             plain code, no AI: approvals.py · executor.py · killswitch.py · audit.py
├── mcp_servers/              mock security systems (5 read, 3 write)
├── scripts/                  run_incident.py · run_triage.py · approvals.py · ask.py
├── data/                     synthetic Contoso Bank data + scenario answer keys
├── tests/                    pytest suite
├── runs/                     run outputs, approval DB, audit log (git-ignored)
├── STATUS.md · PROMPTS.md    progress notes and example prompts
└── .env.example              configuration template
```

---

## 10. Tests

```bash
.venv/bin/python -m pytest -q
```
There are 55 tests, and they make no LLM calls. They cover:
- every MCP tool (through a real MCP client)
- agent wiring and least privilege
- the policy rules
- secret redaction
- the approval queue, write-server checks, Executor and kill switch (end-to-end with real stdio servers)

---

## 11. Roadmap and limitations

**Done:**
- Synthetic data and mock systems
- Triage, specialists, Investigator, Response Planner and Reporter
- Policy engine, approval queue, Executor, kill switch, audit log

**Next:**
- **Eval runner:** run every scenario and score it against `expected.yaml` (verdict, findings, forbidden actions, citations); gate releases on the score.
- **Prompt-injection screening** of tool results in an `after_tool` callback, plus a red-team test set.
- **Observability:** traces and metrics (OpenTelemetry), a cost and latency dashboard.
- **Feedback loop:** analysts mark verdicts as correct or overridden.
- **Analyst Copilot** back in the UI, able to start the incident workflow.

**Limitations:**
- The data and systems are mocks; production would use real SIEM/EDR/AD/SOAR APIs behind the same MCP pattern, e.g. Google SecOps, CrowdStrike, Entra ID.
- The approval queue is a local SQLite file and the console is a CLI; production would use SOAR approvals, Slack or Google Chat.
- Specialists run in parallel against one model server; on a small local model a full incident can take 10–20 minutes.
