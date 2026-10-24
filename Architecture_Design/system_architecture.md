# TROJAN System Architecture

AI powered cybersecurity platform for SMEs in developing countries.

TROJAN watches an organisation's computers and network, uses AI to spot and explain threats, scans for known weaknesses, and tells a non specialist what to do next. It runs on one on premise server and keeps working when the internet is down.

![TROJAN system architecture](TROJAN_System_Architecture.png)

## Contents

1. [Overview](#1-overview)
2. [Deployment view](#2-deployment-view)
3. [Component view](#3-component-view)
4. [Data flow](#4-data-flow)
5. [Vulnerability scanning subsystem](#5-vulnerability-scanning-subsystem)
6. [Inference API contract](#6-inference-api-contract)
7. [Storage and tenancy](#7-storage-and-tenancy)
8. [Security](#8-security)
9. [Failure and offline behaviour](#9-failure-and-offline-behaviour)
10. [Cloud sync protocol](#10-cloud-sync-protocol)
11. [Resource budget and traceability](#11-resource-budget-and-traceability)
12. [Items to confirm](#12-items-to-confirm)

---

## 1. Overview

TROJAN delivers the four features on the pitch slides through four layers, and every feature keeps working when the internet is down. Each feature can be traced to the components that provide it.

| Slide feature | What the user gets | Components that deliver it | Detail in |
| --- | --- | --- | --- |
| AI Threat Detection | Unusual network activity and likely attacks flagged, scored and explained | Wazuh Manager, Suricata, AI Inference Engine (anomaly detection, triage, response templates) | Sections 3, 4, 6 |
| Vulnerability Scanning | Weaknesses found on each machine before an attacker uses them | Scan orchestrator running Wazuh vulnerability detection, Nmap, Nuclei, Wapiti, OSV-Scanner, OWASP ZAP, Nikto, OpenVAS and SQLMap, with a local CVE feed | Section 5 |
| Offline Monitoring | Monitoring and alerts continue with no internet | Everything inside the client site, plus the store and forward queue for later sync | Sections 9, 10 |
| Security Dashboard | Threats, alerts, scan results and guidance in one place | Web Dashboard, reading from the Wazuh Indexer and the AI engine | Sections 3, 4 |

The slides describe the same system as four stages.

| Stage | What happens | Delivered by |
| --- | --- | --- |
| Monitor | Hosts and network traffic are watched | Endpoint agents, Suricata |
| Detect | Rules, AI and scans find problems | Wazuh rules, AI Inference Engine, scan orchestrator |
| Alert | The user is told, with severity and confidence | Web Dashboard |
| Respond | The user gets plain language steps to follow | Template based guidance attached by the AI engine |

Two scope notes. Cloud sync is design only in the 7 week prototype, so only its message formats and rules are specified here (Section 10). Vulnerability Scanning was not in the earlier architecture; it is added here to match the slides, and its place in the 7 week plan needs confirming, since building nine tool adapters is a lot for 7 weeks.

## 2. Deployment view

The whole platform runs on one on premise server, and only the agent and dashboard ports are open to the office network.

```text
OFFICE NETWORK                          TROJAN SERVER (8 GB RAM, 16 GB advised with OpenVAS)
+--------------------+                  +----------------------------------------------+
| Monitored hosts    |--- 1514 TCP ---> | Wazuh Manager --> AI Inference Engine        |
| (Wazuh agent)      |                  | Suricata -------> Wazuh Indexer              |
| Network switch     |--- mirror -----> | Scan orchestrator --> Platform backend       |
| Staff computers    |--- 443 HTTPS --> | Web Dashboard <-----> Platform backend       |
| Approved targets   |<-- scans ------- | PostgreSQL, Redis, files on disk             |
+--------------------+                  | Sync client (optional) - - -> Cloud          |
                                        +----------------------------------------------+
```

Monitored hosts send events to the Wazuh Manager on port 1514, staff reach the dashboard on port 443, and the network switch copies traffic to Suricata through a mirror port or tap. The scan orchestrator reaches out over the network to scan approved ranges and websites. Every other link stays inside the server. Section 4 lists each hop and Section 8 lists every port. The dashed link to the cloud is optional and works only when the internet does.

## 3. Component view

Ten components make up the platform, and each has one job, one technology and one defined connection to its neighbours. Only the agent runs on the monitored machines; everything else runs on the single on premise server.

| Component | Job | Technology | Receives from | Sends to |
| --- | --- | --- | --- | --- |
| Endpoint agent | Collect logs, file changes, running processes, connection data | Wazuh agent | The host it sits on | Wazuh Manager, port 1514 TCP |
| Wazuh Manager | Correlate events, apply detection rules, enrol agents, forward flagged events | Wazuh Manager with a custom integration script | Agents, Suricata log | Wazuh Indexer, AI Inference Engine |
| Suricata | Watch network traffic and analyse protocols | Suricata on a mirror port or tap | Copy of network traffic | Wazuh Manager, through its EVE JSON log |
| Wazuh Indexer | Store and search events and alerts | Wazuh Indexer | Wazuh Manager | Dashboard backend |
| Vulnerability scanner | Find known weaknesses and open services | Scan orchestrator with adapters for Wazuh, Nmap, Nuclei, Wapiti, OSV-Scanner, ZAP, Nikto, OpenVAS, SQLMap | Agent software lists, approved network ranges, website URLs | Platform backend |
| AI Inference Engine | Anomaly detection, alert triage, response templates | Python service, TensorFlow Lite or ONNX Runtime | Wazuh Manager integration | Platform backend |
| Platform backend | Authentication, tenancy, incidents, scan results, API for the dashboard | FastAPI, PostgreSQL, Redis | AI engine, scanner, Indexer | Dashboard, sync client |
| Web Dashboard | Show alerts, scan findings, guidance and settings | React with Next.js | Platform backend | The user |
| Template library | Twenty plain language playbooks plus a manual investigation fallback | Versioned files read by the AI engine | Maintained by the team | AI engine |
| Sync client (optional) | Queue and exchange data with the cloud | Store and forward queue | Platform backend, cloud | Cloud, platform backend |

The agent does no AI work. Keeping all inference on the server means models are updated in one place and the agent stays under 100 MB of RAM and 2 percent of CPU. The template library is separate from the engine code so playbooks can be edited without retraining or redeploying a model.

## 4. Data flow

Data moves through eight hops across the four stages Monitor, Detect, Alert and Respond, and every hop stays inside the client site.

| Hop | Stage | From to | Transport | Payload |
| --- | --- | --- | --- | --- |
| 1 | Monitor | Agent to Wazuh Manager | Port 1514 TCP, encrypted by Wazuh | Batches of host events |
| 2 | Monitor | Suricata to Wazuh Manager | Manager reads Suricata's EVE JSON log on the same server | One JSON line per flow or network alert |
| 3 | Detect | Wazuh Manager to Wazuh Indexer | Local, TLS | Every event and every alert |
| 4 | Detect | Wazuh Manager to AI Inference Engine | HTTP REST with JSON on the local server | Alert requests and flow window requests (Section 6) |
| 5 | Detect | Vulnerability scanner to Platform backend | Internal REST | Findings: host, software or port, CVE identifier, severity |
| 6 | Detect | AI Inference Engine to Platform backend | Internal REST | Result: category, severity, confidence, playbook identifier |
| 7 | Alert | Platform backend to Dashboard | HTTPS, with WebSocket for live updates | Incidents and findings |
| 8 | Respond | Dashboard to Platform backend | HTTPS | Acknowledge, resolve, add a note |

The AI engine receives two kinds of request. An alert request carries one event that a Wazuh rule has already flagged, so the engine can triage it and attach a playbook. A window request carries a summary of recent network flows from Suricata, so the anomaly detector can catch behaviour that no rule describes. Both are answered within the 100 millisecond target per flow window.

The platform backend stores each result as an incident in PostgreSQL and keeps the raw evidence in the Wazuh Indexer, linked by event identifier. Redis carries live updates to the dashboard and caches frequent lookups; it holds nothing that cannot be rebuilt. When the AI engine cannot match a threat to one of the twenty playbooks, the incident carries the manual investigation template instead, so no alert reaches the dashboard without guidance.

### Worked example: a password guessing attack

1. At 2am an attacker's script tries hundreds of passwords against the accounting server. The Wazuh agent on that server reports every failed login (hop 1).
2. The Wazuh Manager's rule for many failed logins from one address fires. Suricata also sees a flood of connections from the same address (hop 2).
3. The Manager sends the flagged event to the AI engine (hop 4). The engine scores it as far outside this site's normal pattern, classifies it as `brute_force`, sets severity high with confidence 0.94, and attaches the matching playbook (hop 6).
4. In the morning the IT person opens the dashboard (hop 7) and sees the alert, a plain explanation, and the fix: block the address, reset the targeted account, check whether any attempt succeeded, and turn on lockout. They acknowledge it when done (hop 8).

## 5. Vulnerability scanning subsystem

Vulnerability scanning runs on the server, with several tools sharing one scan queue, so the monitored machines carry no extra load and everything except scanning an internet hosted website works offline.

| Scope | Tools | What they find |
| --- | --- | --- |
| Host | Wazuh vulnerability detection | Outdated or known vulnerable software on servers and workstations, from the software list each agent already reports |
| Network | Nmap, OpenVAS | Live hosts, open ports, service versions, and with OpenVAS full network vulnerability scans |
| Web application | Wapiti, Nuclei, OWASP ZAP, Nikto, SQLMap | Injection and cross site scripting flaws, known vulnerabilities, misconfigurations, web server weaknesses |
| Dependencies | OSV-Scanner | Libraries with known vulnerabilities in software the client builds in house |

**Host scanning.** Wazuh vulnerability detection compares the software list that each agent already reports against a CVE feed stored on the server. It finds outdated or known vulnerable software on servers and workstations without scanning them over the network.

**Network scanning.** A scheduler runs Nmap over the address ranges the administrator has approved, by default once a week outside working hours. Each run records live hosts, open ports and service versions. The service versions are matched against the same local CVE feed, and the result is compared with the previous run so that a new device or a newly opened port is reported as a finding in its own right.

**Web application scanning.** For a website the client owns, whether it runs on the office network or on the internet, the administrator enters the URL in the dashboard and confirms they are allowed to test it. Wapiti crawls the site and tests its forms and parameters for flaws such as injection and cross site scripting, and Nuclei checks it against a library of known vulnerabilities and misconfigurations. Scanning a site hosted on the internet needs the internet; a site on the local network does not.

**Dependency scanning.** For software the client builds in house, OSV-Scanner reads the project's dependency files from a folder the administrator points it at and reports libraries with known vulnerabilities.

**Adapters and the scan queue.** Each tool sits behind a small adapter that turns its output into the common finding record below, so the dashboard never needs to know which tool found what. Scans run one at a time from a queue, scheduled outside working hours or started on demand, and each job has a memory limit so the Wazuh Manager and the AI engine keep their share of the server.

**CVE feed and offline use.** The feed is refreshed whenever internet access is available and kept on the server. With no connection the scanner keeps using the last copy, and the dashboard shows how old the feed is so the user knows how current the findings are.

**Findings.** Every tool produces the same record: host, affected software or port, CVE identifier, severity, first seen date and status. The platform backend stores it and the dashboard lists it beside the alerts. Each finding type carries a plain language fix from the template library, for example update a named package or close a port.

**Safety limits.** The scanner only touches ranges and websites the administrator has approved, limits Nmap's intensity so fragile devices such as printers and routers are not disrupted, and logs every run with who approved it.

**Heavier and riskier tools.** OWASP ZAP does deeper web scanning, Nikto checks web servers, OpenVAS runs full network vulnerability scans, and SQLMap tests for injection. OpenVAS is the heaviest, so it only runs when no other scan is running, and it is the reason a 16 GB server is recommended. SQLMap attacks the target in order to test it and can change data, so it needs the administrator's separate approval for every run and is never scheduled.

## 6. Inference API contract

The AI engine exposes one analysis call and two status calls, and version 1 is frozen at the end of Week 2 so the AI engineer and the lead developer can build against it in parallel. After the freeze only new optional fields may be added; nothing may be renamed, removed or made required.

| Call | Purpose |
| --- | --- |
| `POST /v1/analyze` | Score one alert or one flow window and return category, severity, confidence and playbook |
| `GET /v1/health` | Report whether the engine is ready and which model versions are loaded |
| `GET /v1/models` | List each model with its version and training dataset |

A request for an alert that a Wazuh rule has flagged:

```json
{
  "request_id": "c91f0a52",
  "schema_version": 1,
  "org_id": "org_0007",
  "kind": "alert",
  "timestamp": 1792634591,
  "source": { "agent_id": "agent_003", "hostname": "accounts_server" },
  "alert": {
    "rule_id": 5712,
    "rule_level": 10,
    "description": "Multiple failed logins from one address",
    "src_ip": "203.0.113.45",
    "event_count": 412
  }
}
```

A flow window request has `"kind": "window"` and a `window` object in place of `alert`. The window object holds the start and end time and a list of flow summaries, each with source and destination address, protocol, bytes, packets and duration.

The response, returned within the 100 millisecond target:

```json
{
  "request_id": "c91f0a52",
  "category": "brute_force",
  "severity": "high",
  "confidence": 0.94,
  "anomaly_score": 0.88,
  "playbook_id": "pb_brute_force",
  "model_version": "bilstm_1.0",
  "latency_ms": 41
}
```

Severity is one of low, medium, high or critical. Confidence runs from 0 to 1. A threat that matches none of the twenty categories returns the category `unknown` and the playbook `pb_manual_investigation`.

| Status | Meaning | Caller behaviour |
| --- | --- | --- |
| 200 | Analysed | Use the result |
| 400 | Payload is not valid JSON or misses a required field | Log and drop, do not retry |
| 422 | Unsupported schema version | Log and drop, raise a configuration alert |
| 503 | Models still loading or engine overloaded | Retry with increasing delay, then queue the event locally |

The Wazuh Manager integration treats a failed call as non fatal: the rule based alert still reaches the dashboard, marked as not yet scored by the AI, and is re scored when the engine recovers.

## 7. Storage and tenancy

Three stores hold the data, each for one purpose, and every record carries an organisation identifier so one client's data can never appear in another's view.

| Data | Where | Kept for |
| --- | --- | --- |
| Raw events | Wazuh Indexer | 30 days, then reduced to daily summaries and purged |
| Alerts and incident reports | Wazuh Indexer and PostgreSQL | 12 months |
| Vulnerability findings | PostgreSQL | 12 months |
| Organisations, users, roles, agents, playbook versions, audit log | PostgreSQL | While in use, audit log 12 months |
| Live update channel and cache | Redis | Short lived, rebuildable |
| Models, template library, CVE feed snapshot, sync queue files | Server disk | Latest versions, queue until acknowledged |

The administrator can change every retention period. The server's 100 GB of storage is the limit these periods must fit inside, and the dashboard warns when disk use passes a threshold the administrator sets.

**Tenancy.** A tenant is one client organisation. Every PostgreSQL table has an organisation column, and row level security policies make the database itself refuse any query that does not match the organisation of the logged in user, so a bug in application code cannot leak data across clients. In the Wazuh Indexer each organisation has its own set of indices and its own role, and agents enrol into a Wazuh group named for their organisation.

**Roles.**

| Role | Can do |
| --- | --- |
| Administrator | Manage users, settings, retention and scan approvals for one organisation |
| Analyst | View and acknowledge alerts and findings |
| Viewer | Read access only |
| Consultant | Granted on several organisations, for an IT consultant who looks after multiple small clients; can view and acknowledge in each but cannot change retention or approve scans |

The 7 week prototype runs one organisation, but the schema, policies and indices above are built with the organisation identifier from the start, so adding a second client is configuration and not a redesign.

## 8. Security

The server exposes only three ports to the office network, and every internal service listens on the server itself, so a compromised workstation cannot reach the database, the indexer or the AI engine directly.

| Port | Service | Reachable from |
| --- | --- | --- |
| 1514 TCP | Wazuh agent events | Monitored machines |
| 1515 TCP | Agent enrolment | Monitored machines |
| 443 TCP | Web Dashboard over HTTPS | Staff computers |
| 8000 | AI Inference Engine | Server only |
| 9200 | Wazuh Indexer | Server only |
| 55000 | Wazuh API | Server only |
| 5432 | PostgreSQL | Server only |
| 6379 | Redis | Server only |

**Agent enrolment.** A new agent can only join with the enrolment password the administrator sets, and it is placed in its organisation's group. After enrolment each agent talks to the manager with its own key, and Wazuh encrypts that traffic. An agent that is lost or retired is removed by the administrator and its key stops working.

**User login.** Passwords are stored as salted hashes, never in readable form. Administrators can turn on a second factor with a time based code. Repeated failed logins lock the account for a period, and sessions use short lived tokens. The dashboard is served over HTTPS with a certificate made at installation, which the client can replace with their own.

**Between services.** Internal calls carry a key issued at installation. The AI engine and database accept connections from the local server only.

**Encryption at rest.** The installation guide tells the client to place the data disk on an encrypted volume. The sync queue and any backup are encrypted with AES 256, as Section 10 requires for data bound for the cloud.

**Audit trail.** Logins, setting changes, scan approvals, agent enrolments and removals, and every acknowledgement of an alert are written to an audit log that administrators can read but not edit.

**What leaves the site.** Raw logs and event contents never leave the client's premises. Only anonymised threat statistics and model performance figures are queued for the cloud, and only when the administrator has turned sync on.

## 9. Failure and offline behaviour

No single failure stops monitoring altogether, and the loss of internet changes nothing the user depends on. The dashboard has a health page that lists the state of every component, so a failure is visible and not silent.

| What fails | What the user sees | What keeps working | Recovery |
| --- | --- | --- | --- |
| Internet connection | An offline marker and the age of the CVE feed | All monitoring, detection, scanning and the dashboard | Queued sync messages send in order when the link returns |
| AI Inference Engine | Rule based alerts marked as not yet scored by the AI | Wazuh rules, Suricata, scanning, dashboard | Engine restarts, then unscored alerts are scored again |
| An agent or its machine | An alert that the agent has gone silent | Every other agent and the server | Agent reconnects and sends what it buffered |
| Link between agent and server | The same silent agent alert | The agent keeps a limited local buffer | Buffer is sent on reconnection, oldest events dropped if it overflowed |
| Suricata | A health alert that network monitoring is paused | Host based monitoring and scanning | Service restarts automatically |
| Server loses power | A gap in the event timeline after restart | Data already on disk | Services start at boot; the installation guide recommends a small UPS |
| Disk nearly full | A warning at the administrator's threshold | Everything | Oldest raw events are purged first, before alerts or incident reports |
| A new model fails validation | A note on the health page | The previous model stays in use | See Section 10 |

Events that occur while the server is off are not recoverable, because the agents hold only a limited buffer. The limitations section of the report should state this plainly.

## 10. Cloud sync protocol

The sync client sends and receives numbered messages whenever a connection exists and does nothing when it does not, which is what lets the platform tolerate unreliable internet. This layer is design only in the 7 week scope: the prototype defines the formats and rules below but does not implement the cloud backend.

Every message, in either direction, is one JSON file with the same envelope:

```json
{
  "seq": 1042,
  "schema_version": 1,
  "org_id": "org_0007",
  "type": "model_metrics",
  "created_at": 1792634591,
  "checksum": "sha256 of the payload",
  "payload": { }
}
```

| Direction | Type | Content |
| --- | --- | --- |
| Out | `telemetry` | Anonymised counts of attack categories and severities |
| Out | `model_metrics` | Detection accuracy and false positive rate measured on the local site |
| In | `threat_intel` | Updated threat intelligence feeds |
| In | `cve_feed` | Refreshed vulnerability data for the scanner |
| In | `model_update` | A new set of model weights with its version and training dataset |
| In | `template_update` | Revised response playbooks and compliance templates |

**Sending.** The client writes each outbound message to the queue directory with the next sequence number. Every so often it sends a lightweight HTTP HEAD request to the sync endpoint; if that succeeds, it sends the queued messages in sequence order over HTTPS using TLS 1.3 with certificate pinning, and deletes each file only after the cloud acknowledges that sequence number. The cloud ignores a sequence number it has already stored, so a message sent twice after a dropped connection does no harm.

**Receiving.** Inbound messages follow the same pattern in reverse. The cloud queues them, and the client pulls them on each sync and acknowledges each one. The checksum is verified before anything is applied.

**Model updates.** The cloud wins, but only after a check. The new model is stored aside from the live one and scored on a held out set of local data. It replaces the live model only if its score is at least 90 percent of the live model's score. If it fails, the live model stays in place, the failure shows on the health page, and the previous version is always kept for rollback.

**Protection.** Data is encrypted in transit with TLS 1.3 and at rest with AES 256. The platform works fully when this layer is unavailable.

## 11. Resource budget and traceability

The server's 8 GB of RAM is fully allocated in the plan below, so the Week 5 to 7 benchmark must confirm it, and the fallback is a 16 GB server or a smaller indexer heap. Running OpenVAS alongside everything else needs the 16 GB server. Only the agent and AI engine figures come from the proposal; the others are planning estimates to be measured.

| Component | RAM | Source of figure |
| --- | --- | --- |
| Endpoint agent, on each monitored machine | Under 100 MB, under 2 percent CPU | Proposal |
| AI Inference Engine | Under 2 GB at steady state | Proposal |
| Wazuh Manager | About 1 GB | Planning estimate |
| Wazuh Indexer | About 2 GB | Planning estimate |
| Suricata | About 1 GB | Planning estimate |
| Platform backend, PostgreSQL and Redis together | About 1 GB | Planning estimate |
| Operating system and one capped scan job at a time | About 1 GB | Planning estimate |

Each requirement in the proposal and on the slides maps to the part of this document that meets it.

| Requirement | Met in |
| --- | --- |
| AI Threat Detection, Vulnerability Scanning, Offline Monitoring, Security Dashboard | Section 1 and the sections it points to |
| Detection accuracy above 95 percent, false positives below 5 percent per dataset | AI engine design, Sections 3 and 6 |
| Under 100 milliseconds per flow window | Section 6 |
| Operates with no internet | Sections 9 and 10 |
| Store and forward synchronisation | Section 10 |
| Template based incident response | Sections 3, 4 and 6 |
| Multi tenancy and consultant access | Section 7 |
| Usable by an IT generalist | Dashboard guidance in Section 4 and the health page in Section 9 |

## 12. Items to confirm

1. **Scanning scope.** Nine scan tool adapters are a lot for 7 weeks. Decide which are built in the prototype and which stay as designed extensions. A sensible build order is Nmap, Wapiti, Nuclei and OSV-Scanner first, then the rest as time allows.
2. **Server size.** Only the agent and AI engine figures come from the proposal. Confirm the others in the Week 5 to 7 benchmark, and decide whether the recommended hardware is 8 GB or 16 GB.
3. **Multi tenancy.** The prototype runs one organisation with the tenancy design built in. Confirm this matches the scope wording in the proposal.