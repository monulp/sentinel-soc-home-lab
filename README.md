# 🛡️ SOC Home Lab — Microsoft Sentinel + Splunk

> A production-grade Security Operations Centre home lab built on live internet-facing infrastructure, designed to develop real-world SOC analyst skills using Microsoft Sentinel, Splunk, and Azure Arc.

![Dashboard](https://github.com/monulp/sentinel-soc-home-lab/blob/main/screenshot/dashboard1.png)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Tools & Technologies](#tools--technologies)
- [Detection Rules](#detection-rules)
- [Incidents Investigated](#incidents-investigated)
- [KQL Playbook](#kql-playbook)
- [Dashboard](#dashboard)
- [Tutorials](#tutorials)
- [Skills Demonstrated](#skills-demonstrated)

---

## Overview

This lab simulates a real SOC environment by exposing a Linux web server to the public internet and monitoring all attack traffic through Microsoft Sentinel and Splunk. Every alert, incident, and investigation documented here is based on **real attacks from real threat actors**.

### What Makes This Different

- **Live attack data** — not simulated, real brute force and scanning activity 24/7
- **Multi-SIEM** — same attacks correlated across Sentinel and Splunk
- **End-to-end workflow** — from log ingestion → detection rules → incident investigation → closure
- **Professional documentation** — incident reports, KQL playbook, tutorials

### Lab Stats (as of May 2026)
| Metric | Value |
|---|---|
| Total incidents detected | 200+ |
| Active detection rules | 6 |
| Unique attacker IPs observed | 50+ |
| Countries of origin identified | 10+ |
| Brute force attempts blocked | 4,600+ |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    INTERNET ATTACKERS                    │
│         SSH Brute Force / Web Scanners / Nmap           │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│           server1.adilmonu.com                          │
│           Digital Ocean Ubuntu 22.04 Droplet            │
│                                                         │
│   Apache Web Server  ←→  rsyslog  ←→  Splunk Agent     │
│   SSH Service                                           │
│   Azure Arc Agent                                       │
│   Azure Monitor Agent                                   │
└──────────┬──────────────────────────┬───────────────────┘
           │                          │
           ▼                          ▼
┌──────────────────┐      ┌───────────────────────┐
│ Microsoft        │      │ Splunk Enterprise      │
│ Sentinel         │      │ (Local Instance)       │
│                  │      │                        │
│ Log Analytics    │      │ Web Security Dashboard │
│ Analytics Rules  │      │ Triggered Alerts       │
│ Incident Queue   │      │ Custom Searches        │
│ Custom Workbook  │      │                        │
└──────────────────┘      └───────────────────────┘
```

### Log Flow

```
Apache Access Log  → rsyslog → local0  → Azure Monitor Agent → Sentinel
Apache Error Log   → rsyslog → local1  → Azure Monitor Agent → Sentinel
SSH Auth Log       → rsyslog → auth    → Azure Monitor Agent → Sentinel
                                       
```

---

## Tools & Technologies

| Category | Tool | Purpose |
|---|---|---|
| **SIEM** | Microsoft Sentinel | Primary SOC platform, detection rules, incident management |
| **SIEM** | Splunk Enterprise | Secondary SIEM, cross-platform correlation |
| **Cloud** | Microsoft Azure | Sentinel workspace, Log Analytics, Azure Arc |
| **Infrastructure** | Digital Ocean | Ubuntu 22.04 droplet (server1.adilmonu.com) |
| **Log Management** | Azure Monitor Agent | Log collection and forwarding to Sentinel |
| **Log Management** | rsyslog | Log routing on Linux server |
| **Web Server** | Apache2 | Generates web access/error logs |
| **Query Language** | KQL | Sentinel hunting and detection queries |
| **Query Language** | SPL | Splunk search and alert queries |
| **Endpoint** | Azure Arc | Connects on-prem server to Azure |

---

## Detection Rules

All rules are custom-built Scheduled Analytics Rules in Microsoft Sentinel, mapped to MITRE ATT&CK.

| Rule Name | Severity | MITRE Tactic | Technique | Schedule | Log Source |
|---|---|---|---|---|---|
| SSH Brute Force Detection | Medium | TA0006 Credential Access | T1110 | Every 5 min | auth/authpriv |
| Port Scan Detection | High | TA0043 Reconnaissance | T1595 | Every 5 min | auth/authpriv |
| Nmap Scan Detection | High | TA0043 Reconnaissance | T1595.001 | Every 5 min | auth/authpriv |
| Web Scanner Detection | Medium | TA0043 Reconnaissance | T1595 | Every 1 hour | local0 (Apache) |
| High HTTP Error Rate | Medium | TA0043 Reconnaissance | T1595 | Every 30 min | local0 (Apache) |
| Suspicious User Agent Detection | High | TA0043 Reconnaissance | T1595 | Every 15 min | local0 (Apache) |

![Analytics Rules](https://github.com/monulp/sentinel-soc-home-lab/blob/main/screenshot/analytics-rules.png)

### Detection Engineering Highlights

**SSH Brute Force Rule** — Uses 24h lookback with a threshold of 5 failed attempts, groups alerts by entity to prevent alert flooding from the same attacker.

**Web Scanner Rule** — Catches scanners across all suspicious status codes (404, 301, 302, 403, 400, 500) after identifying a detection gap where 301 redirects were missed by a 404-only filter. Discovered through cross-platform correlation with Splunk.

**Suspicious User Agent** — Zero false positive rule. Identifies known offensive tools (Nikto, Gobuster, sqlmap, Nmap, Masscan, Nuclei) by their User-Agent string. Any match is confirmed malicious.

---

## Incidents Investigated

### INC-030 — SSH Brute Force Campaign (Multi-Origin Botnet)

![Incident Evidence](https://github.com/monulp/sentinel-soc-home-lab/tree/main/incidents/Incident30)

| Field | Detail |
|---|---|
| **Date** | May 11, 2026 |
| **Classification** | True Positive — Benign (Attack Failed) |
| **Severity** | Medium |
| **Total Attempts** | 2,326 brute force attempts |
| **Attacker IPs** | 7 IPs across USA, Hong Kong, Vietnam, Netherlands, Mexico, Moldova |
| **Peak Volume** | ~1,820 attempts in the 06:00 AM wave |
| **Breach Confirmed** | No — zero successful authentications via KQL |
| **MITRE Tactic** | TA0006 Credential Access |

**Investigation Summary:**  
16 Sentinel alerts triggered by 7 distinct IPs over 75 minutes. All IPs flagged Suspicious by Defender XDR threat intelligence. KQL breach verification query returned zero results — all 2,326 attempts failed at [preauth] stage. Coordinated timing across 7 countries consistent with distributed botnet activity.

📄 [Full Incident Report](https://github.com/monulp/sentinel-soc-home-lab/blob/main/incidents/Incident30/report)

---

### INC-031 — Web Scanner Detection (In Progress)

| Field | Detail |
|---|---|
| **Date** | May 11, 2026 |
| **Classification** | True Positive — Under Investigation |
| **Attacker IP** | 118.148.72.193 |
| **MITRE Tactic** | TA0043 Reconnaissance |

---

## KQL Playbook

A complete investigation guide for every detection rule — what queries to run, in what order, for each alert type.

📄 [KQL Investigation Playbook](https://github.com/monulp/sentinel-soc-home-lab/blob/main/docs/KQL-Investigation-Playbook.md)

### Quick Reference

```kql
// Universal starting query — run this first for every investigation
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage contains "ATTACKER_IP_HERE"
| project TimeGenerated, Facility, SyslogMessage
| order by TimeGenerated asc
```

---

## Dashboard

Custom Sentinel Workbook built to replace generic templates with security-specific visualisations relevant to this lab.

![SOC Dashboard](https://github.com/monulp/sentinel-soc-home-lab/tree/main/screenshot)

### Dashboard Panels
- **Active Incidents Last 24h** — bar chart by rule name
- **Attack Volume Timeline** — 30-minute buckets showing attack waves
- **Top 10 Web Attacking IPs** — ranked by request volume
- **Top 10 SSH Brute Force IPs** — ranked by attempt count
- **HTTP Status Code Breakdown** — pie chart of response codes

---

## Tutorials

Step-by-step guides for building this lab from scratch.

| Tutorial | Description | Status |
|---|---|---|
| [Tutorial 01 — Lab Setup](tutorials/Tutorial-01-Setup.md) | Digital Ocean droplet, Azure Arc, Sentinel workspace, log ingestion | ✅ Complete |
| Tutorial 02 — Detection Rules | Building custom analytics rules, KQL writing, MITRE mapping | 🔄 In Progress |
| Tutorial 03 — Attack Simulations | Running Hydra brute force and Gobuster web scans, investigating results | ⬜ Planned |
| Tutorial 04 — Wazuh EDR | Installing Wazuh as CrowdStrike equivalent, agent deployment | ⬜ Planned |

---

## Skills Demonstrated

### Detection Engineering
- Built 6 custom Sentinel Analytics Rules from scratch
- Wrote KQL detection queries with regex extraction
- Identified and resolved detection gaps via cross-platform correlation
- Mapped all rules to MITRE ATT&CK framework

### Incident Response
- End-to-end incident investigation workflow (Triage → Evidence → KQL → Determination → Closure)
- Breach verification using targeted KQL queries
- Professional incident report writing
- Incident classification and determination

### Threat Hunting
- Proactive KQL hunting beyond alert boundaries
- Cross-platform correlation (Sentinel + Splunk)
- Attacker IP profiling and geolocation
- Kill chain reconstruction

### SIEM Administration
- Microsoft Sentinel workspace configuration
- Log Analytics workspace management
- Data Collection Rules setup
- Azure Monitor Agent deployment
- Custom Workbook development

### Linux & Infrastructure
- Ubuntu server administration
- rsyslog configuration for multi-destination log routing
- Apache2 web server setup and log management
- Azure Arc agent installation and management

---


---

## About

Built as part of interview preparation for a Cyber Security Analyst role, this lab demonstrates practical SOC skills using enterprise-grade tools on live infrastructure.

**Contact:** https://github.com/monulp  
**Platform:** Microsoft Sentinel | Splunk | Digital Ocean | Azure

---

*All attack data shown is real traffic from internet-facing infrastructure. No simulated data.*
