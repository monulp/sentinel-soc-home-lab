# 🛡️ SOC Home Lab — Live Security Monitoring Project

> A hands-on Security Operations Centre (SOC) lab built to develop real-world cyber security skills.  
> This project is actively being built and updated daily as part of interview preparation for a **Cyber Security Analyst** role.

---

## 📌 Project Goal

Build a fully functional SOC monitoring pipeline that mirrors what real SOC teams use — covering **SIEM**, **EDR**, and **log analysis** workflows end to end.

---

## 🏗️ Lab Architecture

```
Digital Ocean Droplet (Ubuntu)
├── Apache/Nginx Web Server
├── Splunk Universal Forwarder      ✅ Complete
├── Azure Monitor Agent (AMA)       ✅ Complete
│     └──► Microsoft Sentinel
└── Wazuh Agent                     🔄 In Progress
      └──► Wazuh Manager (EDR)
```

### Attack Simulation Machine
```
Laptop / Kali Linux
└── Hydra, Gobuster, Nmap
      └──► Attacks web server
              └──► Triggers alerts in Splunk + Sentinel + Wazuh
```

---

## 🧰 Tools & Technologies

| Tool | Category | Status |
|------|----------|--------|
| Splunk | SIEM | ✅ Live |
| Microsoft Sentinel | Cloud SIEM | ✅ Live |
| Wazuh | EDR / HIDS | 🔄 In Progress |
| Azure Arc | Server Management | ✅ Live |
| Azure Monitor Agent | Log Collection | ✅ Live |
| Hydra | Attack Simulation | 📅 Planned |
| Gobuster | Attack Simulation | 📅 Planned |

---

## 📋 Progress Log

### ✅ Phase 1 — Microsoft Sentinel Setup

#### Step 1 — Azure Account & Log Analytics Workspace
- Created Azure free account with $200 credit
- Created **Log Analytics Workspace** named `sentinel-soc-lab`
- Region: Australia East (closest to NZ)
- Resource Group: `SOC-Lab`

![Workspace Created](screenshots/01-workspace-overview.png)

---

#### Step 2 — Microsoft Sentinel Attached
- Navigated to Microsoft Sentinel
- Attached to `sentinel-soc-lab` workspace
- Sentinel is now active and ready to receive logs

---

#### Step 3 — Data Collection Rule (DCR) Created
- Navigated to **Azure Monitor → Data Collection Rules**
- Created rule: `dcr-webserver-linux`

**Configuration:**
```
Rule Name:        dcr-webserver-linux
Subscription:     Azure subscription 1
Resource Group:   SOC-Lab
Region:           Australia East
Type:             Agent-based - Linux
```

![Data Collection Rules](screenshots/02-data-collection-rules.png)

---

#### Step 4 — Log Sources Configured

Selected the following **Linux Syslog facilities** to collect — each chosen for specific SOC value:

| Facility | Why It Matters |
|----------|----------------|
| `LOG_AUTH` | SSH logins, failed passwords, su/sudo — attacker activity |
| `LOG_AUTHPRIV` | Private auth messages, PAM authentication — privilege escalation |
| `LOG_AUDIT` | Linux audit framework — file and system call auditing |
| `LOG_CRON` | Scheduled tasks — attackers use cron for persistence |
| `LOG_DAEMON` | Background services — detects malicious service installs |
| `LOG_KERN` | Kernel events — useful for rootkit detection |

All facilities set to **LOG_DEBUG** level to capture everything in the lab environment.

![Log Facilities Selected](screenshots/03-log-facilities.png)

---

#### Step 5 — Destination Set to Sentinel Workspace

Configured the destination to send all collected logs to the `sentinel-soc-lab` Log Analytics Workspace.

```
Destination type:    Log Analytics Workspaces
Workspace:           sentinel-soc-lab (SOC-Lab)
```

![Destination Configured](screenshots/04-destination-set.png)

---

#### Step 6 — DCR Deployed Successfully ✅

Data Collection Rule deployed and confirmed active.

```
Status:           ✅ Deployment Complete
Resource Group:   SOC-Lab
Subscription:     Azure subscription 1
```

![Deployment Complete](screenshots/05-deployment-complete.png)

---

### 🔄 Phase 2 — Connect Droplet via Azure Arc (In Progress)

**Next steps:**
- [ ] Install Azure Arc agent on Digital Ocean droplet
- [ ] Register droplet as Azure Arc-enabled server
- [ ] Verify logs flowing into Sentinel workspace
- [ ] Confirm `Syslog` table populating in Log Analytics

---

### 📅 Phase 3 — Wazuh EDR Setup (Planned)

- [ ] Deploy Wazuh Manager on second droplet
- [ ] Install Wazuh Agent on web server
- [ ] Configure File Integrity Monitoring (FIM) on `/var/www/html`
- [ ] Enable VirusTotal integration

---

### 📅 Phase 4 — Attack Simulations & SOC Workflow (Planned)

| Attack | Tool | Detection Target |
|--------|------|-----------------|
| SSH Brute Force | Hydra | Sentinel + Splunk + Wazuh |
| Web Directory Scan | Gobuster | Sentinel + Splunk |
| Webshell Upload | Manual | Wazuh FIM |
| Privilege Escalation | Manual | Wazuh + Sentinel |

---

### 📅 Phase 5 — KQL Detection Rules in Sentinel (Planned)

```kusto
// SSH Brute Force Detection
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Failed password"
| summarize FailedAttempts = count() by 
    SourceIP = extract(@"from (\S+)", 1, SyslogMessage), 
    bin(TimeGenerated, 5m)
| where FailedAttempts > 5

// Successful Login After Multiple Failures
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Failed password" 
    or SyslogMessage contains "Accepted password"
| extend IsFailure = SyslogMessage contains "Failed password"
| extend SourceIP = extract(@"from (\S+)", 1, SyslogMessage)
| summarize 
    Failures = countif(IsFailure), 
    Successes = countif(not(IsFailure)) 
    by SourceIP, bin(TimeGenerated, 10m)
| where Failures > 3 and Successes > 0
```

---

## 🧠 Key Concepts Learned

### SIEM vs EDR
| | SIEM (Sentinel/Splunk) | EDR (Wazuh/CrowdStrike) |
|-|----------------------|------------------------|
| Focus | Log aggregation & correlation | Endpoint behaviour monitoring |
| Scope | Entire environment | Individual endpoints |
| Strength | Big picture detection | Deep endpoint forensics |
| Query Language | KQL / SPL | Rules-based |

### Azure Monitor Architecture
```
Server (any cloud/on-prem)
    │
    ▼ Azure Arc (registers non-Azure servers)
    │
    ▼ Azure Monitor Agent (collects logs)
    │
    ▼ Data Collection Rule (defines what + where)
    │
    ▼ Log Analytics Workspace (stores logs)
    │
    ▼ Microsoft Sentinel (detects + alerts)
```

### SOC Incident Investigation Workflow
```
Alert Fires
    │
    ▼ Validate — True or False Positive?
    │
    ▼ Investigate — Who? What? When? Where?
    │
    ▼ Contain — Isolate if needed
    │
    ▼ Remediate — Fix the root cause
    │
    ▼ Document — Incident report
    │
    ▼ Lessons Learned
```

---

## 📁 Repository Structure

```
soc-home-lab/
├── README.md                    # This file — live progress log
├── screenshots/                 # Lab screenshots at each step
│   ├── 01-workspace-overview.png
│   ├── 02-data-collection-rules.png
│   ├── 03-log-facilities.png
│   ├── 04-destination-set.png
│   └── 05-deployment-complete.png
├── kql-queries/                 # Detection rules written in KQL
│   └── detection-rules.kql
├── incident-reports/            # Documented attack investigations
│   └── template.md
└── wazuh/                       # Wazuh config files
    └── ossec.conf
```

---

## 🔗 References

- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Azure Monitor Agent Overview](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-overview)
- [Azure Arc Documentation](https://learn.microsoft.com/en-us/azure/azure-arc/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## 👤 About

Built by a cyber security analyst in training based in Auckland, NZ.  
Actively working toward a SOC Analyst role — this repo documents real hands-on learning, not just theory.

> *"The best way to learn security is to build the thing, break the thing, and detect the thing."*

---

![GitHub last commit](https://img.shields.io/github/last-commit/YOURUSERNAME/soc-home-lab)
![Status](https://img.shields.io/badge/status-active-brightgreen)
![Tools](https://img.shields.io/badge/tools-Sentinel%20%7C%20Splunk%20%7C%20Wazuh-blue)
