# Tutorial 01 — Microsoft Sentinel Setup
### Connecting a Linux Web Server to Azure Sentinel for Security Monitoring

---

## 📋 Overview

In this tutorial we set up **Microsoft Sentinel** — Microsoft's cloud-native SIEM (Security Information and Event Management) platform — and configure it to receive logs from a Linux web server hosted on Digital Ocean.

By the end of this tutorial you will have:
- A live Microsoft Sentinel workspace in Azure
- A Data Collection Rule that captures security-relevant Linux logs
- A pipeline ready to receive logs from your server

---

## 🧠 What Is a SIEM and Why Sentinel?

A **SIEM** is the central nervous system of a SOC. It:
- **Collects** logs from every system in your environment
- **Correlates** events across multiple sources to detect threats
- **Alerts** analysts when suspicious patterns are detected
- **Stores** logs for investigation and forensics

**Microsoft Sentinel** is a cloud-native SIEM built on Azure. It is widely used in enterprise SOC environments and is one of the tools explicitly listed in many Cyber Security Analyst job descriptions. Learning Sentinel gives you a significant advantage in interviews.

### How Sentinel Compares to Splunk

| Feature | Microsoft Sentinel | Splunk |
|---------|-------------------|--------|
| Deployment | Cloud-native (Azure) | On-prem or cloud |
| Query Language | KQL (Kusto Query Language) | SPL (Search Processing Language) |
| Cost Model | Pay per GB ingested | License-based |
| Integration | Deep Azure/Microsoft 365 integration | Broad ecosystem |
| Best for | Azure-heavy environments | Large enterprise |

Both are industry-standard. Knowing both makes you a stronger candidate.

---

## 🏗️ Architecture We Are Building

```
Digital Ocean Droplet (Ubuntu)
        │
        │  Linux system logs
        │  (auth, syslog, kernel, cron, daemon, audit)
        ▼
Azure Monitor Agent
        │
        │  Secure HTTPS transmission
        ▼
Data Collection Rule (DCR)
        │
        │  Routes logs to destination
        ▼
Log Analytics Workspace (sentinel-soc-lab)
        │
        │  Stores logs in Syslog table
        ▼
Microsoft Sentinel
        │
        │  Runs detection rules (KQL)
        ▼
Incidents & Alerts
```

---

## ✅ Prerequisites

- A Digital Ocean account with an Ubuntu droplet running
- A web server (Apache or Nginx) installed on the droplet
- Basic familiarity with SSH and the Linux terminal
- A credit card for Azure account verification (no charges — $200 free credit is provided)

---

## 🔧 Step 1 — Create Your Azure Account

### What Is Azure?
Microsoft Azure is a cloud platform that provides hundreds of services — compute, storage, networking, security, and more. Microsoft Sentinel lives inside Azure. We use Azure's free tier which gives you **$200 credit for 30 days** — more than enough for this lab.

### How to Do It

1. Go to [https://azure.microsoft.com/en-us/free](https://azure.microsoft.com/en-us/free)
2. Click **"Start free"**
3. Sign in with a Microsoft account or create one
4. Verify your identity with a credit card (you will not be charged — the $200 credit covers everything)
5. Complete the sign-up process

You will land on the **Azure Portal** at `portal.azure.com` — this is your Azure home base.

> 💡 **Why free credit?** Microsoft offers this to let developers and learners explore Azure services. For our lab, the Sentinel free trial (10GB/day ingestion for 31 days) combined with the $200 credit means this entire lab costs you nothing.

---

## 🔧 Step 2 — Create a Log Analytics Workspace

### What Is a Log Analytics Workspace?
Think of a **Log Analytics Workspace** as a secure database in Azure that stores all your logs. It is the foundation that Sentinel sits on top of. Every log from your server will land here first, and then Sentinel reads from it to run detection rules.

```
Web Server → [sends logs] → Log Analytics Workspace → [Sentinel reads] → Alerts
```

Without this workspace, Sentinel has nowhere to store or query data.

### How to Do It

1. In the Azure Portal top search bar, type `Log Analytics Workspaces` and click the result
2. Click **"+ Create"**
3. Fill in the form:

```
Subscription:    Azure subscription 1
Resource Group:  Click "Create new" → name it: SOC-Lab
Name:            sentinel-soc-lab
Region:          Australia East
```

> 💡 **Why Australia East?** It is the closest Azure region to New Zealand. Lower latency means logs arrive faster. In a real SOC, you also need to consider data sovereignty — some organisations must keep logs in specific countries for legal compliance.

> 💡 **What is a Resource Group?** Think of it like a folder that contains all your related Azure resources. Naming it `SOC-Lab` keeps everything organised together — workspace, DCR, Arc agent — all in one place. Easy to find, easy to delete when you are done.

4. Click **"Review + Create"** → then **"Create"**
5. Wait approximately 1 minute for deployment to complete

![Workspace Overview](../screenshots/01-workspace-overview.png)

---

## 🔧 Step 3 — Attach Microsoft Sentinel to the Workspace

### What Is Happening Here?
Creating the workspace just creates the database. Attaching Sentinel to it activates the security analysis layer on top of that database. Sentinel is what turns raw logs into detections, alerts, and incidents.

```
Log Analytics Workspace (database)
        +
Microsoft Sentinel (security brain)
        =
Full SIEM capability
```

### How to Do It

1. In the Azure Portal top search bar, type `Microsoft Sentinel` and click the result
2. Click **"+ Create"**
3. Select your workspace: `sentinel-soc-lab`
4. Click **"Add"**

Sentinel is now active on your workspace. You will land on the Sentinel dashboard — it will be mostly empty for now, but it is live and waiting for data.

---

## 🔧 Step 4 — Navigate to Data Collection Rules

### What Is a Data Collection Rule (DCR)?
A **Data Collection Rule** is a configuration object in Azure that defines:
- **What** logs to collect (which log sources and facilities)
- **From where** (which machines)
- **Where to send them** (which workspace)

Think of it like a postal instruction: *"From this server, collect these log types, and deliver them to this address."*

DCRs are the modern approach — Microsoft is moving away from the old MMA (Microsoft Monitoring Agent) in favour of the newer **Azure Monitor Agent (AMA)** with DCRs. Learning the modern method means you are working with what real SOC teams use today.

### How to Get There

1. In the Azure Portal, click **"Monitor"** in the left sidebar, or search for it in the top bar
2. In the Monitor left menu, expand **"Settings"**
3. Click **"Data Collection Rules"**

You will see an empty list — we are about to create your first DCR.

![Data Collection Rules Page](../screenshots/02-data-collection-rules.png)

---

## 🔧 Step 5 — Create the Data Collection Rule

### How to Do It

1. Click **"+ Create"**
2. Fill in the **Basics** tab:

```
Rule name:         dcr-webserver-linux
Subscription:      Azure subscription 1
Resource Group:    SOC-Lab
Region:            Australia East
Platform Type:     Linux
```

> 💡 **Why "Agent-based - Linux"?** This tells Azure we are installing a monitoring agent directly on a Linux machine. The alternative is "Platform" telemetry which is for Azure-native resources like VMs. Since our Digital Ocean droplet is an external server, we use agent-based collection.

3. Leave **Data Collection Endpoint** as "Select..." — not needed for this lab
4. Leave **Identity** section unchecked — this is for enterprise scenarios only
5. Click **"Next"** to go to the Resources tab

---

## 🔧 Step 6 — Resources Tab (Skip for Now)

The Resources tab is where you would normally add Azure Virtual Machines. However, our server is on **Digital Ocean** — not an Azure VM. This means it will not appear in this list.

We will connect the droplet later using **Azure Arc**, which is Microsoft's technology for managing non-Azure servers. For now, click **"Next"** to proceed to the most important tab.

> 💡 **What is Azure Arc?** Azure Arc extends Azure's management capabilities to any server — whether it is on Digital Ocean, AWS, on-premises, or anywhere else. Once Arc is installed on your droplet, Azure treats it like a native Azure resource and can push agents to it automatically.

---

## 🔧 Step 7 — Configure Log Collection (Collect and Deliver Tab)

### What We Are Choosing and Why

This is the most important configuration step. We select exactly which Linux log facilities to collect. In a real SOC, you do not collect everything — that creates noise, increases cost, and makes investigations harder. You collect the logs that matter for security.

**Linux Syslog Facilities** are categories of system logs. Each facility captures a different type of system activity:

| Facility | What It Captures | SOC Relevance |
|----------|-----------------|---------------|
| `LOG_AUTH` | SSH logins, failed passwords, `su` and `sudo` commands | 🔴 Critical — primary source for detecting brute force and unauthorised access |
| `LOG_AUTHPRIV` | Private authentication messages, PAM (Pluggable Authentication Module) events | 🔴 Critical — privilege escalation detection |
| `LOG_AUDIT` | Linux audit framework — file access, system calls, policy changes | 🟠 High — compliance and forensic investigation |
| `LOG_CRON` | Scheduled task execution and cron job output | 🟡 Medium — attackers use cron jobs for persistence after gaining access |
| `LOG_DAEMON` | Background service start/stop events | 🟡 Medium — detecting malicious services being installed |
| `LOG_KERN` | Kernel-level messages and hardware events | 🟠 High — useful for detecting rootkits and kernel-level attacks |

**Log Level — LOG_DEBUG** means "collect all messages from this facility regardless of severity." In a lab environment this is ideal. In production, you would tune this to reduce ingestion volume and cost.

### How to Do It

1. Click **"+ Add new data source"**
2. A panel slides out. Set:
   - **Data source type:** Linux Syslog
3. In the facilities list, tick these 6 checkboxes:
   - ✅ `LOG_AUDIT`
   - ✅ `LOG_AUTH`
   - ✅ `LOG_AUTHPRIV`
   - ✅ `LOG_CRON`
   - ✅ `LOG_DAEMON`
   - ✅ `LOG_KERN`
4. Leave all Log Level dropdowns as `LOG_DEBUG`

![Log Facilities Selected](../screenshots/03-log-facilities.png)

---

## 🔧 Step 8 — Set the Destination

### What Is the Destination?
The destination tells Azure where to deliver the collected logs. We point it at our `sentinel-soc-lab` Log Analytics Workspace. Once logs land there, Sentinel automatically has access to query and analyse them.

Logs from Linux machines are stored in the **`Syslog`** table inside the workspace. When you write KQL detection rules later, you will query this table:

```kusto
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Failed password"
```

### How to Do It

1. Click **"Next: Destinations >"**
2. Click **"+ Add destination"**
3. Fill in:

```
Destination type:         Log Analytics Workspaces
Subscription:             Azure subscription 1
Log Analytics Workspace:  sentinel-soc-lab (SOC-Lab)
```

4. Click **"Apply"**

![Destination Configured](../screenshots/04-destination-set.png)

You will see `Linux Syslog → Log Analytics Workspaces` listed in the table. Your data pipeline is fully defined.

---

## 🔧 Step 9 — Review and Deploy

### Final Check Before Deployment

1. Click **"Review + create"**
2. Verify the summary:

```
Rule Name:               dcr-webserver-linux
Subscription:            Azure subscription 1
Resource Group:          SOC-Lab
Region:                  Australia East
Type of telemetry:       Agent-based - Linux
Resources:               None (will connect via Azure Arc next)
Collect and deliver:     Linux Syslog → sentinel-soc-lab
```

3. Click **"Create"**

Azure deploys the Data Collection Rule in approximately 30 seconds.

![Deployment Complete](../screenshots/05-deployment-complete.png)

---

## ✅ What You Have Built

Congratulations — you have just configured a real security monitoring pipeline. Here is a summary of everything that is now in place:

```
┌─────────────────────────────────────────────┐
│           AZURE SOC INFRASTRUCTURE          │
│                                             │
│  ✅ Log Analytics Workspace                 │
│     sentinel-soc-lab (Australia East)       │
│                                             │
│  ✅ Microsoft Sentinel                      │
│     Attached and active                     │
│                                             │
│  ✅ Data Collection Rule                    │
│     dcr-webserver-linux                     │
│     Collecting: AUTH, AUTHPRIV, AUDIT,      │
│                 CRON, DAEMON, KERN           │
│     Destination: sentinel-soc-lab           │
└─────────────────────────────────────────────┘
```

---

## 🔜 Next Tutorial

**[Tutorial 02 — Connecting Your Droplet via Azure Arc](./02-azure-arc-droplet.md)**

In the next tutorial we will:
- Install the Azure Arc agent on the Digital Ocean droplet
- Register the droplet as an Azure-managed server
- Install the Azure Monitor Agent automatically via Azure
- Verify that logs are flowing into the Sentinel workspace
- Run your first KQL query to confirm live data

---

## 🧠 Key Concepts Recap

| Concept | One-Line Explanation |
|---------|---------------------|
| SIEM | Collects and correlates logs to detect threats |
| Log Analytics Workspace | The database where all logs are stored |
| Microsoft Sentinel | The security analysis layer on top of the workspace |
| Data Collection Rule | Defines what logs to collect and where to send them |
| Syslog Facility | A category of Linux system logs |
| LOG_DEBUG | Collect all messages regardless of severity |
| KQL | The query language used to search logs in Sentinel |

---

*Tutorial 01 of 04 — SOC Home Lab Project*  
*Last updated: May 2026*
