# KQL Investigation Playbook
## SOC Home Lab : Microsoft Sentinel
**Author:** Adil Monu | **Last Updated:** May 11, 2026  
**GitHub:** https://github.com/monulp/sentinel-soc-home-lab

---

## How to Use This Playbook

Every alert investigation answers 5 questions in order:

```
1. WHAT happened?      → Read the alert details
2. WHO did it?         → Identify the source IP / entity
3. HOW did they do it? → Find raw evidence in logs
4. DID IT WORK?        → Check for success indicators
5. WHAT ELSE?          → Hunt for related activity
```

Replace `ATTACKER_IP_HERE` with the actual IP from the incident entity panel.

---

## The Universal Starting Query

Run this first for **every** investigation. It gives you the complete picture of what an IP did across all log sources:

```kql
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage contains "ATTACKER_IP_HERE"
| project TimeGenerated, Facility, SyslogMessage
| order by TimeGenerated asc
```

---

## Alert 1: SSH Brute Force Detection

**MITRE Tactic:** TA0006 — Credential Access  
**MITRE Technique:** T1110 — Brute Force  
**Log Sources:** auth, authpriv  
**Severity:** Medium → High if breach confirmed

### Investigation Questions
- How many attempts from how many IPs?
- What usernames were targeted?
- Did any authentication succeed?

### Step 1 — Scope: How Many Attempts and From Where?

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "Invalid user"
    or SyslogMessage contains "Failed password"
| extend AttackerIP = extract(@'(\d+\.\d+\.\d+\.\d+)', 1, SyslogMessage)
| extend Username = extract(@'Invalid user (\S+)', 1, SyslogMessage)
| summarize
    Attempts = count(),
    UsernamesTried = make_set(Username),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AttackerIP
| order by Attempts desc
```

**What to look for:** High attempt counts, many usernames = automated wordlist attack.

### Step 2 — Critical: Did Anyone Get In?

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "Accepted"
| extend AttackerIP = extract(@'(\d+\.\d+\.\d+\.\d+)', 1, SyslogMessage)
| extend Username = extract(@'Accepted \S+ for (\S+)', 1, SyslogMessage)
| project TimeGenerated, AttackerIP, Username, SyslogMessage
```

**Zero results** = No breach ✅  
**Any results** = Escalate immediately 🚨

### Step 3 — What Usernames Were Targeted?

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "Invalid user"
| extend Username = extract(@'Invalid user (\S+)', 1, SyslogMessage)
| summarize Count = count() by Username
| order by Count desc
```

**What to look for:** root, admin, ubuntu = generic wordlist. Named usernames = targeted attack using leaked credentials.

### Step 4 — Post-Breach Check (If Step 2 Returns Results)

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "session opened"
    or SyslogMessage contains "session closed"
| extend Username = extract(@'for user (\S+)', 1, SyslogMessage)
| project TimeGenerated, Username, SyslogMessage
| order by TimeGenerated asc
```

### Determination Guide

| Finding | Classification | Action |
|---|---|---|
| 0 successful auths | True Positive — Benign | Close, recommend fail2ban |
| Successful auth from attacker IP | True Positive — Breach | Escalate, isolate server |
| All from internal IPs | False Positive | Close, review rule threshold |

---

## Alert 2: Port Scan Detection

**MITRE Tactic:** TA0043 — Reconnaissance  
**MITRE Technique:** T1595 — Active Scanning  
**Log Sources:** auth, authpriv  
**Severity:** High

### Investigation Questions
- What ports were probed?
- Did the scanner follow up with exploitation?
- Is this the same IP as other alerts?

### Step 1 — Scope: Which IP and How Many Probes?

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has_any (
    "Connection closed by",
    "Did not receive identification",
    "Bad protocol version"
)
| extend AttackerIP = extract(@'(\d+\.\d+\.\d+\.\d+)', 1, SyslogMessage)
| summarize
    ProbeCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    DurationMinutes = datetime_diff('minute', max(TimeGenerated), min(TimeGenerated))
    by AttackerIP
| order by ProbeCount desc
```

### Step 2 — Did They Follow Up With SSH Brute Force?

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has_any ("Invalid user", "Failed password")
| extend AttackerIP = extract(@'(\d+\.\d+\.\d+\.\d+)', 1, SyslogMessage)
| where AttackerIP == "ATTACKER_IP_HERE"
| summarize FollowUpAttempts = count()
```

### Step 3 — Did They Also Hit the Web Server?

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| where SyslogMessage contains "ATTACKER_IP_HERE"
| extend URL = extract(@'"\w+\s(\S+)', 1, SyslogMessage)
| extend StatusCode = extract(@'"\s(\d{3})', 1, SyslogMessage)
| summarize WebRequests = count(), URLsHit = make_set(URL) by StatusCode
```

### Kill Chain Check

```
Port Scan → SSH Brute Force → Web Scan = Full reconnaissance campaign
Port Scan only              = Opportunistic automated scanner
Port Scan → Web Scan only   = Web-focused attacker
```

If same IP appears in Steps 2 AND 3 = **escalate severity to Critical**.

---

## Alert 3: Nmap Scan Detection

**MITRE Tactic:** TA0043 — Reconnaissance  
**MITRE Technique:** T1595.001 — Scanning IP Blocks  
**Log Sources:** auth, authpriv  
**Severity:** High

### Investigation Questions
- What Nmap signatures are present?
- What services were fingerprinted?
- Did they follow up with targeted attacks?

### Step 1 — Confirm Nmap Signatures

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has_any (
    "Did not receive identification string",
    "Bad protocol version identification",
    "Unable to negotiate"
)
| extend AttackerIP = extract(@'(\d+\.\d+\.\d+\.\d+)', 1, SyslogMessage)
| summarize
    SignatureCount = count(),
    Signatures = make_set(SyslogMessage),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AttackerIP
| order by SignatureCount desc
```

### Step 2 — Full Activity Timeline for This IP

```kql
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage contains "ATTACKER_IP_HERE"
| project TimeGenerated, Facility, SyslogMessage
| order by TimeGenerated asc
```

### Step 3 — Did They Follow Up With Brute Force?

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "Invalid user"
    or SyslogMessage contains "Failed password"
| extend AttackerIP = extract(@'(\d+\.\d+\.\d+\.\d+)', 1, SyslogMessage)
| where AttackerIP == "ATTACKER_IP_HERE"
| summarize FollowUpAttempts = count()
```

### Nmap Signature Reference

| Log Message | What Nmap Did |
|---|---|
| `Did not receive identification string` | TCP connect scan on SSH port |
| `Bad protocol version identification` | Version detection (-sV) |
| `Unable to negotiate` | Service/cipher enumeration |
| `Connection closed by` | SYN scan or connect scan |

---

## Alert 4: Web Scanner Detection

**MITRE Tactic:** TA0043 — Reconnaissance  
**MITRE Technique:** T1595 — Active Scanning  
**Log Sources:** local0 (Apache access log)  
**Severity:** Medium

### Investigation Questions
- What directories/files were they looking for?
- Did they find anything (200 responses)?
- What tool were they using?

### Step 1 — What URLs Did They Scan?

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| where SyslogMessage contains "ATTACKER_IP_HERE"
| extend URL = extract(@'"\w+\s(\S+)', 1, SyslogMessage)
| extend StatusCode = extract(@'"\s(\d{3})', 1, SyslogMessage)
| summarize
    Count = count(),
    URLs = make_set(URL)
    by StatusCode
| order by Count desc
```

### Step 2 — Critical: Did They Find Anything? (200 Responses)

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| where SyslogMessage contains "ATTACKER_IP_HERE"
| extend URL = extract(@'"\w+\s(\S+)', 1, SyslogMessage)
| extend StatusCode = extract(@'"\s(\d{3})', 1, SyslogMessage)
| where StatusCode == "200"
| project TimeGenerated, URL, SyslogMessage
| order by TimeGenerated asc
```

**Zero 200s** = Scanner found nothing ✅  
**200s on /admin, /phpmyadmin etc** = Exposed endpoints found 🚨

### Step 3 — What Tool Were They Using?

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| where SyslogMessage contains "ATTACKER_IP_HERE"
| extend UserAgent = extract(@'"[^"]*"\s+\d+\s+\d+\s+"([^"]*)"', 1, SyslogMessage)
| summarize Count = count() by UserAgent
| order by Count desc
```

### Status Code Reference for Web Scanning

| Status Pattern | What It Means |
|---|---|
| Mostly 404s | Wordlist scanning — looking for hidden files |
| Some 200s | Found real pages — check what they accessed |
| 403s | Found protected resources — may try to bypass |
| 301/302s | Hitting real paths that redirect |
| Mix of all | Comprehensive scanner like Nikto |

---

## Alert 5: Suspicious User Agent Detection

**MITRE Tactic:** TA0043 — Reconnaissance  
**MITRE Technique:** T1595 — Active Scanning  
**Log Sources:** local0 (Apache access log)  
**Severity:** High (tool-based, zero false positives)

### Investigation Questions
- Which specific tool was used?
- What did the tool access?
- Were any vulnerabilities probed?

### Step 1 — Identify the Tool and Scope

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| where SyslogMessage has_any (
    "nikto", "gobuster", "sqlmap",
    "nmap", "masscan", "dirbuster",
    "nuclei", "whatweb", "wfuzz"
)
| extend ClientIP = extract(@'^(\S+)', 1, SyslogMessage)
| extend URL = extract(@'"\w+\s(\S+)', 1, SyslogMessage)
| extend StatusCode = extract(@'"\s(\d{3})', 1, SyslogMessage)
| extend UserAgent = extract(@'"[^"]*"\s+\d+\s+\d+\s+"([^"]*)"', 1, SyslogMessage)
| project TimeGenerated, ClientIP, URL, StatusCode, UserAgent
| order by TimeGenerated desc
```

### Step 2 — Full Scope of the Scan

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| where SyslogMessage contains "ATTACKER_IP_HERE"
| extend StatusCode = extract(@'"\s(\d{3})', 1, SyslogMessage)
| extend URL = extract(@'"\w+\s(\S+)', 1, SyslogMessage)
| summarize
    TotalRequests = count(),
    UniqueURLs = dcount(URL),
    StatusBreakdown = make_set(StatusCode)
    by bin(TimeGenerated, 5m)
| order by TimeGenerated asc
```

### Step 3 — SQLMap Injection Attempt Check

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| where SyslogMessage contains "ATTACKER_IP_HERE"
| extend URL = extract(@'"\w+\s(\S+)', 1, SyslogMessage)
| where URL contains "'" 
    or URL contains "SELECT"
    or URL contains "--"
    or URL contains "UNION"
    or URL contains "1=1"
| project TimeGenerated, URL, SyslogMessage
```

### Tool Reference Guide

| Tool in User-Agent | What It Does | Severity |
|---|---|---|
| `nikto` | Full web vulnerability scanner | High |
| `gobuster` | Directory/file brute forcing | High |
| `sqlmap` | SQL injection testing | Critical |
| `nmap` | Network/service scanning | High |
| `masscan` | Fast port scanning | High |
| `nuclei` | Vulnerability template scanner | High |
| `whatweb` | Web technology fingerprinting | Medium |
| `wfuzz` | Web fuzzer | High |

---

## Alert 6: High HTTP Error Rate

**MITRE Tactic:** TA0043 — Reconnaissance  
**MITRE Technique:** T1595 — Active Scanning  
**Log Sources:** local0 (Apache access log)  
**Severity:** Medium

### Investigation Questions
- Is this a scanner, fuzzer or application attack?
- What is the request rate?
- What were they targeting?

### Step 1 — Error Profile of the IP

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| where SyslogMessage contains "ATTACKER_IP_HERE"
| extend StatusCode = extract(@'"\s(\d{3})', 1, SyslogMessage)
| summarize Count = count() by StatusCode
| order by Count desc
```

### Step 2 — Request Rate (Burst Detection)

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| where SyslogMessage contains "ATTACKER_IP_HERE"
| summarize RequestsPerMinute = count()
    by bin(TimeGenerated, 1m)
| order by TimeGenerated asc
```

**>100 req/min** = Automated tool  
**>500 req/min** = Aggressive scanner or DoS attempt

### Step 3 — What Were They Targeting?

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| where SyslogMessage contains "ATTACKER_IP_HERE"
| extend URL = extract(@'"\w+\s(\S+)', 1, SyslogMessage)
| extend StatusCode = extract(@'"\s(\d{3})', 1, SyslogMessage)
| where StatusCode != "200"
| summarize Count = count() by URL
| order by Count desc
| take 20
```

### Error Pattern Reference

| Error Pattern | Attack Type |
|---|---|
| Mostly 404s on /admin /wp-login | CMS scanner |
| Mostly 400s | Fuzzer sending malformed requests |
| Mostly 500s | Application attack finding vulnerabilities |
| Mix of 403 + 404 | Directory traversal attempt |
| Spike then stop | Automated one-shot scan |
| Sustained low rate | Slow scanner evading detection |

---

## Cross-Alert Correlation Queries

Use these when you want to see if the same attacker appears across multiple alert types.

### Same IP Across All Log Sources

```kql
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage contains "ATTACKER_IP_HERE"
| summarize
    EventCount = count(),
    LogSources = make_set(Facility),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Facility
| order by EventCount desc
```

### Top IPs Appearing in Both SSH and Web Logs

```kql
let SshAttackers = Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "Invalid user"
| extend IP = extract(@'(\d+\.\d+\.\d+\.\d+)', 1, SyslogMessage)
| summarize SshAttempts = count() by IP;
let WebAttackers = Syslog
| where TimeGenerated > ago(24h)
| where Facility == "local0"
| extend IP = extract(@'^(\S+)', 1, SyslogMessage)
| summarize WebRequests = count() by IP;
SshAttackers
| join kind=inner WebAttackers on IP
| project IP, SshAttempts, WebRequests
| order by SshAttempts desc
```

**Any IP in both = full kill chain attacker — highest priority investigation.**

### Attack Volume by Hour (Identify Peak Times)

```kql
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv", "local0")
| summarize Events = count() by bin(TimeGenerated, 1h), Facility
| order by TimeGenerated asc
```

---

## Incident Classification Guide

| Evidence | Classification | Determination |
|---|---|---|
| Alert fired, attack confirmed, no breach | True Positive | Benign Positive |
| Alert fired, breach confirmed | True Positive | Compromised |
| Alert fired, legitimate activity | False Positive | Incorrect alert |
| Alert fired, insufficient evidence | Undetermined | Needs more investigation |

---

## Threat Intel Quick Reference

For every attacker IP, check these sources:

| Tool | URL | What It Shows |
|---|---|---|
| AbuseIPDB | abuseipdb.com/check/IP | Abuse confidence score, reports |
| VirusTotal | virustotal.com | Multi-vendor threat intel |
| Shodan | shodan.io | What services the IP exposes |
| IPInfo | ipinfo.io/IP | Country, ISP, hosting provider |

**High risk countries for your server:** Moldova, Russia, China, North Korea, Iran — not rules, just statistically higher attack origin rates.

---

## Quick Reference Card

```
ALERT               LOG SOURCE          BREACH CHECK QUERY
─────────────────────────────────────────────────────────────
SSH Brute Force  →  auth/authpriv    →  contains "Accepted"
Port Scan        →  auth/authpriv    →  contains "Accepted" + web check
Nmap Scan        →  auth/authpriv    →  follow-up brute force check  
Web Scanner      →  local0           →  StatusCode == "200"
User Agent       →  local0           →  SQL injection patterns
HTTP Error Rate  →  local0           →  StatusCode == "200" on sensitive URLs
```

---

*This playbook is part of the SOC Home Lab project.*  
*GitHub: https://github.com/monulp/sentinel-soc-home-lab*  
*Built using Microsoft Sentinel, Azure Arc, and live internet-facing infrastructure.*
