INCIDENT #30 — SSH Brute Force Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Classification:  TRUE POSITIVE
Outcome:         ATTACK FAILED — No Breach
Severity:        Medium

ATTACK DETAILS
━━━━━━━━━━━━━━
Duration:        ~75 minutes (10:25 AM onwards)
Peak:            ~1,820 attempts at 6 AM wave
Total attempts:  2,326 brute force attempts
Attacker IPs:    7 IPs across 7 countries
Usernames tried: root, admin, user, zjw + wordlist

ATTACKER INFRASTRUCTURE
━━━━━━━━━━━━━━━━━━━━━━━
USA (x2), Hong Kong, Vietnam, 
Netherlands, Mexico, Moldova
Pattern: Distributed botnet (coordinated timing)

VERDICT
━━━━━━━
All attempts blocked at [preauth] stage
Zero successful authentications confirmed via KQL
No lateral movement possible
No post-exploitation activity
