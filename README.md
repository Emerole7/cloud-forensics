# Cloud Forensics Investigations

Cloud incident-response investigations from [CyberDefenders](https://cyberdefenders.org/), each documented as a SOC-style report: reconstructing an attacker's path through **AWS CloudTrail** logs in a SIEM (Splunk) — from the initial account compromise, to data access, to the persistence and privilege-escalation they set up — mapped to MITRE ATT&CK.

**Core skills:** CloudTrail log analysis, AWS API event interpretation, SIEM querying (Splunk SPL), identity & S3 abuse detection, MITRE ATT&CK mapping.

**Tools:** Splunk, AWS CloudTrail.

## Investigations

| Lab | Focus | Key tools | ATT&CK | Status |
|---|---|---|---|---|
| [AWSRaid](awsraid/) | CloudTrail hunt: brute-forced login → S3 exfil → public bucket → persistence & priv-esc | Splunk, AWS CloudTrail | T1110, T1530, T1136, T1098 | **Done** |
| [AZUREHUNT](azurehunt/) | Entra ID hunt in Elastic: sign-in from Germany → Blob exfil → lateral move to admin → VM start & DB export → backdoor user & Owner role | Elastic (ELK) | T1078.004, T1530, T1537, T1136.003, T1098.003 | **Done** |



## Responsible disclosure

- Write-ups are for **retired** labs. Screenshots are redacted of personal account identifiers.

---
Built by **Prosper Emerole** · [github.com/Emerole7](https://github.com/Emerole7) · Part of my blue-team investigation portfolio.
