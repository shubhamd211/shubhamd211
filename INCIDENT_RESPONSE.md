# Incident Response & Cloud Threat Containment: Geo-Distributed Linux Ingress Triage

## Executive Summary

- Environment: Microsoft Azure (CentOS 7 / Rocky Linux workloads, Azure Sentinel, MDC, MDE)
- Severity: High (Active multi-source external brute-force & perimeter probing)
- Target Workloads: Enterprise DLP Server (Direct SSH exposure) & Syslog Collector (Inbound HTTPS probing)
- Resolution: Network isolation, Linux host-level forensic validation, Azure Bastion zero-trust implementation, and migration to enterprise-supported Rocky Linux

## Professional Experience

This incident response engagement was part of my hands-on cloud security operations work in a Microsoft Azure environment, where I was responsible for triage, investigation, containment, and hardening across critical Linux-based workloads. The case centered on active external reconnaissance and authentication abuse targeting exposed service endpoints, with emphasis on validating whether the hostile activity had resulted in compromise, persistence, or lateral movement.

The immediate risk profile was elevated due to direct public exposure of administrative access and adjacent workload exposure to internet-originated scanning. My role involved correlating telemetry from Azure Defender for Cloud, Defender for Endpoint, and Azure Sentinel, conducting host-level validation on Linux systems, and enforcing network controls to contain the risk without disrupting mission-critical services.

## 1. Threat Identification & Detection Pipeline

### Initial Alert Telemetry

- Microsoft Defender for Cloud (MDC): Flagged anomalous inbound network spikes and high-frequency authentication failures targeting port 22.
- Microsoft Defender for Endpoint (MDE): Alerted on repetitive failed authentication signatures. Due to custom OS build constraints limiting automated live response agents, containment shifted to Azure network-level controls.
- Attack Profile: Distributed credential brute-force attacks from diverse geolocations targeting port 22 on the DLP server, accompanied by simultaneous port 443 scanning against adjacent Sentinel Syslog forwarders over a weekend maintenance window.

### Detection Engineering (KQL)

Query deployed in Azure Sentinel to correlate failed authentication volume and group distributed adversary source IPs over the critical 48-hour event window:

```kql
Syslog
| where TimeGenerated >= ago(48h)
| where ProcessName in ("sshd", "ssh")
| where SyslogMessage has_any ("Failed password", "authentication failure", "Invalid user")
| extend HourOfDay = hourofday(TimeGenerated)
// Filter for high-risk weekend window (19:00 to 08:00)
| where HourOfDay >= 19 or HourOfDay <= 8
| extend ExtractedIP = extract(@"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", 1, SyslogMessage)
| summarize AttemptCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by ExtractedIP, HostName, ProcessName
| where AttemptCount > 10
| order by AttemptCount desc
```

## 2. Host Forensics & Triage Methodology

Prior to network isolation, non-invasive forensic checks were conducted on the CentOS DLP host to verify whether unauthorized execution, lateral movement, or persistence had taken place:

```bash
# 1. Inspect recent failed vs. accepted logins
grep -E "Failed|Accepted" /var/log/secure | tail -n 50

# 2. Verify integrity of administrative SSH keys
cat ~/.ssh/authorized_keys
ls -la ~/.ssh/

# 3. Check for unauthorized scheduled persistence
crontab -l
ls -la /etc/cron* /var/spool/cron/

# 4. Audit environment profile tampering
stat ~/.bashrc ~/.bash_profile /etc/profile

# 5. Check active network listeners and raw sockets
ss -tulpn
```

Findings: All attempts resulted in authentication failure. No unauthorized keys, modified cron entries, reverse shells, or modified shell execution scripts were identified.

## 3. Incident Containment & Escalation Protocol

Stakeholder Escalation: Escalated live findings directly to Cloud Infrastructure Administration, SOC Leadership, and CISO.

Emergency Network Quarantine:

- Modified Azure Network Security Group (NSG) inbound rules to immediately block external port 22 and port 443 traffic from unverified public IP blocks.
- Leveraged Azure Virtual Network isolation to contain the workload without data loss.

Continuous Monitoring:

- Established automated 7-day Sentinel correlation rules to detect subsequent distributed probing against perimeter subnets.

## 4. Root-Cause Remediation & Architecture Hardening

| Vulnerability Vector | Remediation Applied | Security Outcome |
| --- | --- | --- |
| Direct SSH exposure (Port 22) | Implemented Azure Bastion | Administrative access is routed over TLS without public IP exposure. |
| Legacy / Custom OS | Upgraded to Rocky Linux | Restored OS-level compatibility with modern EDR sensors (MDE) and patching channels. |
| Decentralized SSH Keys | Migrated secrets to Azure Key Vault | Enforced RBAC and audit logging; stopped reliance on local key stores. |
| Network Perimeter Posture | Closed unused public inbound NSG rules | Enforced default-deny ingress architecture across perimeter subnets. |

## Key Takeaways

This incident reinforced the importance of defense-in-depth on Linux infrastructure in public cloud environments. The most critical issues were not necessarily malicious execution, but the exposure of administrative paths and the lack of modern endpoint compatibility in a legacy operating system model. By combining Azure-native controls, host-level verification, and architecture modernization, the environment was stabilized while reducing the likelihood of repeat compromise.

## Architecture Overview

### Vulnerable Direct-SSH Topology

```text
Internet
   |
   |-- SSH (22) --> DLP Server (Public IP exposure)
   |
   |-- HTTPS (443) --> Syslog Collector (Public service exposure)

Threat Activity:
- External credential brute force
- Distributed source IP scanning
- Failed authentication flood / perimeter probing
```

### Hardened Azure Bastion & Key Vault Topology

```text
Internet
   |
   |-- Azure Bastion (TLS-secured admin access)
   |        |
   |        +--> Private-only admin path to workloads
   |
   |-- NSG / VNet segmentation
   |        |
   |        +--> Deny unused public ingress
   |
   |-- Azure Key Vault
             |
             +--> Centralized SSH secrets / RBAC / auditing

Workloads:
- Rocky Linux hardened hosts
- MDE-compatible endpoint posture
- Reduced public attack surface
``` 

## Conclusion

This engagement demonstrates my practical experience in identifying, containing, and remediating cloud security incidents affecting Linux workloads in Azure. The work combined SOC-style detection engineering, Linux forensic validation, emergency network containment, and long-term security architecture remediation. It reflects the type of hands-on triage and risk reduction work I perform in enterprise cloud security operations and consulting engagements.

---

This entry is included as part of my professional experience and demonstrates a real-world cloud incident response and infrastructure hardening scenario in Azure.
