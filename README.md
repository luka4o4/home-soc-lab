Home SOC Lab with Wazuh SIEM

A self-built Security Operations Center lab used to **simulate a real attack and
detect it** with an open-source SIEM — demonstrating core SOC analyst skills:
building a monitored environment, generating attacker activity, and analysing the
resulting alerts.

Lab Architecture

Three VMs on an isolated VirtualBox network:

| Machine | Role | IP |
|---|---|---|
| Wazuh Server (Ubuntu) | SIEM | 10.0.2.4 |
| Windows 11 Endpoint | Monitored victim | 10.0.2.5 |
| Kali Linux | Attacker | 10.0.2.15 |

Kali attacks the Windows endpoint → Windows logs it → the Wazuh agent forwards
the logs → alerts appear in the Wazuh dashboard.

What I Did

Simulated an **RDP brute-force attack** (T1110) with Hydra from Kali. Wazuh
captured all failed logins and **automatically escalated them to a level-10
"Multiple Windows Logon Failures" alert**, classified as **Brute Force** under
MITRE ATT&CK.

📄 [Full writeup — including the issues I hit and how I solved them](docs/rdp-bruteforce-detection-writeup.md)

 Key Takeaway

An attack "happening" and an attack being "detected" are two different things —
detection only works when something is configured to observe and log the activity.
Most of the work was troubleshooting (scanning false negatives, network false
alarms, SIEM startup failures), which taught me more than the tools themselves.

Tools

Wazuh · VirtualBox · Kali Linux · Windows 11 · Ubuntu Server · Hydra · MITRE ATT&CK

Skills
SIEM · Log Analysis · Threat Detection · MITRE ATT&CK · Windows Event Logs · Network Troubleshooting · Linux Administration

`SIEM` · `Log Analysis` · `Threat Detection` · `MITRE ATT&CK` · `Windows Event
Logs` · `Network Troubleshooting` · `Linux Administration`
