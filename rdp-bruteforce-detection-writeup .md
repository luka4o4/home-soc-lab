# Detecting an RDP Brute-Force Attack with Wazuh

**Project:** Home SOC Lab — Attack Simulation & Detection
**Attack type:** RDP Brute-Force (MITRE ATT&CK: T1110 – Brute Force)
**Tools used:** Kali Linux (attacker), Hydra, Windows 11 endpoint (target), Wazuh SIEM

---

## Objective

Simulate a real-world attack that a SOC analyst sees constantly — an attacker
repeatedly guessing passwords against a Windows machine's Remote Desktop (RDP)
service — and confirm that the Wazuh SIEM detects it. Unlike a raw port scan
(which Windows does not log by default), failed logins **are** logged by Windows,
which makes this attack reliably detectable.

---

## Lab Setup Recap

| Machine | Role | IP Address |
|---|---|---|
| Kali Linux | Attacker | 10.0.2.15 |
| Windows 11 Endpoint | Target (victim) | 10.0.2.5 |
| Wazuh Server | SIEM (collects & analyses logs) | 10.0.2.4 |

All three run on an isolated VirtualBox NAT Network ("SOC LAB"). The Windows
endpoint runs the Wazuh agent, which forwards its security logs to the Wazuh
server.

---

## What I Did (Step by Step)

1. **Enabled Remote Desktop (RDP) on the Windows endpoint** so there was a login
   service to attack.
2. **Opened port 3389 (RDP) through the Windows Firewall** so the attacker
   machine could reach it.
3. **Installed Hydra** on Kali — a tool that automatically tries many
   username/password combinations against a login service.
4. **Ran the brute-force attack** from Kali against the Windows RDP service using
   a list of common passwords.
5. **Confirmed the attack was detected** in the Wazuh dashboard as a series of
   Windows failed-logon events (Event ID 4625).

The command used for the attack:

```
hydra -l administrator -P passwords.txt -t 1 -f 10.0.2.5 rdp
```

- `-l administrator` → the username to target
- `-P passwords.txt` → the list of passwords to try
- `-t 1` → one attempt at a time (RDP is sensitive to parallel connections)
- `-f` → stop if a valid password is found
- `10.0.2.5 rdp` → the target machine and the service to attack

---

## Issues I Encountered and How I Solved Them

This is the part that reflects real troubleshooting. Each problem below is
something I diagnosed and fixed rather than something that "just worked."

### 1. Port scanner reported RDP as "closed" when it was actually open

**Symptom:** After enabling RDP and opening the firewall, my initial port scan
(`masscan`) kept reporting no open ports on the Windows machine.

**Diagnosis:** I did not trust a single tool. I re-tested the same port with a
different tool, `netcat` (`nc -zv 10.0.2.5 3389`), which reported the port as
**open (ms-wbt-server)**.

**Root cause:** `masscan` was unreliable when scanning a single port and gave a
false negative. RDP had been reachable the whole time.

**Lesson:** Confirm findings with a second tool before drawing conclusions. A
single scanner's "closed" result is not proof a port is closed.

### 2. "100% packet loss" that turned out to be a false alarm

**Symptom:** Pinging the Windows machine from Kali returned 100% packet loss,
suggesting the two machines could not communicate at all.

**Diagnosis:** I tested connectivity in the opposite direction (Windows → Kali)
and to a third machine (Kali → Wazuh server). Both of those worked perfectly.

**Root cause:** Windows Firewall silently blocks incoming ping (ICMP) by default.
The network was healthy; only ping replies were being dropped.

**Lesson:** A failed ping does not always mean a broken network. Windows blocking
ICMP is normal and expected — test connectivity from multiple angles before
assuming a network fault.

### 3. Hydra rejected the target with "Invalid target definition"

**Symptom:** My first Hydra command used the `rdp://10.0.2.5` format, which the
installed version of Hydra (9.7) rejected.

**Fix:** I rewrote the command to pass the target IP and the module as separate
arguments at the end (`... 10.0.2.5 rdp`), which the tool accepted.

**Lesson:** Command syntax changes between tool versions. Read the error message —
it literally told me which two formats were valid.

### 4. Hydra could not find the rockyou.txt password list

**Symptom:** Hydra reported `File for passwords not found:
/usr/share/wordlists/rockyou.txt`.

**Root cause:** On modern Kali, the well-known `rockyou.txt` wordlist ships
compressed (`rockyou.txt.gz`) and is not present at that path until extracted.

**Fix:** Since the goal was only to *generate failed logins* (not to actually
crack the password), I created a small custom password list of common passwords
and pointed Hydra at that instead. This was faster and avoided the missing-file
issue entirely.

**Lesson:** Match the tool to the goal. I did not need 14 million passwords to
prove detection works — I needed a handful of failed attempts.

---

## The Detection

When Hydra ran, each failed password attempt caused Windows to record a
**failed logon event (Windows Event ID 4625)**. The Wazuh agent on the Windows
endpoint forwarded these events to the Wazuh server, where they appeared in the
**Threat Hunting** view.

To find them in Wazuh, I filtered the events with:

```
data.win.system.eventID:4625
```

**What Wazuh showed (9 events from the `windows-endpoint` agent):**

| Wazuh Rule | Rule ID | Level | Meaning |
|---|---|---|---|
| Logon Failure – Unknown user or bad password | 60122 | 5 | Each individual failed login attempt |
| **Multiple Windows Logon Failures** | **60204** | **10** | **Wazuh recognised the brute-force *pattern* and raised a higher-severity alert** |

The key insight: Wazuh did not just log the individual failures. Its correlation
engine noticed **several failed logins from the same source in a very short
window** and automatically fired a **higher-severity (level 10) alert —
"Multiple Windows Logon Failures" (rule 60204)**. This is the difference between
raw logging and real detection. Instead of forcing an analyst to eyeball nine
separate failures, Wazuh produced one clear alert saying "this looks like a
brute-force attack."

**Evidence of automation:** the individual failure timestamps were only ~2
seconds apart (e.g. 18:31:57, 18:31:59, 18:32:01, 18:32:03…). A human does not
fail logins every two seconds — that rapid, regular cadence is the fingerprint of
an automated brute-force tool.

Wazuh also **automatically classified the activity under MITRE ATT&CK as
"Brute Force"** in its dashboard, and the timeline graph showed a sharp spike —
the visual signature of the attack landing in a short burst.

### Analyst Observation (attribution nuance)

When I drilled into an individual failed-logon event, I noticed the logged
source (`data.win.eventdata.ipAddress`) was **`127.0.0.1`** with **logon type 2
(interactive)**, rather than the attacker's real IP (`10.0.2.15`) with a network
logon type. In other words, the alert fired correctly, but the event's recorded
source did **not** directly point to the true origin of the attack.

In a real investigation this matters: an analyst should not assume the IP in a
single event is the attacker. To confirm the real source, I would correlate these
authentication failures with **network-layer logs** (e.g. firewall/connection
logs, or Sysmon network events) that show the inbound RDP connection from
`10.0.2.15`. This is a good reminder that a single log source often tells only
part of the story, and reliable attribution usually requires correlating
multiple sources.

The failure codes in the event confirmed the nature of the attempts:
`status 0xc000006d` / `subStatus 0xc000006a` = **bad password**, and
`failureReason %%2313` = **unknown user name or bad password** — consistent with
a brute-force guessing attack.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | T1110 |

Note: Wazuh mapped this activity to **Brute Force** automatically in its MITRE
ATT&CK dashboard — the classification was demonstrated by the tool, not just
asserted by me.

---

## Evidence / Screenshots Included

1. **Attacker side** – Hydra running against `10.0.2.5` over RDP, attempting
   passwords.
2. **Detection overview** – Wazuh Threat Hunting dashboard showing 9
   authentication failures, the attack spike on the timeline, and the automatic
   **Brute Force** MITRE classification.
3. **Event list (smoking gun)** – the 9 failed-logon events from the
   `windows-endpoint` agent, including the individual `60122` failures and the
   escalated **level-10 `60204` "Multiple Windows Logon Failures"** alert, with
   timestamps ~2 seconds apart.
4. **Event drill-down** – one expanded event showing the source IP
   (`10.0.2.15`, the Kali attacker), the targeted username, and the rule details.
5. **Monitored endpoint** – the Wazuh agent detail view confirming the Windows
   endpoint is active and reporting.

---

## Key Takeaways

- **An attack happening and an attack being detected are two different things.**
  Detection only works if something is configured to observe and log the
  activity. A raw port scan went undetected (Windows does not log it), but failed
  RDP logins were detected because Windows logs them and the agent forwarded them.
- **Troubleshooting is the real skill.** Most of my time was spent diagnosing
  false negatives (masscan), false alarms (ICMP-blocked ping), tool-version
  syntax, and a missing wordlist — not running the final command.
- **Verify with a second tool.** `netcat` corrected `masscan`'s false negative;
  reverse-direction pings corrected the false "network down" conclusion.

---

## Next Steps (Detection Improvement)

- Make the earlier port scan detectable by adding **Sysmon** (which logs network
  connections) to the Windows endpoint.
- Tune / confirm the Wazuh rule that groups many 4625 events into a single
  higher-level "multiple authentication failures" alert, so an analyst sees one
  clear brute-force alert instead of dozens of individual failures.
