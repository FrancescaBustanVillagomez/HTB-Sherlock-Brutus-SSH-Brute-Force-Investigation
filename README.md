# HTB-Sherlock-Brutus-SSH-Brute-Force-Investigation

## Scenario

> A Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using `auth.log`.

The target is a Confluence server (an internal wiki/collaboration space used by companies for documentation, project notes, and configuration credentials), hosted on an AWS EC2 instance. The goal of the investigation is to reconstruct the attack timeline starting from the provided log artifacts: `auth.log` and `wtmp`.

## Artifacts Analyzed

| File | Description |
|---|---|
| `auth.log` | Linux authentication log (SSH, sudo, PAM) — failed/successful login attempts, privilege escalation. |
| `wtmp` | Binary log of system logins/logouts/reboots, read using `utmpdump`. |

## Methodology

### 1. Target Server Identification

The hostname present in every line of `auth.log` follows the AWS convention `ip-<private-address>`, revealing the internal IP of the Confluence server itself.

### 2. Isolating Successful Logins

```bash
grep -i accepted auth.log
```
`grep -i` (case-insensitive) filtra le righe contenenti un login riuscito, escludendo il rumore dei tentativi falliti.

### 3. Distinguishing Between the Expected Administrative Account and a Potential Anomalous Account
```bash
grep -i accepted auth.log | grep -iv root
```

`-v inverts the grep logic, showing lines that do not contain "root" — useful for bringing out successful logins for users other than the expected administrative one, often indicative of an account created or compromised by the attacker.
### 4. Analysis of Failed Attempts and Frequency of Tested Usernames
```bash
grep -i 'failed password' auth.log | grep -iv invalid | cut -d ' ' -f 10 | sort | uniq -c | sort -nr
```

- `cut -d ' ' -f 10` extracts the column of the attempted username
- `sort | uniq -c | sort -nr` produces an ordered ranking by frequency, from the most attempted username to the least

### 5. OSINT on the Source IP

```bash
curl ipinfo.io/<ip_sorgente>
```
Enriching the identified IP with public information (hostname, geolocation, provider) via the `ipinfo.io`service to contextualize the attack's origin (in this case, an AWS EC2 instance).

### 6. Reconstruction of Post-Exploitation Actions

```bash
grep -i <username_compromesso> auth.log
```

Filtering all lines related to the compromised user reveals, in sequence:
- account creation
- addition to the `sudo` group (administrative privileges)
- actual login from the attacker's IP
- execution of `sudo cat /etc/shadow`, attempt to exfiltrate system password hashes
- download via `curl` of a script from GitHub, traceable to an enumeration tool for privilege escalation (LinPEAS family)

### 7. Manual Login Timeline via wtmp

```bash
utmpdump wtmp
```

`wtmp` is a structured binary file (not text), read via utmpdump to obtain a readable timeline of logins/logouts/reboots, complementary to `auth.log`.

## Main Findings

- **Attack Vector:** SSH brute force against an exposed Confluence server
- **Attack Origin:** AWS EC2 instance,`ap-south-1` region (Mumbai, India)
- **Most Tested Usernamesi:** `backup`, `root` (among the most common in an automated brute force attack)
- **Outcome:** Successful compromise, with the creation of a new account added to the`sudo` group
- **Post-exploitation:** Attempted access to `/etc/shadow` and download of an enumeration script for privilege escalation from GitHub

## Lessons Learned

- The importance of combining `grep/cut/sort/uniq` in pipelines to transform raw logs into structured information.
- The difference between textual (`auth.log`) and binary (`wtmp`) log formats, and the correct tools for each.
- How a single suspicious event (successful login on an unexpected user) can pave the way to reconstructing the entire attack chain.
- The value of OSINT (`ipinfo.io`) to quickly contextualize a source IP during an investigation.

---

Writeup created for personal learning purposes, without including the specific answers required by the HTB platform Tasks.
