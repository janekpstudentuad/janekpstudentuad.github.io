---
tags:
  - tryhackme
  - room
  - easy
  - offensive
  - web
  - idor
---
# Love Letter Locker

**Platform:** TryHackMe  
**Type:** Room  
**Difficulty:** Easy  
**Link:** [Love Letter Locker](https://tryhackme.com/room/lafb2026e2)

## Description
*Use your skills to access other users' letters.*

"Welcome to LoverLetterLocker, where you can safely write and store your Valentine's letters. For your eyes only?

You can access the web app here: http://MACHINE_IP:5000"

## Enumeration
Given the challenge description, I went straight in for website enumeration. I used my go-to `ffuf` command to enumerate the website:  
`ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c`. Nothing that I didn't already know about here (having already visited the site in a web browser):  
![ffuf scan results](love_letter_locker/ffuf_scan_results.png)  

Inspection of the source code for the only three discovered pages didn't turn up anything useful and there was no `robots.txt` file. As a final initial enumeration step, I ran an `nmap` service scan against the port to check versioning but there didn't appear to be anything useful for exploitation here either.

## Foothold
With no clue of any username or password, I decided to test the register function first. Registering a fake account was successful, directing me to a page where letters can be viewed (if there are any for the user) and an option to create a new letter. Helpfully, there's a tip from "Cupid" about how each letter is given a number:  
![Letter locker](love_letter_locker/letter_locker.png)  

Creating a new letter shows the number of letters in the archive has increased. Opening the letter created shows that the letter has been allocated the same number as the number of letters in the archive:  
![IDOR evidence](love_letter_locker/idor_evidence.png)  

As the reference is right there in the URL, we can try changing the number in the URL to see if we can access other letters that aren't written for us or by us (classic IDOR). Letter #2 is useless for our purpose, but letter #1 has our flag:  
![Flag success](love_letter_locker/flag_success.png)  
??? success "What is the flag?"
		THM{1_c4n_r3ad_4ll_l3tters_w1th_th1s_1d0r}

**Date completed:** 15/02/26  
**Date published:** 17/02/26