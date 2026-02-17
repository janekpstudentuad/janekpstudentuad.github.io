---
tags:
  - tryhackme
  - room
  - easy
  - offensive
  - web
  - jwt
---
# TryHeartMe

**Platform:** TryHackMe  
**Type:** Room  
**Difficulty:** Easy  
**Link:** [TryHeartMe](https://tryhackme.com/room/lafb2026e5)

## Description
*Access the hidden item in this Valentine's gift shop.*  

"The TryHeartMe shop is open for business. Can you find a way to purchase the hidden “Valenflag” item? 
You can access the web app here: http://MACHINE_IP:5000"

## Enumeration
Given the challenge description, I went straight in for website enumeration. I used my go-to `ffuf` command to enumerate the website:  
`ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c`. Nothing much interesting here (not yet anyway):  
![ffuf scan results](tryheartme/ffuf_scan_results.png)

After looking around the site, checking for `robots.txt`, and examining the source code, I concluded there were no low hanging fruits to be had and decided to move into gaining an account using the "Register" link at the top of the page.

## Foothold
Using a fake email address (`test@test.com:password`) to gain an account was trivial, and as soon as I logged in I was supplied with a site cookie. The name of the cookie suggested it was a JWT token:  
![JWT cookie](tryheartme/jwt_token.png)  

Using an online [JWT decoder](https://www.jwt.io/) showed the token value was able to be decoded and furthermore had a user role assigned:  
![JWT contents](tryheartme/jwt_contents.png)  

Using the same online tool, I moved to the encoding function and changed the user role from "user" to "admin" before copying the encoded value and pasting it into the cookie value on the site (using Developer Tools). Refreshing the page after doing this resulted in a new "Admin" button being made available:  
![Admin login successful](tryheartme/admin_login_successful.png)  

Navigating to this admin area reveals the hidden shop item that we are looking for:  
![valenflag](tryheartme/valenflag.png)  

Clicking "Open Valenflag" and then "Buy" revealed the flag:  
![Flag success](tryheartme/flag_success.png)  
??? success "What is the flag?"
		THM{v4l3nt1n3_jwt_c00k13_t4mp3r_4dm1n_sh0p}

**Tools Used**  
[JWT decoder](https://jwt.io)

**Date completed:** 14/02.26  
**Date published:** 17/02/26