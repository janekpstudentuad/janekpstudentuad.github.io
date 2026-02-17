---
tags:
  - tryhackme
  - room
  - easy
  - offensive
  - web
---

# Hidden Deep Into my Heart
**Platform:** TryHackMe  
**Type:** Room  
**Difficulty:** Easy  
**Link:** [Hidden Deep Into my Heart](https://tryhackme.com/room/lafb2026e9)

## Description
*Find what's hidden deep inside this website.*

"My Dearest Hacker,
Cupid's Vault was designed to protect secrets meant to stay hidden forever. Unfortunately, Cupid underestimated how determined attackers can be.

Intelligence indicates that Cupid may have unintentionally left vulnerabilities in the system. With the holiday deadline approaching, you've been tasked with uncovering what's hidden inside the vault before it's too late.

You can find the web application here: http://MACHINE_IP:5000"

## Initial Enumeration
Given the clue provided, we start with simply by checking to see if there's a `robots.txt` file with entries, and we're in luck:  
![robots.txt](hidden_deep_into_my_heart/robots.txt_content.png)  

There's also some interesting looking text at the underneath the Disallow entry. No use for that at this point, but something to bear in mind

Navigating to the directory from `robots.txt`, and to the home page, reveals a static web page with nothing in the source code to help us out. The text on the "secret" directory tells us we're on the right track though:  
![Secret directory content](hidden_deep_into_my_heart/secret_directory_content.png)

I used my go-to `ffuf` command to enumerate the website:  
`ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic`. This didn't yield anything for the home page but when I ran it against the newly discovered "secret" directory, I got a hit:  
![ffuf scan results](hidden_deep_into_my_heart/ffuf_scan_results.png)  

Navigating to the discovered directory, we're greeted with a sign-in page. Remembering that strange text we saw earlier, and bearing in mind that this is an "administrator" page, I tried `administrator:cupid_arrow_2026!!!`, only to be greeted with an "Invalid credentials" message. When I tried with `admin` as the username on the other hand:  
![Flag found](hidden_deep_into_my_heart/flag_found.png)  

??? success "What is the flag?"
		THM{l0v3_is_in_th3_r0b0ts_txt}

**Tools Used**  
`ffuf`

**Date completed:** 14/02/26  
**Date published:** 17/02/26