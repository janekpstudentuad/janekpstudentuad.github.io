---
tags:
  - tryhackme
  - room
  - medium
  - offensive
  - web
  - crypto
  - scripting
---

# Signed Messages

**Platform:** TryHackMe  
**Type:** Room  
**Difficulty:** Medium  
**Link:** [Signed Messages](https://tryhackme.com/room/lafb2026e8)

## Description
*Their messages are secret, unless you find the key.*

"LoveNote built it's reputation on trust. Every message, every action, signed and verified by the system itself. LoveNoe claims that no message can be forged, no identity faked.

Yet an internal leak suggests the platform may be trusting something it shouldn't. With Valentine's Day fast approaching, the consequences of a broken trust system could be disastrous.

You can find the web application here: http://MACHINE_IP:5000"

## Initial Enumeration
Given the challenge description, I went straight in for website enumeration. I used my go-to `ffuf` command to enumerate the website:  
`ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c`. There was a hidden directory in the results that instantly drew my attention:  
![ffuf scan results](signed_messages/ffuf_scan_results.png)  

Navigating to the page reveals some very interesting information about how keys for users are generated:  
![debug page contents](signed_messages/debug_page_contents.png)

## Cryptography exploitation
The fact that we have the seed given to us in these debug messages is a pretty big vulnerability that makes forging a private key possible in its own right - it means the key generation process is "deterministic". With a deterministic key generation process, anyone with the same seed can recreate the exact same key pair. This means that knowing the seed effectively allows an attacker to regenerate another user’s private key.  As a final piece of the pzzle, we're provided with the construction sequence on this page as well.

Now. I am not very good at crypto challenges. I am still getting my head around the maths of the process, so I am far from being the best person to provide a guide on how it all works. If you want to dive deep into it, there are a whole host of resources available to look into it - I found it easiest to find a resource with a basic worked example. Since the vulnerability required reproducing the application’s key generation process programmatically, I used AI assistance to help build a Python script implementing the same deterministic construction logic described in the debug output. I don't intend to share it here, for one main reason - I realised that once I generated a forged key, I didn't actually know what to with it! (Spoiler alert - the script actually needs to do more than just forge the admin key, which is another reason for my not sharing it) Time to go back to enumeration...

## Further enumeration
Going back to my original `ffuf` results, and looking at the links available on the website, there were no further directories I wasn't aware of. As I spidered through the site, these were my findings:  

* **Home** - nothing interesting here, just the home page.  
* **Messages** - a public message board, with one message from the admin user. Nothing interesting in the content.  
* **Verify** - a page providing a way to verify that a message is actually from who it claims to be from. It requires the message, the user (the options for which are provided in a drop-down menu), and the hex digest of the message.  
* **Login** - this is a pretty simple looking login page. So simple in fact that it doesn't require a password...  
* **Register** - simple registration form.  
* **About** - a page listing the standards apparently applied to the messaging service being offered.  

There were three more points of note about the site functionality:  

* It was possible to log in as the admin user as the login functionality does not require a user password. That said, there did not appear to be anything of use once logged in.
* When registering a new user, you are provided with a key pair of your own to save locally.
* Once logged in (as either the admin or newly-registered user), two more pages become available: **Dashboard** and **Compose**. The former displays public, sent, and received messages for the user. The latter allows the user to create a message to send to another user or to the public forum.

So after all that enumeration, it still wasn't overly clear as to what the intended attack path was.

## Figuring it out
At this point, there was only one piece of discovered functionality that I hadn't interacted with yet - the **Verify** function. Looking back at the room description, I wondered whether the challenge was to craft a message and key pair that would be successfully verified as an admin message, and with that I had a way forward! I needed three things:  

* A forged private key for the admin user.  
* A message.  
* The hex digest of the message.

This is where that earlier spoiler comes in - ideally what I needed was a script that did all of these things. As before I turned to ChatGPT to help me out. The script it output was rather rough, and needed a fair bit of tweaking so I would point others to the excellent one created/tailored by [Djalil Ayed](https://github.com/djalilayed/tryhackme/blob/main/Love_at_First%20Breach/Signed_Messages/admin_signature.py), itself generated with AI, which works perfectly:  
![Script output](signed_messages/script_output.png)  

From there all that was needed was to navigate to the **Verify** page, enter the user (admin), message content (gotten either from the script content or the public message board), and the hex digest output from the script. On clicking the "Verify Signature" button underneath the form, a success message was generated:  
![Flag Success](signed_messages/flag_success.png)  
??? success "What is the flag?"
		THM{PR3D1CT4BL3_S33D5_BR34K_H34RT5}

**Tools Used**  
`ffuf` `python`

**Date completed:** 16/02/26  
**Date published:** 21/02/26