---
tags:
  - tryhackme
  - room
  - easy
  - offensive
  - web
  - unrestricted-file-upload
---

# Speed Chatting

**Platform:** TryHackMe  
**Type:** Room  
**Difficulty:** Easy  
**Link:** [Speed Chatting](https://tryhackme.com/room/lafb2026e4)

## Description
*Can you hack as fast as you can chat?*  

"Days before Valentine's Day, TryHeartMe rushed out a new messaging platform called "Speed Chatter", promising instant connections and private conversations. But in the race to beat the holiday deadline, security took a back seat. Rumours are circulating that "Speed Chatter" was pushed to production without proper testing.

As a security researcher, it's your task to break into "Speed Chatter", uncover flaws, and expose TryHeartMe's negligence before the damage becomes irreversible.

You can find the web application here: http://MACHINE_IP:5000"

## Initial Enumeration
Visitng the web page reveals a chatbot with a file upload functionality, apparently so that you can updte your profile picture. Looking at the source code suggests that the profile picture being displayed is atually being source from an external website:  
![Home page source code](speed_chatting/home_page_source_code.png)  

The source code also reveals that the destination web application is running Flask (a Python framework) and that the page is refreshed every 3 seconds to get the chat messages. Attempting to upload a reverse shell from [PayloadsAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#python) shows that uploading a `.py` file is possible.  
![Upload successful](speed_chatting/upload_successful.png)  

I set up a local `nc` listener prior to uploading the shell (remember, the page automatically refreshes every 3 seconds - this includes the loading of the file allocated to the profile for the profile image), removed the `python -c` prefix from a reverse shell from PayloadsAllTheThings (because that prefix is specific to executing the reverse shell from a command line, not from within a self-contained .py file) and got a connection back to my attacking machine. From there, getting the flag was trivial:  
![Flag success](speed_chatting/flag_success.png)  
??? success "What is the flag?"
		THM{R3v3rs3_Sh3ll_L0v3_C0nn3ct10ns}

**Tools Used**  
`nc`

**Date completed:** 14/02/26  
**Date published:** 17/02/26