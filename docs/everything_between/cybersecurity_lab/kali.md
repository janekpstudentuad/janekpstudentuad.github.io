# Kali Linux "Attacker" Workstation - Kali
## Create Virtual Machine
After downloading the VMHD for Kali Linux (available [here](https://www.kali.org/get-kali/#kali-virtual-machines)):  

* Open the virtual machine in VMware Workstation Pro (File > Open)  
* (optional) Rename the virtual machine as required  
* Add a second network adapter connected to the custom VMnet network  

## Post-creation Configuration
* Power on the virtual machine and update (`sudo apt update && sudo apt full-upgrade -y`)  
* Change the timezone (if required)  
* Change the keyboard layout (if required)  
* (optional but highly recommended) Shut down and take snapshot of fresh OS installation  

## Install Additional Tools
*Most of the following could be automated into a single `bash` script very easily. I have left everything separated out for transparency and adaptability*  
*As an optional (but recommended) step, a snapshot can be taken after each batch of tools are installed*
### Pen Test and CTF tools
```
sudo apt install -y netcat-openbsd seclists dirsearch gdb gdb-multiarch apktool bettercap bloohound docker.io docker-compose rizin-cutter
```
Unzip `rockyou.txt`:
```
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz
```
Add current user to the Docker group:
```
sudo usermod -aG docker $USER
```
Download Atomic Red Team scripts:
```
mkdir <gitRepoSaveDirectory>    # Optional
git clone https://github.com/redcanaryco/atomic-red-team.git <gitRepoSaveDirectory>/atomic-red-team
```
Initialise Metasploit Framework database:
```
sudo msfdb init
```
Sliver C2 installation:  
```
cd <gitRepoSaveDirectory>   # Optional based on above mkdir command
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux-amd64
wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux-amd64
chmod +x sliver-*
sudo mv sliver-server_linux-amd64 /usr/local/bin/sliver-server
sudo mv sliver-client_linux-amd64 /usr/local/bin/sliver-client
```
### VPN and networking tools
```
sudo apt install -y wireguard htop
```
### Additional programming language tools
```
sudo apt install -y golang-go ruby-full openjdk-21-jdk jq
```
Set global config settings for `git`:  
```
git config --global user.name <name>
git config --global user.email <emailAddress>
```
Download VSCode installer from [here](https://code.visualstudio.com/download), then run `sudo dpkg -i Downloads/<fileName>`
### Setup Python virtual environment
```
python3 -m venv <venvLocaltion>
source <venvLocaltion>/bin/activate
pip install pwntools bs4 dnspython python-whois yara-python impacket sublist3r
```
### Reverse engineering
```
clone https://github.com/pwndbg/pwndbg.git <gitRepoSaveDirectory>/pwndbg
./<pwndbgSaveDirectory>/setup.sh
echo "alias pwn='cd ~/gits/pwn'" >> ~/.zshrc
sudo apt install -y openjdk-11-jdk gnupg2 ghidra
```
### Active Directory/Windows tools
```
sudo apt install -y crackmapexec winbind krb5-user libnss-winbind libpam-winbind
sudo gem install evil-winrm
```
### OSINT tools
```
sudo apt install -y sublist3r
```
### Steganography tools
```
sudo gem install zsteg
mkdir <stegsolveSaveDirectory>  # Optional
cd <stegsolveSaveDirectory>     # Optional based on the above command
wget https://github.com/eugenekolo/sec-tools/raw/master/stego/stegsolve/stegsolve/stegsolve.jar
```
### Browser plugins
Allow all access to private windows and pin to toolbar:  

* Cookie Editor ([download](https://addons.mozilla.org/en-GB/firefox/addon/cookie-editor/))  
* FoxyProxy ([download](https://addons.mozilla.org/en-GB/firefox/addon/foxyproxy-standard/))  
* Wappalyzer ([download](https://addons.mozilla.org/en-GB/firefox/addon/wappalyzer/))  

Add FoxyProxy Burp/ZAP route: 

* Click on FoxyProxy icon in browser  
* Options > Proxies > Add  
* Title: as desired  
* Hostname: 127.0.0.1  
* Port: 8080  
* Save

Configure Burp Suite for HTTPS connections:  

* Open Burp Suite  
* Enable Burp route in FoxyProxy  
* Navigate to https://burp, accepting security risk through "Advanced" options  
* Click "CA Certificate" (certificate will download)  
* Open Firefox settings  
* Search for "certificates"  
* View Certificates  
* Import  
* Select downloaded certificate  
* Check box for identifying websites > OK > OK
## Setup Bloodhound
```
sudo neo4j console
# Open new terminal tab
sudo bloodhound-start
```
Login to neo4j console in launched browser window using default credentials provided by `bloodhound-start` command  
Change password  
Edit `/etc/bhapi/bhapi.json` file to include new password (`secret` parameter in `neo4j` stanza)
## Nessus
In the first iteration of my home lab, I installed Nessus as a vulnerability scanner Since that time, Tenable (who make Nessus) have changed the licensing model so that home users receive a 30-day free trial, limited to 5 IP addresses, before the data and setup is rendered useless. As such, I have decided not to include instructions for its installation here. It is possible to buy a home license, which is relatively inexpensive, but I am keen to keep this guide as something that anyone can do without any financial ties. Going forward, I may consider installing Greenbone as an alternative, though my previous experience with it has left me feeling frustrated. Should I choose to incorporate this as a component at a later time, or if I invest in a Nessus license, the notes will be updated accordingly.
## Static IP Address
The NAT adapter for this virtual machine will get an IP address by DHCP natively. It's much more convenient for the custom VMnet adapter to be set statically (think reverse shells). This is best done using a host address that will never be given out from the DHCP scope on the DC (I used the .50 host address):  
```
ip a    # Find name of network adapter in VMnet custom network
sudo nmcli con add type ethernet ifname <adapterName> con-name HostOnlyStatic ip4 <desiredIpAddress>/24
sudo nmcli con mod HostOnlyStatic ipv4.dns <dcIpAddress>
sudo nmcli con up HostOnlyStatic
```
## Snapshot!
This is, as ever, optional. 