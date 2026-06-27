# Ubuntu Server - Splunk
## Create Virtual Machine
After downloading the ISO for Ubuntu Server (available [here](https://ubuntu.com/download/server)), create a new virtual machine in VMware Workstation Pro (File > New Virtual Machine), with the following settings:  

* Typical (Recommended) configuration  
* Installer disc image file: Ubuntu Server ISO  
* Virtual machine name: Splunk  
* Location: desired location for VMHD files  
* Specify Disk Capacity options: increase size to 60GB  
*This is necessary for Splunk installation - will fail if disk is less than this*  
## Operating System Installation
*Use default network adapter (NAT) during OS installation - add custom VMnet once installation completed*  
Power on the virtual machine and proceed with Ubuntu installation using the following settings:  

* Language/keyboard layout: as required  
* Type of installation: Ubuntu Server  
* Accept all other defaults  
* Name: as desired  
* Server name: Splunk  
* Username/password: as desired  
* Skip Ubunto Pro installation  
* Enable SSH server  
* Skip additional program installation  
## Post OS Installation Configuration
Once the OS has finished installing:  

* Disconnect (or remove) CD drive  
* Apply updates (`sudo apt update && sudo apt full-upgrade -y`)  
* (optional) take snapshot of fresh installation  
## Extend Hard Drive
Due to the way that VMware hard drives are dynamically allocated, you need to "claim" the hard drive space that has not yet been occupied with data. The Splunk installation will fail if this is not done!  
```
# Find partition number
lsblk
# Grow partition
sudo growpart /dev/sda<partitionNumber>
sudo pvresize /dev/<partition>
# Find logical volume name
sudo lvdisplay
# Extend volume
sudo lvextend -l +100%FREE /dev/<logicalVolume>
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
```
Snapshot after complete
## Splunk Installation
You will need to register for a Splunk account before you can download the Splunk binary but once you have done so, you will be able to use Splunk for free with a 500MB ingest daily limit (correct at time of writing). Once you have an account, the `wget` command to obtain the Splunk binary can be obtained from [here](https://www.splunk.com/en_us/download/splunk-enterprise.html) and pasted into the virtual machine terminal using Edit > Paste within Workstation Pro. Once downloaded, proceed with installation:  
```
sudo dpkg -i <fileName>
cd /opt/splunk/bin
sudo ./splunk start --accept-license --run-as-root  # Set admininstrator username and password as desired
sudo chown -R splunk:splunk /opt/splunk             # Required for start on boot to work
sudo ./splunk enable boot-start -user splunk        # Start service on boot
```
Snapshot after complete
## Post Splunk-installation Configuration
### Enable SSH
```
sudo systemctl enable ssh
sudo systemctl start ssh
```
### Add second network adapter
The Splunk machine requires the NAT connection to satisfy software requirements (in order for it to get updates) but in its current state, it has no way of speaking to the machines in the customer VMnet network. As such, a second network adapter is required, this one connected to that custom VMnet network. Once the second adapter has been added, it's a good idea to set a static IP address (I used the .20 host address from my custom VMnet network) to ensure there are no issues with endpoints sending data to the indexer following their configuration.  
Setting the static IP address for the second network adapter:  

* Ascertain the adapter names (`ip a`)  
* Create and open a new file for setting network configuration (`sudo nano /etc/netplan/01-static.yaml`)  
* Add the following configuration to the new file:
```
network:
  version: 2
  ethernets:
    <hostOnlyAdapterName>:
      dhcp4: no
      addresses:
        - <staticIpAddress>/24
      gateway4: <dcIpAddress>
      nameservers:
        addresses:
          - <dcIpAddress>
    <natAdapterName>:
      dhcp4: yes
```
* Save and exit the file  
* Reboot the networking service (`sudo netplan apply`)
### Sysmon add-on for Splunk
Splunk squirrels add-ons away into their App store, which is accessible via the web console in a browser. Due to the fact that the Ubuntu Splunk server has no graphical interface, this part actually needs to be performed on one of the other machines in the network. Once the add-on is downloaded, it needs to be transferred to the Ubuntu Splunk server. With this in mind, I used the Kali machine, which has SSH (and therefore `scp`) installed by default.
Installation:  

* Power on Kali machine and open internet browser  
* Download Splunk add-on from [here](https://splunkbase.splunk.com/app/5709)  
* Transfer the downloaded file to the Splunk machine (`scp /<pathToSysmonFile> <splunkMachineAdminUser>@<splunkMachineIpAddress:/tmp/`)  
* Return to the Splunk virtual machine:
```
cd /opt/splunk/etc/apps/
sudo tar -xvzf /tmp/<sysmonFileName>
sudo chown -R splunk:splunk <sysmonFolderName> .
sudo /opt/splunk/bin/splunk restart
```
### Configure receiving port for Splunk
This part needs to be done through the web console, which can be accessed on the Kali machine (http://splunkMachineIpAddress:8000):  

* Login to the console using the administrator user name and password created during Splunk installation  
* Navigate through Settings > Forwarding and receiving > Configure receiving > New Receiving Port  
* Enter "9997" and click Save

That concludes the installation and configuration for the Splunk server itself. It's good practice, particularly in a lab environment that has no firewall (yet!), to disable the internet-facing network adapter (right-click the VM > Settings > Network Adapter (NAT) > untick "Connect at startup") at this point. And, of course, take a snapshot.
## Configuring Splunk and Sysmon for DC01, WS01, and WS02
### Installing and configuring `Sysmon`

* Download the Sysmon agent for Windows from [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) on host machine and extract  
* Copy the contents of [config.xml](https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml) and save to a `config.xml` file saved in the same folder as the extracted Sysmon agent  
* Copy the whole extracted Sysmon folder to the virtual machine (DC01/WS01/WS02)  
* Open an elevated PowerShell prompt on the virtual machine:
```
cd C:\<sysmonFolder>
.\Sysmon.exe -accepteula -i config.xml
```
### Installing and configuring the Splunk Universal Forwarder
* Download the Splunk Universal Forwarder from [here](https://www.splunk.com/en_us/download/universal-forwarder.html) on the host machine  
* Copy the installer to the virtual machine  
* Run the installer:  
    
    * Accept the license agreenment  
    * Set the Splunk admin credentials created during Splunk installation  
    * Leave the settings for Deployment Server blank  
    * Set the IP address for the Receiving Indexer as the custom VMnet network address of the Splunk server and the port as the one set during Splunk configuration (9997)  
* Open `notepad` and save the following as `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`:  
```
host = <hostName>

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0

[WinEventLog://Security]
disabled = 0

[WinEventLog://Application]
disabled = 0

[WinEventLog://System]
disabled = 0
```
* Snapshot!    
*Repeat the "Configuring Splunk and Sysmon" process for each Windows machine in the lab that should report in to Splunk*  
## Splunk for Kali
### Installing and enabling `Syslog`
```
sudo apt install rsyslog
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```
### Install and configure Splunk Universal Forwarder

* Obtain  the `wget` link to download the Splunk Universal Forwarder from [here](https://www.splunk.com/en_us/download/universal-forwarder.html)  
* Execute `wget` command  
* Install and start Splunk Universal Forwarder (set admin credentials as the ones created during Splunk installation when prompted):  
```
sudo /opt/splunkforwarder/bin/splunk start --accept-license
```
* Create `/opt/splunkforwarder/etc/system/local/outputs.conf` with the following contents:  
```
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = <splunkMachineIpAddress>:9997

[tcpout-server://<splunkMachineIpAddress>:9997]
```
* Create `/opt/splunkforwarder/etc/system/local/inputs.conf` with the following contents:  
```
[default]
host = Kali

# System logs
[monitor:///var/log/syslog]
disabled = 0
index = main
sourcetype = syslog

[monitor:///var/log/auth.log]
disabled = 0
index = main
sourcetype = linux_secure

# Optional: monitor Sliver logs (if you log Sliver to a file)
[monitor:///var/log/sliver/sliver-server.log]
disabled = 0
index = main
sourcetype = sliver
```
* Restart the Splunk Forwarder service (`sudo /opt/splunkforwarder/bin/splunk restart`)  
* Snapshot!