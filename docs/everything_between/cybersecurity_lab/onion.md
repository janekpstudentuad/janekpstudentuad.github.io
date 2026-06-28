# Security Onion - Onion
## Create Virtual Machine
After downloading the ISO for Security Onion (available [here](https://docs.securityonion.net/en/2.4/download.html)), create a new virtual machine in VMware Workstation Pro (File > New Virtual Machine), with the following settings:  

* Typical (Recommended) configuration  
* Installer disc image file: Security Onion LTS ISO  
* Virtual machine name: Onion  
* Location: desired location for VMHD files  
* Specify Disk Capacity options: increase size to 100GB  
* Change amount of RAM to 8GB  
* Change number of processors to 4  
* Add a second network adapter to connect to the custom VMnet network   
## Installation
* Power on the virtual machine - the installer will start once you type "yes" at the prompt  
* Set username and password as desired  
* Once the installation is complete, reboot as prompted and then login with the administrator credentials created during set up  
* Installation responses:  
    * Install  
    * Evaluation mode  
    * Standard  
    * Hostname: onion  
    * Pick the NAT network adapter as the management NIC (MAC addresses can be confirmed in the "Advanced" section of the Network Adapter settings in VMware Workstation Pro)  
    * DHCP (this would be different in a production environment - we are going to set it to a static address later)  
    * Direct connection  
    * Keep the default Docker range  
    * Select the other NIC for the Monitoring interface (hit the SPACE bar)  
    * Enter an email address for the administrator account (this does not have to be valid!)  
    * Create a password for the administrator account  
    * Access the web interface by IP  
    * Allow access to the installation via the web interface  
    * Enter network address for the NAT network in CIDR notation (e.g., 192.168.1.0/24)  
    * Do not allow SOC telemetry 
* This installation takes a good while, despite the fact that the machine has been beefed up so I would definitely recommend taking a snapshot when it's complete
## Setting the Static IP Address
* Confirm the name and leased IP address of the NAT network adapter (`ip a`)  
* Set the network adapter configuration:  
```
sudo nmcli con delete <natAdapterName>
sudo nmcli con add type ethernet ifname <natAdapterName> con-name <natAdapterName> ipv4.addresses <leasedIpAddress>/24 ipv4.gateway <natSubnet>.2 ipv4.dns 8.8.8.8 ipv4.method manual
sudo nmcli con up <natAdapterName>
```
* Snapshot!  
*The web management interface should be available in a browser window on the Kali machine at http://onionIpAddress using the email and password credentials created during the installation*