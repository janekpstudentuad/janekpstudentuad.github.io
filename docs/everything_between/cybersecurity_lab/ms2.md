# Metasploitable 2 - MS2
## Create Virtual Machine
After downloading the VMHD (and extracting) for Metasploitable2 (available [here](https://www.rapid7.com/products/metasploit/metasploitable/)):  

* Open the virtual machine in VMware Workstation Pro (File > Open)  
* (optional) Rename the virtual machine as required  
* Change the network adapted to connect to the custom VMnet network  
## Set Static IP Address
* Power on the virtual machine  
* Obtain the network adapter name (`ip a`)  
* Open the `/etc/network/interfaces` file and update the stanza with the relevant network adapter name with the following content:  
```
iface <adapterName> inet static
    address <metasploitableIpAddress>
    netmask 255.255.255.0
    dns-nameservers <dcIpAddress>
```
*I used the .98 host address from the custom VMnet network*
* (optional but highly recommended) Shut down and take snapshot of fresh OS installation  
## Configure for Splunk Logging
* Append the following to `sudo nano /etc/syslog.conf`:  
```
*.*   @<splunkMachineIpAddress>
```
* Reboot  
**!!The rest of the steps on this page need to be performed on the Splunk virtual machine!!**  
```
sudo systemctl enable --now rsyslog
sudo systemctl status rsyslog --no-pager
sudo mkdir -p /var/log/remote
sudo chown syslog:adm /var/log/remote
sudo chmod 0755 /var/log/remote
sudo usermod -aG adm splunk
```
* Add the following contents to `/etc/rsyslog.d/10-splunk-remote.conf`:  
```
# Accept remote syslog via UDP and TCP
module(load="imudp")
input(type="imudp" port="514")

module(load="imtcp")
input(type="imtcp" port="514")

# Template to write logs into per-host directory and per-program file
template(name="RemoteLogs" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")

# Write everything to the template
*.* ?RemoteLogs
& stop
```
* Restart the `rsyslog` service (`sudo systemctl restart rsyslog`)  
* Create the `/opt/splunk/etc/system/local/inputs.conf` file with the following contents:  
```
[default]
host = splunk

[monitor:///var/log/remote]
disabled = false
index = main
recursive = true
sourcetype = syslog
```
* Restart the Splunk service (`sudo /opt/splunk/bin/splunk restart`)  
* Snapshot! (for both Splunk and MSF2 machines)