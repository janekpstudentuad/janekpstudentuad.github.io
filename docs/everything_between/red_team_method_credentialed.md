## Phase 1 – Situational Awareness
Goal: understand context before taking action.  
**Ask:**  

* Who am I?  
* What groups am I in?  
* What privileges do I have?  
* Am I local or domain joined?  
* What host type is this? (Workstation/Server/ DC)  
* What OS/version am I on?  
* What network am I sitting in?  

**Identify:**  

* Domain name & trust context  
* Logged-on users  
* Network interfaces and reachable subnets  
* Current user integrity level  

**Security Controls Awareness**  
Before escalation or tooling, understand detection surface:  

* Is AV present?  
* Is EDR present?  
* Is the host firewall enabled?  
* Is PowerShell constrained?  
* Is AMSI active?  
* Are logging/monitoring controls obvious?  

## Phase 2 – Local Enumeration (System-Level)
Goal: identify local privilege escalation paths.
**Hunt for:**  

* Service Misconfigurations:

	* Services running as SYSTEM  
	* Writable service binaries  
	* Unquoted service paths  
	* Weak service registry ACLs

* Scheduled Tasks:

	* Writable task binaries  
	* Tasks running as Administrator/SYSTEM

* Weak File/Folder Permissions:

    * Program Files  
	* Service directories  
	* Startup folders  
	* Writable system directories  

* Token Abuse Opportunities:  

	* SeImpersonatePrivilege **<< major red flag**  
	* SeAssignPrimaryToken  
	* SeBackupPrivilege  
	* SeRestorePrivilege  

## Phase 3 – File System Enumeration

Goal: understand what lives on this machine.  
*Don’t just check permissions — enumerate contents.*  
**Look for:**  

* Interesting directories (dev folders, backups, temp builds)  
* Old installers  
* Backup copies of configs  
* Database dumps  
* Password lists  
* SSH keys  
* Internal documentation  
* Deployment scripts  
* User desktop artefacts  
* Hidden directories  
* Recently modified files  

**Ask:**  

* What shouldn’t be here?  
* What looks like operational tooling?  
* What indicates this machine’s role in the environment?  

*File systems often leak far more than services.*

## Phase 4 – Credential & Secret Hunting
Goal: identify material enabling escalation or lateral movement.  
**Search for:**  

* Stored credentials  
* RunAs saved creds  
* Registry secrets  
* Config files with plaintext passwords  
* Browser credentials  
* Application config files  
* Backup files containing creds  
* SAM/LSASS (if privileges allow)  

**Look for:**  

* Hardcoded credentials in scripts  
* Service account passwords  
* Scheduled task stored credentials  
* Deployment artefacts  

*Credential reuse often beats local privilege escalation.*

## Phase 5 – Decision Point: Escalate or Pivot?

**Ask:**  

* Is local SYSTEM the best next move?  
* Do I already have credentials useful elsewhere?  
* Is this machine strategically valuable?  
* Would lateral movement yield better access?  

**Consider:**  

* Local privilege escalation  
* Credential reuse  
* Token impersonation  
* Share access  
* Session hijacking  
* Domain escalation path  

*Choose the path with the greatest operational advantage and least noise.*

## Phase 6 – Privilege Escalation (If Chosen)

**Typical Windows paths:**  

* Service misconfiguration  
* DLL hijacking  
* AlwaysInstallElevated  
* Writable service path  
* Weak registry ACL  
* Token impersonation  
* Stored credentials  
* Scheduled task abuse  

*Keep noise minimal and reversible where possible.*

## Phase 7 – Lateral Movement Assessment

**Once stable:**  

* What hosts are reachable?  
* Do credentials work elsewhere?  
* Are there admin sessions on other machines?  
* Can I access shares?  
* Is this a stepping stone to a domain controller?

*Re-evaluate context after each move.*

## Phase 8 – Elevated Context Actions

**If SYSTEM / Administrator obtained:**  

* Validate integrity level  
* Re-check privileges  
* Dump additional credentials (if in scope)  
* Identify persistence options  
* Assess domain-level escalation paths  
* Retrieve proof (flag)