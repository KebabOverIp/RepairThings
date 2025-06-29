
## Inital access : What to look for

* Look at the service version of ports and see if there is any low-hanging fruit or public exploits
* If nothing easy is found, look deeper into the services (FTP,SMB,NFS,SMTP,WEB)
* Check if there's a way to upload files
* Check if there's a way to read sensitive information
* Check if there's any files that give contextual hints or point towards a vulnerable service running on an unknown port
* Open each service note and dig deep starting with FTP, SNMP, SMB, HTTP

### 21 - FTP

* Check version using `searchsploit` for public exploits
* Check for `anonymous` login
* Check for hints within the directory (i.e. `minniemouse.exe`)
* Download the directory `wget -m ftp://anonymous:anonymous@10.10.10.20`
* Check if there's anything that points towards uploads going to the web directory

### 22 - SSH

* Try to bruteforce basics credentials as ftp:ftp, user:user, backup:backup, webappname:webappname... 

### 80 - WEB

* Check Web Application Checklist
* Check version using `searchsploit` for public exploits (Traversal, SQLi, RCE)
* Check to see if anything else is running using `whatweb http://10.10.10.20` (searchsploit, wordpress)
* Fully enumerate with directory brute-forcing
	* Run multiple tools and check for file extensions, try from deeper directories
* Visit site in the browser and look for any context clues
	* See if there's any hint for FQDN and put it in `/etc/hosts`
	* See if there's any hints to valid users or software in pages or source code
* Test everything for default credentials or username being the password

### 161 - SNMP
* Enumerate community strings on v1 and v2
 
	 `sudo nmap -sU -p 161 --script snmp-brute 10.10.10.20`
  
* Try to get useful information from accessible communities
 
	 `snmpwalk -v 1 -c public 10.10.10.20 NET-SNMP-EXTEND-MIB::nsExtendObjects`
  
	 `snmpwalk -v2c -c public 10.10.10.20 | grep <string>`


### 389 LDAP

* Try `ldapdomaindump`

 `ldapdomaindump -u 'foo.domain\username' -p 'password' --no-json --no-grep 10.10.10.20`

* Make a wordlist from user domains dumps, one liner :
  `grep -oP '<tr><td>\K[^<]+' domain_users.html`

* Analyze dumps with caution, any informations can be useful




 ### 445 - SMB

* This list is to reproduce with every new access you harvest.
* Try enum4linux to enumerate smb information.

`enum4linux 10.10.10.10`

* Try crackmapexec to list accessibles SMB shares

`crackmapexec smb 10.10.10.10 -u "" -p "" --shares` 

* If you got an share read access, download all the files and analyze your loot. grep with pass,key,secret,username,ssh,ftp...


  







