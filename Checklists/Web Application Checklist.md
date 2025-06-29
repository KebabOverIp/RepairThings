## Web Application : WTF i am doin?

* Analyze nmap output with caution, remember that even apache version can lead to RCE, service name runing, version, search about it.
* Enumerate the web application dirctory, subdomains and params -> See : Webapp Enum Checklist  (incoming)
* Analyze your loot, if nothing seems juicy, change wordlist, if nothing change, change tools configuration or tools (gobuster, dirbuster, dirb...)
* Try to fuzz any parameter to detect some kind offcCode injecionor file inclusion with this check list : Param Fuzzing Procedure
* Analyze subdomains
