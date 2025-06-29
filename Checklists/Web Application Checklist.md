## Web Application : WTF i am doin?

* Analyze nmap output with caution, remember that even apache version can lead to RCE, service name runing, version, search about it.
* Enumerate the web application directory, subdomains and params -> See : Webapp Enum Checklist (incoming)
* Analyze your loot, if nothing seems juicy, change wordlist, if nothing change, change tools configuration or tools (gobuster, dirbuster, dirb...)
* Try to fuzz any parameter to detect some kind of Code injection or file inclusion with this procedure : Param Fuzzing Procedure
* Analyze subdomains and replay the initial info gathering part on it.
* Try Harder
