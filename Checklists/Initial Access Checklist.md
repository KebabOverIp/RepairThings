
## Inital access : What to look for

* Look at the service version of ports and see if there is any low-hanging fruit or public exploits
* If nothing easy is found, look deeper into the services (FTP,SMB,NFS,SMTP,WEB)
* Check if there's a way to upload files
* Check if there's a way to read sensitive information
* Check if there's any files that give contextual hints or point towards a vulnerable service running on an unknown port
* Open each service note and dig deep starting with FTP, SNMP, SMB, HTTP

  

















remember to grep -ri "productname @/usr/share/wordlists/ ? :)
