# SMB

NSE scripts can be used
```
locate .nse | grep smb
nmap -p445 --script="name" 10.10.10.10
```

crackmapexec
```
crackmapexec smb <IP/range>  
```
```
crackmapexec smb 192.168.1.100 -u username -p password
```
```
crackmapexec smb 192.168.1.100 -u username -p password --shares #lists available shares

```
```
crackmapexec smb 192.168.1.100 -u username -p password --users #lists users
```
```
crackmapexec smb192.168.1.100 -u username -p password -p 445 --shares #specific port
```
```
crackmapexec smb 192.168.1.100 -u username -p password -d mydomain --shares #specific domain
```

Inplace of username and password, we can include usernames.txt and passwords.txt for password-spraying or bruteforcing.


 Smbclient
```
smbclient -L //IP or try with 4 /'s
smbclient //server/share
smbclient //server/share -U <username>
smbclient //server/share -U domain/username
```

SMBmap
```
smbmap -H <target_ip>
smbmap -H <target_ip> -u <username> -p <password>
smbmap -H <target_ip> -u <username> -p <password> -d <domain>
smbmap -H <target_ip> -u <username> -p <password> -r <share_name>
```
Within SMB session
```
put <file> #to upload file
get <file> #to download file
```

Recursive download
```
smbclient '\\server\share'
mask ""
recurse ON
prompt OFF
cd 'path\to\remote\dir'
lcd '~/path/to/download/to/'
mget *
```
