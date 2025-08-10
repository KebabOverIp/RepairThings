
<img width="1097" height="92" alt="image" src="https://github.com/user-attachments/assets/3707d937-892a-4e07-b8bb-47b8fd464d86" />



Enumeration

Web Proxy

You can try to set this discovered service as proxy in your browser. However, if it's configured with HTTP authentication you will be prompted for usernames and password.

bash

```bash
# Try to proxify curl
curl --proxy http://10.10.11.131:3128 http://10.10.11.131
```

SPOSE Scanner

Alternatively, the Squid Pivoting Open Port Scanner (spose.py) can be used.

https://book.hacktricks.wiki/en/network-services-pentesting/3128-pentesting-squid.html#spose-scanner


https://github.com/aancw/spose

bash

```bash
python spose.py --proxy http://10.10.11.131:3128 --target 10.10.11.131
```
