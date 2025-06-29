# WINDOWS
```
Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx, *.log -File -Recurse -ErrorAction SilentlyContinue -force
```

```
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log -File -Recurse -ErrorAction SilentlyContinue -force
```

```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

```
Get-ChildItem -Path C:\ -Include *.txt,*.log, *.ini, *.ps1, *.csv -File -Recurse -ErrorAction SilentlyContinue -Force | Select-String -Pattern "paterne1", "paterne2"
```

```
| Select-String -Pattern "password"
```

# Linux

```
find / -name "local.txt" 2>/dev/null
```

```
grep -ri <filename>
```
