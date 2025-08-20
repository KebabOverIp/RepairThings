sudo -l￼￼

find / -type f -perm -u=s 2>/dev/null | xargs ls -l

/usr/sbin/getcap -r / 2>/dev/null

cat /etc/crontab

cat /etc/issue && uname -r && arch

env

cat .bashrc


