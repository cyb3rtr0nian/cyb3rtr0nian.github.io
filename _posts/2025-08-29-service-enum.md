---
title: "Service Enumeration & Footprinting"
date: 2025-08-29 00:00:01 +0800
categories: [The Hacker’s PlayBook]
tags: [Enumeration]
image: /assets/img/favicons/footprinting.webp
---

## Overview
Service enumeration is a **crucial phase** in network security and penetration testing, where security professionals gather detailed information about the services running on a target’s open ports. This step goes beyond simply identifying live hosts; it uncovers the type, version, and configuration of services, helping to pinpoint **potential vulnerabilities and attack vectors**.

This post covers enumeration techniques for a wide range of commonly used network services, including FTP, SSH, SMTP, DNS, SMB, RDP, and various email and database services. You will find practical tools, commands, and methodologies to systematically enumerate services, verify configurations, and identify weaknesses for further analysis.

### FTP (Port 21/TCP)
FTP (File Transfer Protocol) is primarily used for transferring files.

#### Nmap Script Engine (NSE)
Check for Anonymous Login:
```shell
nmap -p 21 --script=ftp-anon <ip>
```
Check for Vulnerabilities on FTP:
```shell
nmap -p 21 --script=vuln <ip>
```

#### Connecting to FTP
Check FTP manually:
```shell
nc -nv <ip> 21
# or
telnet <ip> 21
```

Non-SSL Connections:
```shell
ftp <ip> 21
```

SSL/TLS Connections:
```shell
openssl s_client -connect <ip>:21 -starttls ftp
```

#### Brute-Forcing FTP
Using Hydra:
```shell
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt \
      -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt \
      <ip> ftp
```

Using Nmap:
```shell
echo "<username1>" > userlist.txt
echo "<username2>" >> userlist.txt
echo "<username3>" >> userlist.txt
nmap -p 21 --script ftp-brute --script-args userdb=/root/userlist.txt <ip>
```

#### Downloading Files via FTP
- Mirror Entire FTP Directory (Useful to bypass proxies):
```shell
wget -m ftp://anonymous:anonymous@<ip>
wget -m --no-passive ftp://anonymous:anonymous@<ip>
```

- Download Files with Special Characters in Credentials:
```shell
wget -r --user="USERNAME" --password="PASSWORD" ftp://<ip>/
```

- FTP Command for Downloading All Files in Current Directory:
```shell
mget *
```

#### Using Metasploit for FTP

- Get FTP Version:
```shell
msfconsole
use auxiliary/scanner/ftp/ftp_version
set RHOSTS <ip>
run
```

- FTP Brute Force:
```shell
use auxiliary/scanner/ftp/ftp_login
set RHOSTS <ip>
set USER_FILE /usr/share/wordlists/MetasploitRoom/MetasploitWordlist.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

- Check for Anonymous Login:
```shell
use auxiliary/scanner/ftp/anonymous
set RHOSTS <ip>
run
```
