---
description: CPTS path - Footprinting
---

# Host Based Enumeration

## FTP

vsFTPd

**obtain version of FTP server**

sudo nmap -sVC -p21 -A 10.129.124.136 //



### **Enumerate FTP server and find flag.txt**

smbclient -L //10.129.45.189

![](<.gitbook/assets/image (1) (1) (1) (1).png>)

smbclient //10.129.45.189/sambashare

smbstatus

get flag.txt

rpcclient -U "" 10.129.45.189

srvinfo //DOMAIN NAME

enumdomains //DOMAIN NAME

netshareenumall //PATH

## NFS

same purpose as SMB, but different protocol - is used between Linux and Unix sys

cant communicate directly w SMB servers

NFSv4 - user auth (includes Kerberos, supports ACLs)

based on ONC-RPC/SUN-RPC ... TCP and UDP ports 111 -> NFS doesnt have auth mechanism, thats why RPC protocol (Remote Procedure Call)

has less options than FPT/SMB ... easier to configure

### Work w NFS

table of physical filesystens on NFS server in /etc/exports&#x20;

cat /etc/exports



show available NFS Shares

showmount -e \<IP>



mount NFS Share

mkdir target-NFS

sudo mount -t nfs \<IP>:/ ./target-NFS/ -o nolock

cd target-NFS

tree .

sudo umount ./target-NFS



List Contents w UN\&Group names ; UIDs\&GUIDs

ls -l mnt/nfs/

ls -n mnt/nfs/



### Enumeration

sudo nmap 10.129.172.42 -p111,2049 -sVC

sudo nmap --script nfs\* 10.129.172.42 -p111,2049 -sV

sudo showmount -e 10.129.172.42

sudo mount -t nfs 10.129.172.42:/ ./target-NFS/ -o nolock

cd target-NFS

tree .

cat mnt/nfsshare/flag.txt

cat var/nfs/flag.txt



## DNS

converting IP <-> URL

![](<.gitbook/assets/image (3) (1) (1).png>)

NDS is mainly UNENCRYPTED -> devices on local WLAN and ISP can hack in and spy on DNS queries

Thats why IT guys apply DNS over TLS or DNS over HTTPS, additionally network protocol NSCrypt (it ecrypts traffic between PC and DNS server)

There are many DNS records...A,AAAA,MX,NS,TXT,CNAME,PTR,SOA

Dangerous settings: allow-query, allow-recursion, allow-transfer, zone-statistics



### Footprinting

dig soa \<IP>



DIG - NS query

dig ns \<URL> @\<IP>



DIG - VERSION Query

dig CH TXT version.bind \<IP>



DIG - ANY Query

dig any \<URL> @\<IP>



DIG - AXFR Zone Transfer + Internal

dig axfr \<URL> @\<IP>

dig axfr internal.\<URL> @\<IP>

### Enumeration

enumerate the FQDN (Full domain name)

dig ns \<URL> @\<IP>



Is it possible to perform zone transfer??

dig axfr internal.\<URL> @\<IP>



IPv4 address of the hostname XX

dig axfr internal.\<URL> @\<IP>



what is FQDN of the host with IP: XX

for sub in $(cat /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @\<IP> | grep -v ';|SOA' | sed -r '/^\s\*$/d' | grep $sub | tee -a subdomains.txt;done

dnsenum --dnsserver \<IP> --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb



**AFTER DIG AXFR -> we obtain zone transferable domains -> try subdomains with script/dnsenum above....**

dnsenum --dnsserver 10.129.244.244 --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/SecLists/Discovery/DNS/fierce-hostlist.txt dev.inlanefreight.htb



## SMTP

sending mails in IP network

client-server or server-server

combined w IMAP/POP3 (they send mails)

\-p 25, never servers use 587

SMTP itself is unencrypted, it uses SSL/TLS layer

Creating email w MUA (Mail User Agent), after sending mail, SMTP converts it to header+body, MTA (Mail Transfer Agent) or Relay server checks email for size and spam. Then it is work of MDA (Mail Delivery Agent)

MUA -> MSA -> MTA -> MDA -> POP3/IMAP



### Work with SMTP

Def config

cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s\*$/d"



Telnet - HELO/EHLO and VRFY

telnet \<IP> 25 //port 25

HELO mail1.URL

EHLO mail1.URL

VRFY \<username>



### Dangerous settings

Open relay conf

mynetworks = 0.0.0.0/0 -> SMTP srv can send fake mails and initialize communication between multiple parties or we can spooof mail traffic





### Enumeration

obtain SMTP version

**sudo nmap 10.129.157.28 -sVC -p25**

**sudo nmap 10.129.157.28 -p25 --script smtp-open-relay -v**

**telnet 10.129.157.28 25**



find the UN that exists on the system

**smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/common\_roots.txt -t 10.129.157.28 -w 15**

dont forget to set timeout for request to 15 (-w 15) ... default value is 5sec

also try more wordlists...for example Seclists/Discovery/SNMP



## IMAP / POP3

Internet Message Access protocol, post Office protocol

IMAP - online management of emails on server + supports folder structure, client based, does sync from local client to server...network file system for email

POP3 only provides listing, retrieving and deleting emails

\-p 143 or 993

\-p 110 or 995



IMAP works unencrypted -> SSL/TLS addon



### Dangerous settings

auto\_debug

auth\_debug\_passwords

auth\_verbose

auth\_verbose\_passwords

auth\_anonymous\_username





### Enumeration

organization name + FQDN from IMA/POP3 service

sudo nmap \<IP> -sVC -p110,143,993,995



curl

curl -k 'imaps://10.129.139.103' --user robin:robin



IMAP service enumeration

curl -k 'imaps://10.129.139.103' --user robin:robin -v       // (-v ... verbose)

openssl s\_client -connect \<IP>:imaps



POP3 service enumeration

openssl s\_client -connect \<IP>:pop3s



customized version of POP3 server

telnet \<IP> 110           // 110 is default port of POP3



obtain EMAIL CONTENT + ADMIN EMAIL

openssl s\_client -connect 10.129.139.103:143 -starttls imap -crlf -quiet

TAG LOGIN \<UN> \<PW>

TAG LIST "" \*            // to see all inboxes

g21 SELECT "\<INBOX>"              // \<count> EXISTS

F1 fetch 1 RFC822



## SNMP

Simple Network Management Protocol

to monitor network devices and handle config tasks + change settings remotely

routers, switches, servers, IoT

SNMPv3

\-p 161 over UDP + traps (packets without being requested) on -p 162



MIB (Management Information base) for storing device info

text file written in ASN.1 based ASCII text format



OID (Onject Identifier Registry)

node in a hierarchical namespace for MIB



SNMPv1 -> no auth, no encryption

SNMPv2 -> auth, but no encryption

SNMPv3 -> auth + encryption (via pre-shared key)





### Dafault config

SNMP Daemon cfg

cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s\*$/d'





### Dangerous settings

rwuser noauth

rwcommunity \<community string> \<IPv4 address>

rwcommunity6 \<community string> \<IPv6 address>





### ENUMERATION

Enumerate SNMP service and obtain admin email address

**snmpwalk -v2c -c public 10.129.251.166**

onesixtyone -c /usr/share/SecLists/Discovery/SNMP/snmp.txt 10.129.251.166



customized version of SNMP server

**snmpwalk -v2c -c public 10.129.251.166**



find custom script running on the system as a flag

**snmpwalk -v2c -c public 10.129.251.166 | grep "HTB"**



## MySQL

relational database SQL management system by Oracle

client-server

single file with .sql extension

MariaDB is a fork of original MySQL code (developer left company and created his own)



Database

ideal usage for dynamic websites ... high response speed

combined w Linux OS, PHP and Apache or Nginx web server (LAMP) (LEMP)

PW can be stored in plain-text, but generally encrypted via PHP scripts by one-way-encryption





### Default config

sudo apt install mysql-server -y

cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s\*$/d'





### Dangerous Settings

user

password

admin\_address

debig

sql\_warnings

secure\_file\_priv



### ENUMERATION

Enumerate MySQL server and obtain version in use

**sudo nmap \<IP> -sVC -p3306 --script mysql\***

**mysql -u \<UN> -p\<PW> -h \<IP>**

**select version();**



with obtained credentials (robin:robin) - what is the email address of the customer "Otto Lang"?

**mysql -u \<UN> -p\<PW> -h \<IP>**

**show databases;**

**use customers;**

**show tables;**

**select \* from myTable where name = "Otto Lang";**

## MSSQL

Microsoft SQL - closed source code, for running on Windows OS

popular with .NET framework cause of its strong native support for .NET&#x20;



MSSQL Clients

SQL Server Management Studio (SSMS)

SQLPro

mssql-cli

SQL Server PowerShell

HeidiSQL



### Dangerous settings

* MSSQL clients dont use encryption to connect to the MSSQL server
* self-signed certs for encryption ... we can spoof self-signed certs
* use of named pipes
* weak or default sa credentians



### Enumeration

enumerate the target - list the HOSTNAME of MSSQL server

**msfconsole**

**use auxiliary/scanner/mssql/mssql\_ping**

**set rhosts \<IP>**

**run**



Connect to MSSQL instance w onbtained account backdoor:Password1 -> list the non-default database present on the server

**python3 examples/mssqlclient.py backdoor@10.129.74.93 -windows-auth**

**select name from sys.databases**



## Oracle TNS

Oracle Transparent network Substrate

does communication betweeen Oracle DB and apps over network

supports not only TCP/Ip stack, but also IPX/SPX atd.

updated to support newer techs like IPv6 and SSL/TLS

\-p 1521 (TCP)

config files are calles tnsnames.ora and listener.ora, located in ORACLE\_HOME/network/admin

![](<.gitbook/assets/image (8) (1) (1).png>)



### Enumeration

Enumerate the Oracle DB and submit HASH of PW of the user DBSNMP

1.  Obtain SID of the DB using nmap => "XE"

    `sudo nmap -p1521 -sV 10.129.205.19 --open --script oracle-sid-brute`
2.



## IPMI

* Intelligent Platform Management Interface
* HW-based host management systems used for sys management and monitorint
* autonomous subsystem which works independently of the hosts BIOS, CPU, firmware...
* 3 use-cases:
  * before OS has booted to modify BIOS config
  * when the host is fully powered down
  * access to a host after a system failure
* IPMI protocol was published by Intel in 1998
* \-p 623 (over UDP)



### Enumeration

1.  What username is configured for accessing the host via IPMI?

    **`sudo nmap -sU -p 623 10.129.165.205 --script ipmi-version`**

    \=> ![](<.gitbook/assets/image (9) (1).png>)

    METASPLOIT

    **`msfconsole`**

    **`use auxiliary/scanner/ipmi/ipmi_version`**

    **`set rhosts <IP>`**

    **`run`**

    **`use auxiliary/scanner/ipmi/ipmi_dumphashes`**

    **`set rhosts <IP>`**

    **`run`**

    \=>![](<.gitbook/assets/image (10) (1).png>)
2.  What is the account's cleartext password?

    we obtained HASH of the password, let´s crack it to obtain cleartext PW from that

    `576c4ea282000000816e7e01165f3ae1d9f94c88fac01d22381acd0e807cc96d7f821ffbdc125ee4a123456789abcdefa123456789abcdef140561646d696e:3d2813e5234fb7ed46ddd88325aa5904858cfaab`

    **`msfconsole`**

    **`use auxiliary/scanner/ipmi/ipmi_dumphashes`**

    **`set pass_file /usr/share/wordlists/rockyou.txt`**

    **`run`**

    \=> ![](<.gitbook/assets/image (11) (1).png>)

