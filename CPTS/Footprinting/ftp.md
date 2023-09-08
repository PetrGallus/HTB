# FTP

vsFTPd

**obtain version of FTP server**

sudo nmap -sVC -p21 -A 10.129.124.136 //



**Enumerate FTP server and find flag.txt**

smbclient -L //10.129.45.189

![](<.gitbook/assets/image (1).png>)

smbclient //10.129.45.189/sambashare

smbstatus

get flag.txt

rpcclient -U "" 10.129.45.189

srvinfo //DOMAIN NAME

enumdomains //DOMAIN NAME

netshareenumall //PATH

