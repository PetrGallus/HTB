# Oracle TNS

Oracle Transparent network Substrate

does communication betweeen Oracle DB and apps over network

supports not only TCP/Ip stack, but also IPX/SPX atd.

updated to support newer techs like IPv6 and SSL/TLS

\-p 1521 (TCP)

config files are calles tnsnames.ora and listener.ora, located in ORACLE\_HOME/network/admin

![](<.gitbook/assets/image (8).png>)



## Enumeration

Enumerate the Oracle DB and submit HASH of PW of the user DBSNMP

1.  Obtain SID of the DB using nmap => "XE"

    `sudo nmap -p1521 -sV 10.129.205.19 --open --script oracle-sid-brute`
2.

