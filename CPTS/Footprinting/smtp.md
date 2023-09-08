# SMTP

sending mails in IP network

client-server or server-server

combined w IMAP/POP3 (they send mails)

\-p 25, never servers use 587

SMTP itself is unencrypted, it uses SSL/TLS layer

Creating email w MUA (Mail User Agent), after sending mail, SMTP converts it to header+body, MTA (Mail Transfer Agent) or Relay server checks email for size and spam. Then it is work of MDA (Mail Delivery Agent)

MUA -> MSA -> MTA -> MDA -> POP3/IMAP



## Work with SMTP

Def config

cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s\*$/d"



Telnet - HELO/EHLO and VRFY

telnet \<IP> 25 //port 25

HELO mail1.URL

EHLO mail1.URL

VRFY \<username>



## Dangerous settings

Open relay conf

mynetworks = 0.0.0.0/0 -> SMTP srv can send fake mails and initialize communication between multiple parties or we can spooof mail traffic





## Enumeration

obtain SMTP version

**sudo nmap 10.129.157.28 -sVC -p25**

**sudo nmap 10.129.157.28 -p25 --script smtp-open-relay -v**

**telnet 10.129.157.28 25**



find the UN that exists on the system

**smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/common\_roots.txt -t 10.129.157.28 -w 15**

dont forget to set timeout for request to 15 (-w 15) ... default value is 5sec

also try more wordlists...for example Seclists/Discovery/SNMP

