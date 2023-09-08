# IMAP / POP3

Internet Message Access protocol, post Office protocol

IMAP - online management of emails on server + supports folder structure, client based, does sync from local client to server...network file system for email

POP3 only provides listing, retrieving and deleting emails

\-p 143 or 993

\-p 110 or 995



IMAP works unencrypted -> SSL/TLS addon



## Dangerous settings

auto\_debug

auth\_debug\_passwords

auth\_verbose

auth\_verbose\_passwords

auth\_anonymous\_username





## Enumeration

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







