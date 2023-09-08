# DNS

converting IP <-> URL

![](.gitbook/assets/image.png)

NDS is mainly UNENCRYPTED -> devices on local WLAN and ISP can hack in and spy on DNS queries

Thats why IT guys apply DNS over TLS or DNS over HTTPS, additionally network protocol NSCrypt (it ecrypts traffic between PC and DNS server)

There are many DNS records...A,AAAA,MX,NS,TXT,CNAME,PTR,SOA

Dangerous settings: allow-query, allow-recursion, allow-transfer, zone-statistics



## Footprinting

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

## Enumeration

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

