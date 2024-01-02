# Information gathering

## Passive Info Gathering

## WHOIS

* TCP-based transaction-oriented query/response protocol defined in RFC 3912
* \-p 43
* \*1970 by Elizabeth Feinler + team on Stanford Uni
* ICANN requires that accredited registrars enter these info
* Usage:
  * export TARGET="facebook.com" // assign target to an env variable
  * whois $TARGET

### Questions

*   Perform a WHOIS lookup against the paypal.com domain. What is the registrar Internet Assigned Numbers Authority (IANA) ID number?

    **`export TARGET="paypal.com"`**

    **`whois $TARGET`**
*   What is the admin email contact for the tesla.com domain (also in-scope for the Tesla bug bounty program)?

    **`export TARGET="tesla.com"`**

    **`whois $TARGET`**

## DNS

* Domain Name System
*   Usage:

    * `export TARGET="facebook.com"`
    * `nslookup $TARGET`
    * `nslookup -query=A $TARGET`
    * `dig <URL> @<IP>`



#### Questions

1.  Which IP address maps to inlanefreight.com?

    **`export TARGET="inlanefreight.com"`**

    **`nslookup $TARGET`**

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

2. Which subdomain is returned when querying the PTR record for 173.0.87.51?

**`nslookup -query=PTR 173.0.87.51`**

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

3. What is the first mailserver returned when querying the MX records for paypal.com?

**`export TARGET="paypal.com"`**

**`nslookup -query=MX $TARGET`**

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Passive subdomain Enumeration

* VirusTotal -> Relations
*   Certifications ->&#x20;

    ```
    https://censys.io

    https://crt.sh
    ```
* Automating the enum -> TheHarvester

## Passive infrastructure Identification

* Netcraft
* Wayback machine
* Tool -> waybackurls (go install github.com/tomnomnom/waybackurls@latest)

## Active Info Gathering

### Active infrastructure identification

* HTTP headers -> **`curl -I "http://${TARGET}"`**
* **`whatweb -a3 https://www.facebook.com -v`**
* Tool -> **Wappalyzer**
* Tool -> **WafW00f** (sudo apt install wafw00f -y) (wafw00f -v https://www.tesla.com)
* Tool -> Aquatone (sudo apt install golang chromium-driver) (go get github.com/michenriksen/aquatone) (export PATH="$PATH":"$HOME/go/bin") (cat facebook\_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000)

#### Questions

1. What Apache version is running on app.inlanefreight.local? (Format: 0.0.0)

**`nmap -sV -p80 10.129.26.247`**

2. Which CMS is used on app.inlanefreight.local? (Format: word)

**`nmap -sC -p80 10.129.26.247`**

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

3. On which operating system is the dev.inlanefreight.local webserver running on? (Format: word)

**`export TARGET="dev.inlanefreight.local"`**

**`curl -I "http://${TARGET}"`**

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Active subdomain Enumeration

* ZoneTransfers -> [https://hackertarget.com/zone-transfer/](https://hackertarget.com/zone-transfer/)
* nslookup -type=NS zonetransfer.me
* nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja
* Gobuster - DNS
  * export TARGET="facebook.com"
  * export NS="d.ns.facebook.com"
  * export WORDLIST="numbers.txt"
  * gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster\_${TARGET}.txt"

#### Questions

1. Submit the FQDN of the nameserver for the "inlanefreight.htb" domain as the answer.

**`dig NS inlanefreight.htb @10.129.146.220`**

2. Identify how many zones exist on the target nameserver. Submit the number of found zones as the answer.

**`dig axfr inlanefreight.htb @10.129.146.220`**

3. Find and submit the contents of the TXT record as the answer.

// add root.inlanefreight to /etc/hosts...

**`nslookup -query=axfr internal.inlanefreight.htb root.inlanefreight.htb`**

<figure><img src=".gitbook/assets/image (5) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

4. What is the FQDN of the IP address 10.10.34.136?

**`nslookup -query=axfr internal.inlanefreight.htb root.inlanefreight.htb`**

<figure><img src=".gitbook/assets/image (6) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

5. What FQDN is assigned to the IP address 10.10.1.5? Submit the FQDN as the answer.

**`nslookup -query=axfr internal.inlanefreight.htb root.inlanefreight.htb`**

<figure><img src=".gitbook/assets/image (7) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

6. Which IP address is assigned to the "us.inlanefreight.htb" subdomain. Submit the IP address as the answer.

**`dig @10.129.146.220 NS a us.inlanefreight.htb`**

<figure><img src=".gitbook/assets/image (8) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

7. Submit the number of all "A" records from all zones as the answer.

**`dig @10.129.128.199 AXFR a inlanefreight.htb`**

**`dig @10.129.128.199 AXFR a internal.inlanefreight.htb`**

**19 + 7 records ... 27**

### Virtual Hosts

`ffuf -w /usr/share/SecLists/Discovery/DNS/namelist.txt -u http://10.129.137.129 -H "HOST: FUZZ.inlanefreight.htb" -fs 612`

<figure><img src=".gitbook/assets/image (9) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (10) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (11) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (12) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (13) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Crawling

What is the registrar IANA ID number for the githubapp.com domain?

`whois githubapp.com`



What is the last mailserver returned when querying the MX records for githubapp.com?

`export TARGET="githubapp.com"`

`nslookup -query=MX $TARGET`



Perform active infrastructure identification against the host https://i.imgur.com. What server name is returned for the host?



## Skills Assessment



### Questions

What is the registrar IANA ID number for the githubapp.com domain?

`whois githubapp.com`



What is the last mailserver returned when querying the MX records for githubapp.com?

`export TARGET="githubapp.com"`

`nslookup -query=MX $TARGET`



Perform active infrastructure identification against the host https://i.imgur.com. What server name is returned for the host?

`curl -I 'https://i.imgur.com/'`

Perform subdomain enumeration against the target githubapp.com. Which subdomain has the word 'triage' in the name?

[https://crt.sh/?q=githubapp.com](https://crt.sh/?q=githubapp.com)
