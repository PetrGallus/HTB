# Pivoting, Tunneling and Port forwarding

<figure><img src=".gitbook/assets/image (161).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src=".gitbook/assets/image (162).png" alt=""><figcaption></figcaption></figure>

## Choosing the Dig Site & Starting our Tunnels

### Dynamic port FW w SSH and SOCKS Tunneling

<figure><img src=".gitbook/assets/image (163).png" alt=""><figcaption></figcaption></figure>

Port forwarding&#x20;

* \= to redirect a communication request from one port to another
* uses TCP / SSH / SOCKS (non-application layer)

<figure><img src=".gitbook/assets/image (164).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (165).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (166).png" alt=""><figcaption></figcaption></figure>

**You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many network interfaces does the target web server have? (Including the loopback interface)**

`ssh ubuntu@10.129.187.139`

* PW: HTB\_@cademy\_stdnt!

`ifconfig`

**Apply the concepts taught in this section to pivot to the internal network and use RDP (credentials: victor:pass@123) to take control of the Windows target on 172.16.5.19. Submit the contents of Flag.txt located on the Desktop.**

tail -4 /etc/proxychains.conf

proxychains msfconsole

search rdp\_scanner

use 0

options

set

set

<figure><img src=".gitbook/assets/image (167).png" alt=""><figcaption></figcaption></figure>



### Remote/Reverse port FW w SSH

### Meterpreter Tunneling & port Forwarding

## Playing Pong w SOCAT

### Socat Redirection w Reverse Shell

### Socat Redirection w Bind Shell

## Pivoting Around Obstacles

### SSH for Windows: plink.exe

### SSH Pivoting w sshuttle

### Web Server pivoting w Rpivot

### port Forwarding w Windows. Netsh

## Branching out Our Tunnels

### DNS Tunneling w DNScat2

### SOCKS5 Tunneling w Chisel

### ICMP Tunneling w SOCKS

## Double Pivots

### RDP and SOCKS Tunneling w SocksOverRDP

## Skills Assessment
