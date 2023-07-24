## Agile
### Reco
### Weaponisation
### Exploitation
### User flag
### Root flag
## OnlyForYou
> To obtain access we must read various files on the web using an LFI to find a vulnerability in the form. Using the form we can run CERs. To move to a user we must perform a Cypher Injection on an internal website to get the password. And for the escalation of privileges we must modify a file, create a tar.gz and upload it to the Gogs web intera and then download the file using pip3 and thus be able to modify the bash to SUID permissions.
### Reco
1. nmap 10.10.11.210 -sVC
2. dir busting
    - there is a subdomain
    ![](https://hackmd.io/_uploads/rytoaqich.png)
    - add it also to the /etc/hosts

### Weaponisation
1. beta subdomain
    - allows us to download source code
        ![](https://hackmd.io/_uploads/BklH0qoqh.png)
        - When analyzing it we realize that in the / download path if in the parameter image start with 2 points then launch a message that says Hacking detected and makes us a redirect to / list.
            ![](https://hackmd.io/_uploads/HkT9C5iq3.png)
### Exploitation
1. BurpSuite - LFI
    - 
### User flag
### Root flag
