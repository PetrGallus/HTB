# Attacking WebApps with FFUFF

## Basic Fuzzing

### Directory Fuzzing

`ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.57.242:47977/FUZZ`

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Page Fuzzing

`ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://159.65.81.48:32733/blog/indexFUZZ`

* php
* phps

`ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://159.65.81.48:32733/blog/FUZZ.php`

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* visit website
  * [http://94.237.51.68:46904/blog/XXXX.php](http://94.237.51.68:46904/blog/home.php)
    * flag obtained

### Recursive Fuzzing

**Try to repeat what you learned so far to find more files/directories. One of them should give you a flag. What is the content of the flag?**

`ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.57.242:45177/forum/FUZZ -recursion -recursion-depth 1 -e .php -v`

<figure><img src=".gitbook/assets/image (2) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* visit website to obtain flag

## Domain Fuzzing

### Sub-domain Fuzzing

**Try running a sub-domain fuzzing test on 'inlanefreight.com' to find a customer sub-domain portal. What is the full domain of it?**

`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/`

<figure><img src=".gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Filtering Results

**Try running a VHost fuzzing scan on 'academy.htb', and see what other VHosts you get. What other VHosts did you get?**

`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://94.237.57.242:45177/ -H 'Host: FUZZ.academy.htb' -fs 986`

<figure><img src=".gitbook/assets/image (4) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Parameter Fuzzing

### Parameter Fuzzing - GET

**Using what you learned in this section, run a parameter fuzzing scan on this page. what is the parameter accepted by this webpage?**

* add generated IP to /etc/hosts as admin.academy.htb
* `ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:45177/admin/admin.php?FUZZ=key -fs 798`

<figure><img src=".gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

### Value Fuzzing

**Try to create the 'ids.txt' wordlist, identify the accepted value with a fuzzing scan, and then use it in a 'POST' request with 'curl' to collect the flag. What is the content of the flag?**

* create the ids.txt wordlist
  * `for i in $(seq 1 1000); do echo $i >> ids.txt; done`
* POST request w curl to collect flag
  * `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:45177/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 768`

<figure><img src=".gitbook/assets/image (6) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

* OK - we got 73
  * `curl -d "id=73" -H 'Content-Type: application/x-www-form-urlencoded' -X POST http://admin.academy.htb:45177/admin/admin.php`

<figure><img src=".gitbook/assets/image (7) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

## Skills Assessment - Web Fuzzing

**Run a sub-domain/vhost fuzzing scan on '\*.academy.htb' for the IP shown above. What are all the sub-domains you can identify? (Only write the sub-domain name)**

`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://94.237.49.235:59074/ -H 'Host: FUZZ.academy.htb' -fs 985`

<figure><img src=".gitbook/assets/image (8) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**Before you run your page fuzzing scan, you should first run an extension fuzzing scan. What are the different extensions accepted by the domains?**

* add these 3 subdomains to /etc/hosts
* `ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://faculty.academy.htb:59074/indexFUZZ`

<figure><img src=".gitbook/assets/image (9) (1) (1).png" alt=""><figcaption></figcaption></figure>

**One of the pages you will identify should say 'You don't have access!'. What is the full page URL?**

`ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://faculty.academy.htb:59074/FUZZ -recursion -recursion-depth 1 -e .php7 -v -fs 0`

* _took me about 20mins till it found it_

<figure><img src=".gitbook/assets/image (10) (1) (1).png" alt=""><figcaption></figcaption></figure>

* ANSWER: http://faculty.academy.htb:PORT/courses/linux-security.php7

**In the page from the previous question, you should be able to find multiple parameters that are accepted by the page. What are they?**

`sudo ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:39355/courses/linux-security.php7?FUZZ=key -fs 774`

* we obtained first one: user

`sudo ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://faculty.academy.htb:39355/courses/linux-security.php7 -X POST -d 'key=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 774 -t 1000`

* we obtained second one: username

**Try fuzzing the parameters you identified for working values. One of them should return a flag. What is the content of the flag?**

* Fuzzing
  * `sudo ffuf -w /usr/share/wordlists/dirb/others/names.txt:FUZZ -u http://faculty.academy.htb:39355/courses/linux-security.php7 -X POST -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 781`
* Curl
  * `curl -d "username=Harry" -H 'Content-Type: application/x-www-form-urlencoded' -X POST http://faculty.academy.htb:39355/courses/linux-security.php7`
    * HTB{w3b\_fuzz1n6\_m4573r}

