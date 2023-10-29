# PW Attacks

## Theory

### Protection theory

* CIA triade (Confidentiality, Integrity, Availability)
* Authentication
  * sth you KNOW (credentials)
  * sth you HAVE (app like Google auth)
  * sth you ARE (biometrics)
* PW Statistics (US)&#x20;
  * [https://www.pandasecurity.com/en/mediacenter/password-statistics/](https://www.pandasecurity.com/en/mediacenter/password-statistics/)
  * 24% americans use PW: 12345678, password, qwertyqwerty
  * [https://storage.googleapis.com/gweb-uniblog-publish-prod/documents/PasswordCheckup-HarrisPoll-InfographicFINAL.pdf](https://storage.googleapis.com/gweb-uniblog-publish-prod/documents/PasswordCheckup-HarrisPoll-InfographicFINAL.pdf)
  * combination pet / child + address number
  * 33% use their pets / children
  * 22% own name



### Credential storage

* rockyou.txt

#### Linux

* /etc/shadow
*   hashes

    <figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

* /etc/passwd
*

    <figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>





#### Windows

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

* LSASS
* SAM database
* NTDS
* C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\\

### John The Ripper

* \*1996
* Attack Methods (Dictionary, Brute-force, Rainbow table)

## Remote PW attacks

### Network services



#### Questions

Find the user for the **WinRM** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.

* WinRM = Windows Remote Management
  * must be configured manually in Win10
  * \-p5985 (HTTP) -p5986 (HTTPS)



Find the user for the **SSH** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.



Find the user for the **RDP** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.



Find the user for the **SMB** service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer.
