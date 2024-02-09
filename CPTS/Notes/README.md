# ANSWERS

Module: Penetration Testing Process\
1\. How many documents must be prepared in total for a penetration test? -> 7\
2\. What type of analysis can be used to predict future probabilities? -> predictive\
3\. How many types of evasive testing are mentioned in this section? -> 3\
4\. What is the name of the security standard for credit card payments that a company must adhere to? (Answer Format: acronym) -> pci-dss\
5\. What designation do we typically give a report when it is first delivered to a client for a chance to review and comment? (One word) -> draft\
\
Module: Getting Started\
1\. Apply what you learned in this section to grab the banner of the above server and submit it as the answer. -> SSH-2.0-OpenSSH\_8.2p1 Ubuntu-4ubuntu0.1\
2\. Perform a Nmap scan of the target. What is the version of the service from the Nmap scan running on port 8080? -> apache tomcat\
3\. Perform an Nmap scan of the target and identify the non-default port that the telnet service is running on.  -> 2323\
4\. List the SMB shares available on the target host. Connect to the available share as the bob user. Once connected, access the folder called 'flag' and submit the contents of the flag.txt file. -> dceece590f3284c3866305eb2473d099\
5\. Try running some of the web enumeration techniques you learned in this section on the server above, and use the info you get to get the flag. -> HTB{w3b\_3num3r4710n\_r3v34l5\_53cr375}\
6\. Try to identify the services running on the server above, and then try to search to find public exploits to exploit them. Once you do, try to get the content of the '/flag.txt' file. (note: the web server may take a few seconds to start -> HTB{my\_f1r57\_h4ck}\
7\. SSH into the server above with the provided credentials, and use the '-p xxxxxx' to specify the port shown above. Once you login, try to find a way to move to 'user2', to get the flag in '/home/user2/flag.txt'. -> HTB{l473r4l\_m0v3m3n7\_70\_4n07h3r\_u53r}\
8\. Once you gain access to 'user2', try to find a way to escalate your privileges to root, to get the flag in '/root/flag.txt' -> HTB{pr1v1l363\_35c4l4710n\_2\_r007}\
9\. Run an nmap script scan on the target. What is the Apache version running on the server? (answer format: X.X.XX) -> 2.4.18\
10\. Gain a foothold on the target and submit the user.txt flag -> 79c03865431abf47b90ef24b9695e148\
11\. Escalate privileges and submit the root.txt flag. -> de5e5d6619862a8aa5b9b212314e0cdd\
12\. Spawn the target, gain a foothold and submit the contents of the user.txt flag. -> 7002d65b149b0a4d19132a66feed21d8\
13\. After obtaining a foothold on the target, escalate privileges to root and submit the contents of the root.txt flag -> f1fba6e9f71efb2630e6e34da6387842\
\
Module: Network Enumeration with Nmap\
1\. Based on the last result, find out which operating system it belongs to. Submit the name of the operating system as result. -> windows\
2\. Find all TCP ports on your target. Submit the total number of found TCP ports as the answer. -> 7\
3\. Enumerate the hostname of your target and submit it as the answer. (case-sensitive) -> NIX-NMAP-DEFAULT\
4\. Perform a full TCP port scan on your target and create an HTML report. Submit the number of the highest port as the answer -> 31337\
5\. Enumerate all ports and their services. One of the services contains the flag you have to submit as the answer. -> HTB{pr0F7pDv3r510nb4nn3r}\
6\. Use NSE and its scripts to find the flag that one of the services contain and submit it as the answer. -> HTB{873nniuc71bu6usbs1i96as6dsv26}\
7\. Our client wants to know if we can identify which operating system their provided machine is running on. Submit the OS name as the answer. -> Ubuntu\
8\. After the configurations are transferred to the system, our client wants to know if it is possible to find out our target's DNS server version. Submit the DNS server version of the target as the answer -> HTB{GoTtgUnyze9Psw4vGjcuMpHRp}\
9\. Now our client wants to know if it is possible to find out the version of the running services. Identify the version of service our client was talking about and submit the flag as the answer. -> HTB{kjnsdf2n982n1827eh76238s98di1w6}\
\
Module: Footprinting\
1\. Which version of the FTP server is running on the target system? Submit the entire banner as the answer. -> InFreight FTP v1.1\
2\. Enumerate the FTP server and find the flag.txt file. Submit the contents of it as the answer. -> HTB{b7skjr4c76zhsds7fzhd4k3ujg7nhdjre}\
3\. What version of the SMB server is running on the target system? Submit the entire banner as the answer. -> Samba smbd 4.6.2\
4\. What is the name of the accessible share on the target? -> sambashare\
5\. Connect to the discovered share and find the flag.txt file. Submit the contents as the answer. -> HTB{o873nz4xdo873n4zo873zn4fksuhldsf}\
6\. Find out which domain the server belongs to. -> devops\
7\. Find additional information about the specific share we found previously and submit the customized version of that specific share as the answer. -> InFreight SMB v3.1\
8\. What is the full system path of that specific share? -> /home/sambauser\
9\. Enumerate the NFS service and submit the contents of the flag.txt in the "nfs" share as the answer. -> HTB{hjglmvtkjhlkfuhgi734zthrie7rjmdze}\
10\. Enumerate the NFS service and submit the contents of the flag.txt in the "nfsshare" share as the answer. -> HTB{8o7435zhtuih7fztdrzuhdhkfjcn7ghi4357ndcthzuc7rtfghu34}\
11\. Interact with the target DNS using its IP address and enumerate the FQDN of it for the "inlanefreight.htb" domain. -> ns.inlanefreight.htb\
12\. Identify if its possible to perform a zone transfer and submit the TXT record as the answer. (Format: HTB{...)) -> HTB{DN5\_z0N3\_7r4N5F3r\_iskdufhcnlu34}\
13\. What is the IPv4 address of the hostname DC1? -> 10.129.34.16\
14\. What is the FQDN of the host where the last octet ends with "x.x.x.203"? -> win2k.dev.inlanefreight.htb\
15\. Enumerate the SMTP service and submit the banner, including its version as the answer. -> InFreight ESMTP v2.11\
16\. Enumerate the SMTP service even further and find the username that exists on the system. Submit it as the answer. -> robin\
17\. Figure out the exact organization name from the IMAP/POP3 service and submit it as the answer. -> InLaneFreight Ltd\
18\. What is the FQDN that the IMAP and POP3 servers are assigned to? -> dev.inlanefreight.htb\
19\. Enumerate the IMAP service and submit the flag as the answer. (Format: HTB{...}) -> HTB{roncfbw7iszerd7shni7jr2343zhrj}\
20\. What is the customized version of the POP3 server? -> InFreight POP3 v9.188\
21\. What is the admin email address? -> devadmin@inlanefreight.htb\
22\. Try to access the emails on the IMAP server and submit the flag as the answer. (Format: HTB{...}) -> HTB{983uzn8jmfgpd8jmof8c34n7zio}\
23\. Enumerate the SNMP service and obtain the email address of the admin. Submit it as the answer. -> devadmin@inlanefreight.htb\
24\. What is the customized version of the SNMP server? -> InFreight SNMP v0.91\
25\. Enumerate the custom script that is running on the system and submit its output as the answer. -> HTB{5nMp\_fl4g\_uidhfljnsldiuhbfsdij44738b2u763g}\
26\. Enumerate the MySQL server and determine the version in use. (Format: MySQL X.X.XX) -> MySQL 8.0.27\
27\. During our penetration test, we found weak credentials "robin:robin". We should try these against the MySQL server. What is the email address of the customer "Otto Lang"? -> ultrices@google.htb\
28\. Enumerate the target using the concepts taught in this section. List the hostname of MSSQL server. -> ILF-SQL-01\
29\. Connect to the MSSQL instance running on the target using the account (backdoor:Password1), then list the non-default database present on the server. -> Employees\
30\. Enumerate the target Oracle database and submit the password hash of the user DBSNMP as the answer. -> E066D214D5421CCC\
31\. What username is configured for accessing the host via IPMI? -> admin\
32\. What is the account's cleartext password? -> trinity\
33\. Enumerate the server carefully and find the flag.txt file. Submit the contents of this file as the answer. -> HTB{7nrzise7hednrxihskjed7nzrgkweunj47zngrhdbkjhgdfbjkc7hgj}\
34\. Enumerate the server carefully and find the username "HTB" and its password. Then, submit this user's password as the answer. -> lnch7ehrdn43i7AoqVPK4zWR\
35\. Enumerate the server carefully and find the username "HTB" and its password. Then, submit HTB's password as the answer. -> cr3n4o7rzse7rzhnckhssncif7ds\
\
Module: Information Gathering - Web Edition\
1\. Perform a WHOIS lookup against the paypal.com domain. What is the registrar Internet Assigned Numbers Authority (IANA) ID number? -> 292\
2\. What is the admin email contact for the tesla.com domain (also in-scope for the Tesla bug bounty program)? -> hostmaster@paypal.com\
3\. Which subdomain is returned when querying the PTR record for 173.0.87.51? -> cloudmonitor30.paypal.com\
4\. What is the first mailserver returned when querying the MX records for paypal.com? -> mx1.paypalcorp.com\
5\. What Apache version is running on app.inlanefreight.local? (Format: 0.0.0) -> 2.4.41\
6\. Which CMS is used on app.inlanefreight.local? (Format: word) -> joomla!\
7\. On which operating system is the dev.inlanefreight.local webserver running on? (Format: word) -> ubuntu\
8\. Submit the FQDN of the nameserver for the "inlanefreight.htb" domain as the answer. -> ns.inlanefreight.htb\
9\. Identify how many zones exist on the target nameserver. Submit the number of found zones as the answer -> 2\
10\. Find and submit the contents of the TXT record as the answer. -> ZONE\_TRANSFER{87o2z3cno7zsoiedznxoi82z3o47xzhoi}\
11\. What is the FQDN of the IP address 10.10.34.136? -> ns2.internal.inlanefreight.htb\
12\. What FQDN is assigned to the IP address 10.10.1.5? Submit the FQDN as the answer. -> dc3.internal.inlanefreight.htb\
13\. Which IP address is assigned to the "us.inlanefreight.htb" subdomain. Submit the IP address as the answer. -> 10.10.200.5\
14\. Submit the number of all "A" records from all zones as the answer. -> 27\
15\. Enumerate the target and find a vHost that contains flag No. 1. Submit the flag value as your answer (in the format HTB{DATA}). -> HTB{h8973hrpiusnzjoie7zrou23i4zhmsxi8732zjso}\
16\. Enumerate the target and find a vHost that contains flag No. 2. Submit the flag value as your answer (in the format HTB{DATA}). -> HTB{u23i4zhmsxi872z3rn98h7nh2sxnbgriusd32zjso}\
17\. Enumerate the target and find a vHost that contains flag No. 3. Submit the flag value as your answer (in the format HTB{DATA}). -> HTB{Fl4gF0uR\_o8763tznb4xou7zhgsniud7gfi734}\
18\. Enumerate the target and find a vHost that contains flag No. 4. Submit the flag value as your answer (in the format HTB{DATA}). -> HTB{bzghi7tghin2u76x3ghdni62higz7x3s}\
19\. Find the specific vHost that starts with the letter "d" and submit the flag value as your answer (in the format HTB{DATA}). -> HTB{7zbnr4i3n7zhrxn347zhh3dnrz4dh7zdjfbgn6d}\
20\. What is the registrar IANA ID number for the githubapp.com domain? -> 292\
21\. What is the last mailserver returned when querying the MX records for githubapp.com? -> aspmx5.googlemail.com\
22\. Perform active infrastructure identification against the host [https://i.imgur.com](https://i.imgur.com/). What server name is returned for the host? -> cat factory 1.0\
23\. Perform subdomain enumeration against the target githubapp.com. Which subdomain has the word 'triage' in the name? -> fastly-elephants.githubapp.com\
\
Module: Vulnerability Assessment\
1\. What is the name of one of the accessible SMB shares from the authenticated Windows scan? (One word) -> wsus\
2\. What was the target for the authenticated scan? -> 172.16.16.100\
3\. What is the plugin ID of the highest criticality vulnerability for the Windows authenticated scan? -> 156032\
4\. What is the name of the vulnerability with plugin ID 26925 from the Windows authenticated scan? (Case sensitive) -> VNC Server Unauthenticated Access\
5\. What port is the VNC server running on in the authenticated Windows scan? -> 5900\
6\. What type of operating system is the Linux host running? (one word) -> ubuntu\
7\. What type of FTP vulnerability is on the Linux host? (Case Sensitive, four words) -> Anonymous FTP Login Reporting\
8\. What is the IP of the Linux host targeted for the scan? -> 172.16.16.160\
9\. What vulnerability is associated with the HTTP server? (Case-sensitive) -> Cleartext Transmission of Sensitive Information via HTTP\
\
Module: File Transfers\
1\. Download the file flag.txt from the web root using wget from the Pwnbox. Submit the contents of the file as your answer. -> b1a4ca918282fcd96004565521944a3b\
2\. Upload the attached file named upload\_win.zip to the target using the method of your choice. Once uploaded, RDP to the box, unzip the archive, and run "hasher upload\_win.txt" from the command line. Submit the generated hash as your answer. -> f458303ea783c224c6b4e7ef7f17eb9d\
3\. Download the file flag.txt from the web root using Python from the Pwnbox. Submit the contents of the file as your answer. -> 5d21cf3da9c0ccb94f709e2559f3ea50\
4\.  Upload the attached file named upload\_nix.zip to the target using the method of your choice. Once uploaded, SSH to the box, extract the file, and run "hasher \<extracted file>" from the command line. Submit the generated hash as your answer. -> 159cfe5c65054bbadb2761cfa359c8b0\
\
Module: Shells & Payloads\
1\. Which two shell languages did we experiment with in this section? (Format: shellname\&shellname) -> bash\&powershell\
2\. In Pwnbox issue the $PSversiontable variable using PowerShell. Submit the edition of PowerShell that is running as the answer. -> core\
3\. Des is able to issue the command nc -lvnp 443 on a Linux target. What port will she need to connect to from her attack box to successfully establish a shell session? -> 443\
4\. SSH to the target, create a bind shell, then use netcat to connect to the target using the bind shell you set up. When you have completed the exercise, submit the contents of the flag.txt file located at /customscripts. -> B1nD\_Shells\_r\_cool\
5\. When establishing a reverse shell session with a target, will the target act as a client or server? -> client\
6\. Connect to the target via RDP and establish a reverse shell session with your attack box then submit the hostname of the target box. -> Shells-Win10\
7\. What command language interpreter is used to establish a system shell session with the target? -> powershell\
8\. Exploit the target using what you've learned in this section, then submit the name of the file located in htb-student's Documents folder. (Format: filename.extension) -> staffsalaries.txt\
9\. What file type is a text-based DOS script used to perform tasks from the cli? (answer with the file extension, e.g. '.something') -> .bat\
10\. What Windows exploit was dropped as a part of the Shadow Brokers leak? (Format: ms bulletin number, e.g. MSxx-xxx) -> MS17-010\
11\. Gain a shell on the vulnerable target, then submit the contents of the flag.txt file that can be found in C:\ -> EB-Still-W0rk$\
12\. What language is the payload written in that gets uploaded when executing rconfig\_vendors\_auth\_file\_upload\_rce? -> PHP\
13\. Exploit the target and find the hostname of the router in the devicedetails directory at the root of the file system. -> edgerouter-isp\
14\. Establish a web shell session with the target using the concepts covered in this section. Submit the full path of the directory you land in. (Format: c:\path\you\land\in) -> c:\windows\system32\inetsrv\
15\. Where is the Laudanum aspx web shell located on Pwnbox? Submit the full path. (Format: /path/to/laudanum/aspx) -> /usr/share/webshells/laudanum/aspx/shell.aspx\
16\. Where is the Antak webshell located on Pwnbox? Submit the full path. (Format:/path/to/antakwebshell) -> /usr/share/nishang/Antak-WebShell/antak.aspx\
17\. Establish a web shell with the target using thc39f2beb3d2ec06a62cb887fb391dee0e concepts covered in this section. Submit the name of the user on the target that the commands are being issued as. In order to get the correct answer you must navigate to the web shell you upload using the vHost name. (Format: \*\*\*\*\\\*\*\*\*, 1 space) -> iis apppool\status\
18\. In the example shown, what must the Content-Type be changed to in order to successfully upload the web shell? (Format: .../... ) -> image/gif\
19\. Use what you learned from the module to gain a web shell. What is the file name of the gif in the /images/vendor directory on the target? (Format: xxxx.gif) -> ajax-loader.gif\
20\. What is the hostname of Host-1? (Format: all lower case) -> shells-winsvr\
21\. Exploit the target and gain a shell session. Submit the name of the folder located in C:\Shares\ (Format: all lower case) -> dev-share\
22\. What distribution of Linux is running on Host-2? (Format: distro name, all lower case) -> ubuntu\
23\. What language is the shell written in that gets uploaded when using the 50064.rb exploit? -> php\
24\. Exploit the blog site and establish a shell session with the target OS. Submit the contents of /customscripts/flag.txt -> B1nD\_Shells\_r\_cool\
25\. What is the hostname of Host-3? -> shells-winblue\
26\. Exploit and gain a shell session with Host-3. Then submit the contents of C:\Users\Administrator\Desktop\Skills-flag.txt -> One-H0st-Down!\
\
Module: Using the Metasploit Framework\
1\. Which version of Metasploit comes equipped with a GUI interface? -> metasploit pro\
2\. What command do you use to interact with the free version of Metasploit? -> msfconsole\
3\. Use the Metasploit-Framework to exploit the target with EternalRomance. Find the flag.txt file on Administrator's desktop and submit the contents as the answer. -> HTB{MSF-W1nD0w5-3xPL01t4t10n}\
4\. Exploit the Apache Druid service and find the flag.txt file. Submit the contents of this file as the answer. -> HTB{MSF\_Expl01t4t10n}\
5\. The target has a specific web application running that we can find by looking into the HTML source code. What is the name of that web application? -> elfinder\
6\. Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with? -> www-data\
7\. The target system has an old version of Sudo running. Find the relevant exploit and get root access to the target system. Find the flag.txt file and submit the contents of it as the answer. -> HTB{5e55ion5\_4r3\_sw33t}\
8\. Find the existing exploit in MSF and use it to get a shell on the target. What is the username of the user you obtained a shell with? -> NT AUTHORITY\SYSTEM\
9\. Retrieve the NTLM password hash for the "htb-student" user. Submit the hash as the answer. -> cf3a5525ee9414229e66279623ed5c58\
\
Module: Password Attacks\
1\. Find the user for the WinRM service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer -> HTB{That5Novemb3r}\
2\. Find the user for the SSH service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer. -> HTB{Let5R0ck1t}\
3\. Find the user for the RDP service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer. -> HTB{R3m0t3DeskIsw4yT00easy}\
4\. Find the user for the SMB service and crack their password. Then, when you log in, you will find the flag in a file there. Submit the flag you found as the answer. -> HTB{S4ndM4ndB33}\
5\. Create a mutated wordlist using the files in the ZIP file under "Resources" in the top right corner of this section. Use this wordlist to brute force the password for the user "sam". Once successful, log in with SSH and submit the contents of the flag.txt file as your answer. -> HTB{P455\_Mu7ations}\
6\. Use the user's credentials we found in the previous section and find out the credentials for MySQL. Submit the credentials as the answer. (Format: \<username>:\<password>) -> superdba:admin\
7\. Where is the SAM database located in the Windows registry? (Format: \*\*\*\*\\\*\*\*) -> hklm\sam\
8\. Apply the concepts taught in this section to obtain the password to the ITbackdoor user account on the target. Submit the clear-text password as the answer. -> matrix\
9\. Dump the LSA secrets on the target and discover the credentials stored. Submit the username and password as the answer. (Format: username:password, Case-Sensitive) -> frontdesk:Password123\
10\. What is the name of the executable file associated with the Local Security Authority Process? -> lsass.exe\
11\. Apply the concepts taught in this section to obtain the password to the Vendor user account on the target. Submit the clear-text password as the answer. (Format: Case sensitive) -> Mic@123\
12\. What is the name of the file stored on a domain controller that contains the password hashes of all domain accounts? (Format: \*\*\*\*.\*\*\*) -> ntds.dit\
13\. Submit the NT hash associated with the Administrator user from the example output in the section reading. -> 64f12cddaa88057e06a81b54e73b949b\
14\. On an engagement you have gone on several social media sites and found the Inlanefreight employee names: John Marston IT Director, Carol Johnson Financial Controller and Jennifer Stapleton Logistics Manager. You decide to use these names to conduct your password attacks against the target domain controller. Submit John Marston's credentials as the answer. (Format: username:password, Case-Sensitive) -> jmarston:P@ssword!\
15\. Capture the NTDS.dit file and dump the hashes. Use the techniques taught in this section to crack Jennifer Stapleton's password. Submit her clear-text password as the answer. (Format: Case-Sensitive) -> Winter2008\
16\. What password does Bob use to connect to the Switches via SSH? (Format: Case-Sensitive) -> WellConnected123\
17\. What is the GitLab access code Bob uses? (Format: Case-Sensitive) -> 3z1ePfGbjWPsTfCsZfjy\
18\. What credentials does Bob use with WinSCP to connect to the file server? (Format: username:password, Case-Sensitive) -> ubuntu:FSadmin123\
19\. What is the default password of every newly created Inlanefreight Domain user account? (Format: Case-Sensitive) -> Inlanefreightisgreat2022\
20\. What are the credentials to access the Edge-Router? (Format: username:password, Case-Sensitive) -> edgeadmin:Edge@dmin123!\
21\. Examine the target and find out the password of the user Will. Then, submit the password as the answer. -> TUqr7QfLTLhruhVbCP\
22\. Examine the target using the credentials from the user Will and find out the password of the "root" user. Then, submit the password as the answer. -> J0rd@n5\
23\. Access the target machine using any Pass-the-Hash tool. Submit the contents of the file located at C:\pth.txt. -> G3t\_4CCE\$$\_V1@\_PTH\
24\. Try to connect via RDP using the Administrator hash. What is the name of the registry value that must be set to 0 for PTH over RDP to work? Change the registry key value and connect using the hash with RDP. Submit the name of the registry value name as the answer. -> DisableRestrictedAdmin\
25\. Connect via RDP and use Mimikatz located in c:\tools to extract the hashes presented in the current session. What is the NTLM/RC4 hash of David's account? -> c39f2beb3d2ec06a62cb887fb391dee0\
26\. Using David's hash, perform a Pass the Hash attack to connect to the shared folder \\\DC01\david and read the file david.txt. -> D3V1d\_Fl5g\_is\_Her3\
27\. Using Julio's hash, perform a Pass the Hash attack to connect to the shared folder \\\DC01\julio and read the file julio.txt. -> JuL1()\_SH@re\_fl@g\
28\. Using Julio's hash, perform a Pass the Hash attack, launch a PowerShell console and import Invoke-TheHash to create a reverse shell to the machine you are connected via RDP (the target machine, DC01, can only connect to MS01). Use the tool nc.exe located in c:\tools to listen for the reverse shell. Once connected to the DC01, read the flag in C:\julio\flag.txt. -> JuL1()\_N3w\_fl@g\
29\. Connect to the target machine using RDP and the provided creds. Export all tickets present on the computer. How many users TGT did you collect? -> 3\
30\. Use john's TGT to perform a Pass the Ticket attack and retrieve the flag from the shared folder \\\DC01.inlanefreight.htb\john -> Learn1ng\_M0r3\_Tr1cks\_with\_J0hn\
31\. Use john's TGT to perform a Pass the Ticket attack and connect to the DC01 using PowerShell Remoting. Read the flag from C:\john\john.txt -> P4\$$\_th3\_Tick3T\_PSR\
32\. Connect to the target machine using SSH to the port TCP/2222 and the provided credentials. Read the flag in David's home directory. -> Gett1ng\_Acc3\$$\_to\_LINUX01\
33\. Which group can connect to LINUX01? -> Linux Admins\
34\. Look for a keytab file that you have read and write access. Submit the file name as a response. -> carlos.keytab\
35\. Extract the hashes from the keytab file you found, crack the password, log in as the user and submit the flag in the user's home directory. -> C@rl0s\_1$\_H3r3\
36\. Check Carlos' crontab, and look for keytabs to which Carlos has access. Try to get the credentials of the user svc\_workstations and use them to authenticate via SSH. Submit the flag.txt in svc\_workstations' home directory. -> Mor3\_4cce\$$\_m0r3\_Pr1v$\
37\. Check svc\_workstation's sudo privileges and get access as root. Submit the flag in /root/flag.txt directory as the response -> Ro0t\_Pwn\_K3yT4b\
38\. Check the /tmp directory and find Julio's Kerberos ticket (ccache file). Import the ticket and read the contents of julio.txt from the domain share folder \\\DC01\julio. -> JuL1()\_SH@re\_fl@g\
39\. Use the LINUX01$ Kerberos ticket to read the flag found in \\\DC01\linux01. Submit the contents as your response (the flag starts with Us1nG\_). -> Us1nG\_KeyTab\_Like\_@\_PRO\
40\. Use the cracked password of the user Kira and log in to the host and crack the "id\_rsa" SSH key. Then, submit the password for the SSH key as the answer. -> L0veme\
41\. Use the cracked password of the user Kira, log in to the host, and read the Notes.zip file containing the flag. Then, submit the flag as the answer. -> HTB{ocnc7r4io8ucsj8eujcm}\
42\. Examine the first target and submit the root password as the answer. -> dgb6fzm0ynk@AME9pqu\
43\. Examine the second target and submit the contents of flag.txt in /root/ as the answer. -> HTB{PeopleReuse\_PWsEverywhere!}\
44\. Examine the third target and submit the contents of flag.txt in C:\Users\Administrator\Desktop\ as the answer. -> HTB{PWcr4ck1ngokokok}\
\
Module: Attacking Common Services\
1\. What port is the FTP service running on? -> 2121\
2\. What username is available for the FTP server? -> robin\
3\. Use the discovered username with its password to login via SSH and obtain the flag.txt file. Submit the contents as your answer. -> HTB{ATT4CK1NG\_F7P\_53RV1C3}\
4\. What is the name of the shared folder with READ permissions? -> ggj\
5\. What is the password for the username "jason"? -> 34c8zuNBo91!@28Bszh\
6\. Login as the user "jason" via SSH and find the flag.txt file. Submit the contents as your answer. -> HTB{SMB\_4TT4CKS\_2349872359}\
7\. What is the password for the "mssqlsvc" user? -> princess1\
8\. Enumerate the "flagDB" database and submit a flag as your answer. -> HTB{!\_l0v3\_#4$#!n9\_4nd\_r3$p0nd3r}\
9\. What is the name of the file that was left on the Desktop? (Format example: filename.txt) -> pentest-notes.txt\
10\. Which registry key needs to be changed to allow Pass-the-Hash with the RDP protocol? -> disablerestrictedadmin\
11\. Connect via RDP with the Administrator account and submit the flag.txt as you answer. -> HTB{RDP\_P4\$$\_Th3\_H4$#}\
12\. Find all available DNS records for the "inlanefreight.htb" domain on the target name server and submit the flag found as a DNS record as the answer. -> HTB{LUIHNFAS2871SJK1259991}\
13\. What is the available username for the domain inlanefreight.htb in the SMTP server? -> marlin\
14\. Access the email account using the user credentials that you discovered and submit the flag in the email as your answer. -> HTB{w34k\_p4\$$w0rd}\
15\. You are targeting the inlanefreight.htb domain. Assess the target server and obtain the contents of the flag.txt file. Submit it as the answer. -> HTB{t#3r3\_4r3\_tw0\_w4y$\_t0\_93t\_t#3\_fl49}\
16\. Assess the target server and find the flag.txt file. Submit the contents of this file as your answer. -> HTB{1qay2wsx3EDC4rfv\_M3D1UM}\
17\. What file can you retrieve that belongs to the user "simon"? (Format: filename.txt) -> random.txt\
18\. Enumerate the target and find a password for the user Fiona. What is her password? -> 48Ns72!bns74@S84NNNSl\
19\. Once logged in, what other user can we compromise to gain admin privileges? -> john\
20\. Submit the contents of the flag.txt file on the Administrator Desktop -> HTB{46u$!n9\_l!nk3d\_$3rv3r$}\
\
Module: Pivoting, Tunneling, and Port Forwarding\
1\. Reference the Using ifconfig output in the section reading. Which NIC is assigned a public IP address? -> eth0\
2\. Reference the Routing Table on Pwnbox output shown in the section reading. If a packet is destined for a host with the IP address of 10.129.10.25, out of which NIC will the packet be forwarded? -> tun0\
3\. Reference the Routing Table on Pwnbox output shown in the section reading. If a packet is destined for [www.hackthebox.com](http://www.hackthebox.com/) what is the IP address of the gateway it will be sent to? -> 178.62.64.1\
4\. You have successfully captured credentials to an external facing Web Server. Connect to the target and list the network interfaces. How many network interfaces does the target web server have? (Including the loopback interface) -> 3\
5\. Apply the concepts taught in this section to pivot to the internal network and use RDP (credentials: victor:pass@123) to take control of the Windows target on 172.16.5.19. Submit the contents of Flag.txt located on the Desktop. -> N1c3Piv0t\
6\. Which IP address assigned to the Ubuntu server Pivot host allows communication with the Windows server target? (Format: x.x.x.x) -> 172.16.5.129\
7\. What IP address is used on the attack host to ensure the handler is listening on all IP addresses assigned to the host? (Format: x.x.x.x) -> 0.0.0.0\
8\. What two IP addresses can be discovered when attempting a ping sweep from the Ubuntu pivot host? (Format: x.x.x.x,x.x.x.x) -> 172.16.5.19,172.16.5.129\
9\. Which of the routes that AutoRoute adds allows 172.16.5.19 to be reachable from the attack host? (Format: x.x.x.x/x.x.x.x) -> 172.16.5.0/255.255.254.0\
10\. SSH tunneling is required with Socat. True or False? -> FALSE\
11\. What Meterpreter payload did we use to catch the bind shell session? (Submit the full path as the answer) -> windows/x64/meterpreter/bind\_tcp\
12\. From which host will rpivot's server.py need to be run from? The Pivot Host or Attack Host? Submit Pivot Host or Attack Host as the answer. -> attack host\
13\. From which host will rpivot's client.py need to be run from? The Pivot Host or Attack Host. Submit Pivot Host or Attack Host as the answer. -> pivot host\
14\. Using the concepts taught in this section, connect to the web server on the internal network. Submit the flag presented on the home page as the answer. -> I\_L0v3\_Pr0xy\_Ch@ins\
15\. Using the concepts covered in this section, take control of the DC (172.16.5.19) using xfreerdp by pivoting through the Windows 10 target host. Submit the approved contact's name found inside the "VendorContacts.txt" file located in the "Approved Vendors" folder on Victor's desktop (victor's credentials: victor:pass@123) . (Format: 1 space, not case-sensitive) -> jim flipflop\
16\.  Using the concepts taught in this section, connect to the target and establish a DNS Tunnel that provides a shell session. Submit the contents of C:\Users\htb-student\Documents\flag.txt as the answer. -> AC@tinth3Tunnel\
17\. Using the concepts taught in this section, connect to the target and establish a SOCKS5 Tunnel that can be used to RDP into the domain controller (172.16.5.19, victor:pass@123). Submit the contents of C:\Users\victor\Documents\flag.txt as the answer. -> Th3$eTunne1$@rent8oring!\
18\. Using the concepts taught thus far, connect to the target and establish an ICMP tunnel. Pivot to the DC (172.16.5.19, victor:pass@123) and submit the contents of C:\Users\victor\Downloads\flag.txt as the answer. -> N3Tw0rkTunnelV1sion!\
19\. Use the concepts taught in this section to pivot to the Windows server at 172.16.6.155 (jason:WellConnected123!). Submit the contents of Flag.txt on Jason's Desktop. -> H0pping@roundwithRDP!\
20\. + 1 Once on the webserver, enumerate the host for credentials that can be used to start a pivot or tunnel to another host in the network. In what user's directory can you find the credentials? Submit the name of the user as the answer. -> webadmin\
21\. Submit the credentials found in the user's home directory. (Format: user:password) -> mlefay:Plain Human work!\
22\. Enumerate the internal network and discover another active host. Submit the IP address of that host as the answer. -> 172.16.5.35\
23\. Use the information you gathered to pivot to the discovered host. Submit the contents of C:\Flag.txt as the answer -> S1ngl3-Piv07-3@sy-Day\
24\. In previous pentests against Inlanefreight, we have seen that they have a bad habit of utilizing accounts with services in a way that exposes the users credentials and the network as a whole. What user is vulnerable? -> vfrank\
25\. For your next hop enumerate the networks and then utilize a common remote access solution to pivot. Submit the C:\Flag.txt located on the workstation. -> N3tw0rk-H0pp1ng-f0R-FuN\
26\. Submit the contents of C:\Flag.txt located on the Domain Controller. -> 3nd-0xf-Th3-R@inbow!\
\
Module: Active Directory Enumeration & Attacks\
1\. While looking at inlanefreights public records; A flag can be seen. Find the flag and submit it. ( format == HTB{\*\*\*\*\*\*} ) -> HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}\
2\. From your scans, what is the "commonName" of host 172.16.5.5 ? -> ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\
3\. What host is running "Microsoft SQL Server 2019 15.00.2000.00"? (IP address, not Resolved name) -> 172.16.5.130\
4\. Run Responder and obtain a hash for a user account that starts with the letter b. Submit the account name as your answer. -> backupagent\
5\. Crack the hash for the previous account and submit the cleartext password as your answer. -> h1backup55\
6\. Run Responder and obtain an NTLMv2 hash for the user wley. Crack the hash using Hashcat and submit the user's password as your answer -> transporter@4\
7\. Run Inveigh and capture the NTLMv2 hash for the svc\_qualys account. Crack and submit the cleartext password as the answer. -> security#1\
8\. What is the default Minimum password length when a new domain is created? (One number) -> 7\
9\. What is the minPwdLength set to in the INLANEFREIGHT.LOCAL domain? (One number) -> 8\
10\. Enumerate valid usernames using Kerbrute and the wordlist located at /opt/jsmith.txt on the ATTACK01 host. How many valid usernames can we enumerate with just this wordlist from an unauthenticated standpoint? -> 56\
11\. Find the user account starting with the letter "s" that has the password Welcome1. Submit the username as your answer. -> sgage\
12\. Using the examples shown in this section, find a user with the password Winter2022. Submit the username as the answer. -> dbranch\
13\. What AD User has a RID equal to Decimal 1170? -> mmorgan\
14\. What is the membercount: of the "Interns" group? -> 10\
15\. Using Bloodhound, determine how many Kerberoastable accounts exist within the INLANEFREIGHT domain. (Submit the number as the answer) -> 13\
16\. What PowerView function allows us to test if a user has administrative access to a local or remote host? -> test-adminaccess\
17\. Run Snaffler and hunt for a readable web config file. What is the name of the user in the connection string within the file? -> sa\
18\. What is the password for the database user? -> ILFREIGHTDB01!\
19\. Enumerate the host's security configuration information and provide its AMProductVersion. -> 4.18.2109.6\
20\. What domain user is explicitly listed as a member of the local Administrators group on the target host? -> adunn\
21\. Utilizing techniques learned in this section, find the flag hidden in the description field of a disabled account with administrative privileges. Submit the flag as the answer. -> HTB{LD@P\_I$\_W1ld}\
22\. Retrieve the TGS ticket for the SAPService account. Crack the ticket offline and submit the password as your answer. -> !SapperFi2\
23\. What powerful local group on the Domain Controller is the SAPService user a member of? -> account operators\
24\. What is the name of the service account with the SPN 'vmware/inlanefreight.local'? -> svc\_vmwaresso\
25\. Crack the password for this account and submit it as your answer. -> Virtual01\
26\. What type of ACL defines which security principals are granted or denied access to an object? (one word) -> DACL\
27\. Which ACE entry can be leveraged to perform a targeted Kerberoasting attack? -> GenericAll\
28\. What is the rights GUID for User-Force-Change-Password? -> 00299570-246d-11d0-a768-00aa006e0529\
29\. What flag can we use with PowerView to show us the ObjectAceType in a human-readable format during our enumeration? -> resolveguids\
30\. What privileges does the user damundsen have over the Help Desk Level 1 group? -> GenericWrite\
31\. Using the skills learned in this section, enumerate the ActiveDirectoryRights that the user forend has over the user dpayne (Dagmar Payne). -> GenericAll\
32\. What is the ObjectAceType of the first right that the forend user has over the GPO Management group? (two words in the format Word-Word) -> Self-Membership\
33\. Work through the examples in this section to gain a better understanding of ACL abuse and performing these skills hands-on. Set a fake SPN for the adunn account, Kerberoast the user, and crack the hash using Hashcat. Submit the account's cleartext password as your answer. -> SyncMaster757\
34\. Perform a DCSync attack and look for another user with the option "Store password using reversible encryption" set. Submit the username as your answer. -> syncron\
35\. What is this user's cleartext password? -> Mycleart3xtP@ss!\
36\. Perform a DCSync attack and submit the NTLM hash for the khartsfield user as your answer. -> 4bb3b317845f0954200a6b0acc9b9f9a\
37\. What other user in the domain has CanPSRemote rights to a host? -> bdavis\
38\. What host can this user access via WinRM? (just the computer name) -> academy-ea-dc01\
39\. Leverage SQLAdmin rights to authenticate to the ACADEMY-EA-DB01 host (172.16.5.150). Submit the contents of the flag at C:\Users\damundsen\Desktop\flag.txt. -> 1m\_the\_sQl\_@dm1n\_n0w!\
40\. Which two CVEs indicate NoPac.py may work? (Format: ####-#####\&####-#####, no spaces) -> 2021-42278&2021-42287\
41\. Apply what was taught in this section to gain a shell on DC01. Submit the contents of flag.txt located in the DailyTasks directory on the Administrator's desktop. -> D0ntSl@ckonN0P@c!\
42\. Find another user with the passwd\_notreqd field set. Submit the samaccountname as your answer. The samaccountname starts with the letter "y". -> ygroce\
43\. Find another user with the "Do not require Kerberos pre-authentication setting" enabled. Perform an ASREPRoasting attack against this user, crack the hash, and submit their cleartext password as your answer. -> Pass@word\
44\. What is the child domain of INLANEFREIGHT.LOCAL? (format: FQDN, i.e., DEV.ACME.LOCAL) -> logistics.inlanefreight.local\
45\. What domain does the INLANEFREIGHT.LOCAL domain have a forest transitive trust with? -> freightlogistics.local\
46\. What direction is this trust? -> bidirectional\
47\. What is the SID of the child domain? -> S-1-5-21-2806153819-209893948-922872689\
48\. What is the SID of the Enterprise Admins group in the root domain? -> S-1-5-21-3842939050-3880317879-2865463114-519\
49\. Perform the ExtraSids attack to compromise the parent domain. Submit the contents of the flag.txt file located in the c:\ExtraSids folder on the ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL domain controller in the parent domain. -> f@ll1ng\_l1k3\_d0m1no3$\
50\. Perform the ExtraSids attack to compromise the parent domain from the Linux attack host. After compromising the parent domain obtain the NTLM hash for the Domain Admin user bross. Submit this hash as your answer. -> 49a074a39dd0651f647e765c2cc794c7\
51\. Perform a cross-forest Kerberoast attack and obtain the TGS for the mssqlsvc user. Crack the ticket and submit the account's cleartext password as your answer. -> 1logistics\
52\. Kerberoast across the forest trust from the Linux attack host. Submit the name of another account with an SPN aside from MSSQLsvc. -> sapsso\
53\. Crack the TGS and submit the cleartext password as your answer. -> pabloPICASSO\
54\. Log in to the ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL Domain Controller using the Domain Admin account password submitted for question #2 and submit the contents of the flag.txt file on the Administrator desktop. -> burn1ng\_d0wn\_th3\_f0rest!\
55\. Submit the contents of the flag.txt file on the administrator Desktop of the web server -> JusT\_g3tt1ng\_st@rt3d!\
56\. Kerberoast an account with the SPN MSSQLSvc/SQL01.inlanefreight.local:1433 and submit the account name as your answer -> svc\_sql\
57\. Crack the account's password. Submit the cleartext value. -> lucky7\
58\. Submit the contents of the flag.txt file on the Administrator desktop on MS01 -> spn$\_r0ast1ng\_on\_@n\_0p3n\_f1re\
59\. Find cleartext credentials for another domain user. Submit the username as your answer. -> tpetty\
60\. Submit this user's cleartext password. -> Sup3rS3cur3D0m@inU2eR\
61\. What attack can this user perform? -> dcsync\
62\. Take over the domain and submit the contents of the flag.txt file on the Administrator Desktop on DC01 -> r3plicat1on\_m@st3r!\
63\. Obtain a password hash for a domain user account that can be leveraged to gain a foothold in the domain. What is the account name? -> ab920\
64\. What is this user's cleartext password? -> weasel\
65\. Submit the contents of the C:\flag.txt file on MS01. -> aud1t\_gr0up\_m3mbersh1ps!\
66\. Use a common method to obtain weak credentials for another user. Submit the username for the user whose credentials you obtain -> BR086\
67\. What is this user's password? -> Welcome1\
68\. Locate a configuration file containing an MSSQL connection string. What is the password for the user listed in this file? -> D@ta\_bAse\_adm1n!\
69\. Submit the contents of the flag.txt file on the Administrator Desktop on the SQL01 host. -> s3imp3rs0nate\_cl@ssic\
70\. Submit the contents of the flag.txt file on the Administrator Desktop on the MS01 host. -> exc3ss1ve\_adm1n\_r1ights!\
71\. Obtain credentials for a user who has GenericAll rights over the Domain Admins group. What's this user's account name? -> CT059\
72\. Crack this user's password hash and submit the cleartext password as your answer. -> charlie1\
73\. Submit the contents of the flag.txt file on the Administrator desktop on the DC01 host. -> acLs\_f0r\_th3\_w1n!\
74\. Submit the NTLM hash for the KRBTGT account for the target domain after achieving domain compromise. -> 7eba70412d81c1cd030d72a3e8dbe05f\
\
Module: Using Web Proxies\
1\. Try intercepting the ping request on the server shown above, and change the post data similarly to what we did in this section. Change the command to read 'flag.txt' -> HTB{1n73rc3p73d\_1n\_7h3\_m1ddl3}\
2\. Try using request repeating to be able to quickly test commands. With that, try looking for the other flag. -> HTB{qu1ckly\_r3p3471n6\_r3qu3575}\
3\. The string found in the attached file has been encoded several times with various encoders. Try to use the decoding tools we discussed to decode it and get the flag. -> HTB{3nc0d1n6\_n1nj4}\
4\. Try running 'auxiliary/scanner/http/http\_put' in Metasploit on any website, while routing the traffic through Burp. Once you view the requests sent, what is the last line in the request? -> msf test file\
5\. Use Burp Intruder to fuzz for '.html' files under the /admin directory, to find a file containing the flag. -> HTB{burp\_1n7rud3r\_fuzz3r!}\
6\. The directory we found above sets the cookie to the md5 hash of the username, as we can see the md5 cookie in the request for the (guest) user. Visit '/skills/' to get a request with a cookie, then try to use ZAP Fuzzer to fuzz the cookie for different md5 hashed usernames to get the flag. Use the "top-usernames-shortlist.txt" wordlist from Seclists. -> HTB{fuzz1n6\_my\_f1r57\_c00k13}\
7\. Run ZAP Scanner on the target above to identify directories and potential vulnerabilities. Once you find the high-level vulnerability, try to use it to read the flag at '/flag.txt' -> HTB{5c4nn3r5\_f1nd\_vuln5\_w3\_m155}\
8\. The /lucky.php page has a button that appears to be disabled. Try to enable the button, and then click it to get the flag. -> HTB{d154bl3d\_bu770n5\_w0n7\_570p\_m3}\
9\. The /admin.php page uses a cookie that has been encoded multiple times. Try to decode the cookie until you get a value with 31-characters. Submit the value as the answer. -> 3dac93b8cd250aa8c1a36fffc79a17a\
10\. Once you decode the cookie, you will notice that it is only 31 characters long, which appears to be an md5 hash missing its last character. So, try to fuzz the last character of the decoded md5 cookie with all alpha-numeric characters, while encoding each request with the encoding methods you identified above. (You may use the "alphanum-case.txt" wordlist from Seclist for the payload) -> HTB{burp\_1n7rud3r\_n1nj4!}\
11\. You are using the 'auxiliary/scanner/http/coldfusion\_locale\_traversal' tool within Metasploit, but it is not working properly for you. You decide to capture the request sent by Metasploit so you can manually verify it and repeat it. Once you capture the request, what is the 'XXXXX' directory being called in '/XXXXX/administrator/..'? -> cfide\
\
Module: Attacking Web Applications with FFUF\
1\. In addition to the directory we found above, there is another directory that can be found. What is it? -> forum\
2\. Try to use what you learned in this section to fuzz the '/blog' directory and find all pages. One of them should contain a flag. What is the flag? -> HTB{bru73\_f0r\_c0mm0n\_p455w0rd5}\
3\. Try to repeat what you learned so far to find more files/directories. One of them should give you a flag. What is the content of the flag? -> HTB{fuzz1n6\_7h3\_w3b!}\
4\. Try running a sub-domain fuzzing test on 'inlanefreight.com' to find a customer sub-domain portal. What is the full domain of it? -> store.hackthebox.eu\
5\. Try running a VHost fuzzing scan on 'academy.htb', and see what other VHosts you get. What other VHosts did you get? -> test.academy.htb\
6\. Using what you learned in this section, run a parameter fuzzing scan on this page. what is the parameter accepted by this webpage? -> user\
7\. Try to create the 'ids.txt' wordlist, identify the accepted value with a fuzzing scan, and then use it in a 'POST' request with 'curl' to collect the flag. What is the content of the flag? -> HTB{p4r4m373r\_fuzz1n6\_15\_k3y!}\
8\. Run a sub-domain/vhost fuzzing scan on '\*.academy.htb' for the IP shown above. What are all the sub-domains you can identify? (Only write the sub-domain name) -> archive test faculty\
9\. Before you run your page fuzzing scan, you should first run an extension fuzzing scan. What are the different extensions accepted by the domains? -> php7 phps php\
10\. One of the pages you will identify should say 'You don't have access!'. What is the full page URL? -> [http://faculty.academy.htb](http://faculty.academy.htb/):PORT/courses/linux-security.php7\
11\. In the page from the previous question, you should be able to find multiple parameters that are accepted by the page. What are they? -> username user\
12\. Try fuzzing the parameters you identified for working values. One of them should return a flag. What is the content of the flag? -> HTB{w3b\_fuzz1n6\_m4573r}\
\
Module: Login Brute Forcing\
1\. Using the technique you learned in this section, try attacking the IP shown above. What are the credentials used? -> admin:admin\
2\. Try running the same exercise on the question from the previous section, to learn how to brute force for users. -> admin:admin\
3\. Using what you learned in this section, try attacking the '/login.php' page to identify the password for the 'admin' user. Once you login, you should find a flag. Submit the flag as the answer. -> HTB{bru73\_f0rc1n6\_15\_4\_l457\_r350r7}\
4\. Using what you learned in this section, try to brute force the SSH login of the user "b.gates" in the target server shown above. Then try to SSH into the server. You should find a flag in the home dir. What is the content of the flag? -> HTB{n3v3r\_u53\_c0mm0n\_p455w0rd5!}\
5\. Once you ssh in, try brute forcing the FTP login for the other user. You should find another flag in their home directory. What is the flag? -> HTB{1\_4m\_@\_bru73\_f0rc1n6\_m4573r}\
6\. When you try to access the IP shown above, you will not have authorization to access it. Brute force the authentication and retrieve the flag. -> HTB{4lw4y5\_ch4n63\_d3f4ul7\_p455w0rd5}\
7\. Once you access the login page, you are tasked to brute force your way into this page as well. What is the flag hidden inside? -> HTB{c0mm0n\_p455w0rd5\_w1ll\_4lw4y5\_b3\_h4ck3d!}\
8\. As you now have the name of an employee from the previous skills assessment question, try to gather basic information about them, and generate a custom password wordlist that meets the password policy. Also use 'usernameGenerator' to generate potential usernames for the employee. Finally, try to brute force the SSH server shown above to get the flag. -> HTB{4lw4y5\_u53\_r4nd0m\_p455w0rd\_63n3r470r}\
9\. Once you are in, you should find that another user exists in server. Try to brute force their login, and get their flag. -> HTB{1\_50l3mnly\_5w34r\_7h47\_1\_w1ll\_u53\_r4nd0m\_p455w0rd5}\
\
Module: SQL Injection Fundamentals\
1\. Connect to the database using the MySQL client from the command line. Use the 'show databases;' command to list databases in the DBMS. What is the name of the first database? -> employees\
2\. What is the department number for the 'Development' department? -> d005\
3\. What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01? -> Mitchem\
4\. In the 'titles' table, what is the number of records WHERE the employee number is greater than 10000 OR their title does NOT contain 'engineer'? -> 654\
5\. Try to log in as the user 'tom'. What is the flag value shown after you successfully log in? -> 202a1d1a8b195d5e9a57e434cc16000c\
6\. Login as the user with the id 5 to get the flag. -> cdad9ecdf6f14b45ff5c4de32909caec\
7\. Connect to the above MySQL server with the 'mysql' tool, and find the number of records returned when doing a 'Union' of all records in the 'employees' table and all records in the 'departments' table. -> 663\
8\. Use a Union injection to get the result of 'user()' -> root@localhost\
9\. What is the password hash for 'newuser' stored in the 'users' table in the 'ilfreight' database? -> 9da2c9bcdf39d8610954e0e11ea8f45f\
10\. We see in the above PHP code that '$conn' is not defined, so it must be imported using the PHP include command. Check the imported page to obtain the database password. -> dB\_pAssw0rd\_iS\_flag!\
11\. Find the flag by using a webshell. -> d2b5b27ae688b6a0f1d21b7d3a0798cd\
12\. Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer. -> 528d6d9cedc2c7aab146ef226e918396\
\
Module: SQLMap Essentials\
1\. What's the fastest SQLi type? -> union query-based\
2\. What's the contents of table flag2? (Case #2) -> HTB{700\_much\_c0n6r475\_0n\_p057\_r3qu357}\
3\. What's the contents of table flag3? (Case #3) -> HTB{c00k13\_m0n573r\_15\_7h1nk1n6\_0f\_6r475}\
4\. What's the contents of table flag4? (Case #4) -> HTB{j450n\_v00rh335\_53nd5\_6r475}\
5\. What's the contents of table flag5? (Case #5) -> HTB{700\_much\_r15k\_bu7\_w0r7h\_17}\
6\. What's the contents of table flag6? (Case #6) -> HTB{v1nc3\_mcm4h0n\_15\_4570n15h3d}\
7\. What's the contents of table flag7? (Case #7) -> HTB{un173\_7h3\_un173d}\
8\. What's the contents of table flag1 in the testdb database? (Case #1) -> HTB{c0n6r475\_y0u\_kn0w\_h0w\_70\_run\_b451c\_5qlm4p\_5c4n}\
9\. What's the name of the column containing "style" in it's name? (Case #1) -> parameter\_style\
10\. What's the Kimberly user's password? (Case #1) -> Enizoom1609\
11\. What's the contents of table flag8? (Case #8) -> HTB{y0u\_h4v3\_b33n\_c5rf\_70k3n1z3d}\
12\. What's the contents of table flag9? (Case #9) -> HTB{700\_much\_r4nd0mn355\_f0r\_my\_74573}\
13\. What's the contents of table flag10? (Case #10) -> HTB{y37\_4n07h3r\_r4nd0m1z3}\
14\. What's the contents of table flag11? (Case #11) -> HTB{5p3c14l\_ch4r5\_n0\_m0r3}\
15\. Try to use SQLMap to read the file "/var/www/html/flag.txt". ->HTB{5up3r\_u53r5\_4r3\_p0w3rful!}\
16\. Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host. -> HTB{n3v3r\_run\_db\_45\_db4}\
17\. What's the contents of table final\_flag? -> HTB{n07\_50\_h4rd\_r16h7?!}\
\
Module: Cross-Site Scripting (XSS)\
1\. To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url. -> HTB{570r3d\_f0r\_3v3ry0n3\_70\_533}\
2\. To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url. -> HTB{r3fl3c73d\_b4ck\_2\_m3}\
3\. To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url. -> HTB{pur3ly\_cl13n7\_51d3}\
4\. Utilize some of the techniques mentioned in this section to identify the vulnerable input parameter found in the above server. What is the name of the vulnerable parameter? -> email\
5\. What type of XSS was found on the above server? "name only" -> reflected\
6\. Try to find a working XSS payload for the Image URL form found at '/phishing' in the above server, and then use what you learned in this section to prepare a malicious URL that injects a malicious login form. Then visit '/phishing/send.php' to send the URL to the victim, and they will log into the malicious login form. If you did everything correctly, you should receive the victim's login credentials, which you can use to login to '/phishing/login.php' and obtain the flag. -> HTB{r3f13c73d\_cr3d5\_84ck\_2\_m3}\
7\. Try to repeat what you learned in this section to identify the vulnerable input field and find a working XSS payload, and then use the 'Session Hijacking' scripts to grab the Admin's cookie and use it in 'login.php' to get the flag. -> HTB{4lw4y5\_53cur3\_y0ur\_c00k135}\
8\. What is the value of the 'flag' cookie? -> HTB{cr055\_5173\_5cr1p71n6\_n1nj4}\
\
Module: File Inclusion\
1\. Using the file inclusion find the name of a user on the system that starts with "b". -> barry\
2\. Submit the contents of the flag.txt file located in the /usr/share/flags directory. -> HTB{n3v3r\_tru$t\_u$3r\_!nput}\
3\. The above web application employs more than one filter to avoid LFI exploitation. Try to bypass these filters to read /flag.txt -> HTB{64$!c\_f!lt3r$\_w0nt\_$t0p\_lf!}\
4\. Fuzz the web application for other php scripts, and then read one of the configuration files and submit the database password as the answer -> HTB{n3v3r\_$t0r3\_pl4!nt3xt\_cr3d$}\
5\. Try to gain RCE using one of the PHP wrappers and read the flag at / -> HTB{d!$46l3\_r3m0t3\_url\_!nclud3}\
6\. Attack the target, gain command execution by exploiting the RFI vulnerability, and then look for the flag under one of the directories in / -> 99a8fc05f033f2fc0cf9a6f9826f83f4\
7\. Use any of the techniques covered in this section to gain RCE and read the flag at / -> HTB{upl04d+lf!+3x3cut3=rc3}\
8\. Use any of the techniques covered in this section to gain RCE, then submit the output of the following command: pwd -> /var/www/html\
9\. Try to use a different technique to gain RCE and read the flag at / -> HTB{1095\_5#0u1d\_n3v3r\_63\_3xp053d}\
10\. Fuzz the web application for exposed parameters, then try to exploit it with one of the LFI wordlists to read /flag.txt -> HTB{4u70m47!0n\_f!nd5\_#!dd3n\_93m5}\
11\. What is the full path to the php.ini file for Apache? -> /etc/php/7.4/apache2/php.ini\
12\. Edit the php.ini file to block system(), then try to execute PHP Code that uses system. Read the /var/log/apache2/error.log file and fill in the blank: system() has been disabled for \_\_\_\_\_\_\_\_ reasons. -> security\
13\. Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer. -> a9a892dbc9faf9a014f58e007721835e\
\
Module: File Upload Attacks\
1\. Try to upload a PHP script that executes the (hostname) command on the back-end server, and submit the first word of it as the answer. -> fileuploadsabsentverification\
2\. Try to exploit the upload feature to upload a web shell and get the content of /flag.txt -> HTB{g07\_my\_f1r57\_w3b\_5h3ll}\
3\. Try to bypass the client-side file type validations in the above exercise, then upload a web shell to read /flag.txt (try both bypass methods for better practice) -> HTB{cl13n7\_51d3\_v4l1d4710n\_w0n7\_570p\_m3}\
4\. Try to find an extension that is not blacklisted and can execute PHP code on the web server, and use it to read "/flag.txt" -> HTB{1\_c4n\_n3v3r\_b3\_bl4ckl1573d}\
5\. The above exercise employs a blacklist and a whitelist test to block unwanted extensions and only allow image extensions. Try to bypass both to upload a PHP script and execute code to read "/flag.txt" -> HTB{1\_wh173l157\_my53lf}\
6\. The above server employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image. Try to combine all of the attacks you learned so far to bypass these filters and upload a PHP file and read the flag at "/flag.txt" -> HTB{m461c4l\_c0n73n7\_3xpl0174710n}\
7\. The above exercise contains an upload functionality that should be secure against arbitrary file uploads. Try to exploit it using one of the attacks shown in this section to read "/flag.txt" -> HTB{my\_1m4635\_4r3\_l37h4l}\
8\. Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes) -> ./images/\
9\. Try to exploit the upload form to read the flag found at the root directory "/". -> HTB{m4573r1ng\_upl04d\_3xpl0174710n}\
\
Module: Command Injections\
1\. Try adding any of the injection operators after the ip in IP field. What did the error message say (in English)? -> Please match the requested format.\
2\. Review the HTML source code of the page to find where the front-end input validation is happening. On which line number is it? -> 17\
3\. Try using the remaining three injection operators (new-line, &, |), and see how each works and how the output differs. Which of them only shows the output of the injected command? -> |\
4\. Try all other injection operators to see if any of them is not blacklisted. Which of (new-line, &, |) is not blacklisted by the web application? -> new-line\
5\. Use what you learned in this section to execute the command 'ls -la'. What is the size of the 'index.php' file? -> 1613\
6\. Use what you learned in this section to find name of the user in the '/home' folder. What user did you find? -> 1nj3c70r\
7\. Use what you learned in this section find the content of flag.txt in the home folder of the user you previously found -> HTB{b451c\_f1l73r5\_w0n7\_570p\_m3}\
8\. Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1 -> /usr/share/mysql/debian\_create\_root\_user.sql\
9\. What is the content of '/flag.txt'? -> HTB{c0mm4nd3r\_1nj3c70r}\
\
Module: Web Attacks\
1\. Try to use what you learned in this section to access the 'reset.php' page and delete all files. Once all files are deleted, you should get the flag. -> HTB{4lw4y5\_c0v3r\_4ll\_v3rb5}\
2\. To get the flag, try to bypass the command injection filter through HTTP Verb Tampering, while using the following filename: file; cp /flag.txt ./ -> HTB{b3\_v3rb\_c0n51573n7}\
3\. Repeat what you learned in this section to get a list of documents of the first 20 user uid's in /documents.php, one of which should have a '.txt' file with the flag. -> HTB{4ll\_f1l35\_4r3\_m1n3}\
4\. Try to download the contracts of the first 20 employee, one of which should contain the flag, which you can read with 'cat'. You can either calculate the 'contract' parameter value, or calculate the '.pdf' file name directly. -> HTB{h45h1n6\_1d5\_w0n7\_570p\_m3}\
5\. Try to read the details of the user with 'uid=5'. What is their 'uuid' value? -> eb4fe264c10eb7a528b047aa983a4829\
6\. Try to change the admin's email to 'flag@idor.htb', and you should get the flag on the 'edit profile' page. -> HTB{1\_4m\_4n\_1d0r\_m4573r}\
7\. Try to read the content of the 'connection.php' file, and submit the value of the 'api\_key' as the answer. -> UTM1NjM0MmRzJ2dmcTIzND0wMXJnZXdmc2RmCg\
8\. Use either method from this section to read the flag at '/flag.php'. (You may use the CDATA method at '/index.php', or the error-based method at '/error'). -> HTB{3rr0r5\_c4n\_l34k\_d474}\
9\. Using Blind Data Exfiltration on the '/blind' page to read the content of '/327a6c4304ad5938eaf0efb6cc3e53dc.php' and get the flag. -> HTB{1\_d0n7\_n33d\_0u7pu7\_70\_3xf1l7r473\_d474}\
10\. Try to escalate your privileges and exploit different vulnerabilities to read the flag at '/flag.php'. -> HTB{m4573r\_w3b\_4774ck3r}

Module: Attacking Common Applications\
1\. Use what you've learned from this section to generate a report with EyeWitness. What is the name of the .db file EyeWitness creates in the inlanefreight\_eyewitness folder? (Format: filename.db) -> ew.db\
2\. What does the header on the title page say when opening the aquatone\_report.html page with a web browser? (Format: 3 words, case sensitive) -> Pages by Similarity\
3\. Enumerate the host and find a flag.txt flag in an accessible directory. -> 0ptions\_ind3xeS\_ftw!\
4\. Perform manual enumeration to discover another installed plugin. Submit the plugin name as the answer (3 words). -> WP sitemap page\
5\. Find the version number of this plugin. (i.e., 4.5.2) -> 1.6.4\
6\. Perform user enumeration against [http://blog.inlanefreight.local](http://blog.inlanefreight.local/). Aside from admin, what is the other user present? -> doug\
7\. Perform a login bruteforcing attack against the discovered user. Submit the user's password as the answer. -> jessica1\
8\. Using the methods shown in this section, find another system user whose login shell is set to /bin/bash. -> webadmin\
9\. Following the steps in this section, obtain code execution on the host and submit the contents of the flag.txt file in the webroot. -> l00k\_ma\_unAuth\_rc3!\
10\. Fingerprint the Joomla version in use on [http://app.inlanefreight.local](http://app.inlanefreight.local/) (Format: x.x.x) -> 3.10.0\
11\. Find the password for the admin user on [http://app.inlanefreight.local](http://app.inlanefreight.local/) -> turnkey\
12\. Leverage the directory traversal vulnerability to find a flag in the web root of the [http://dev.inlanefreight.local/](http://dev.inlanefreight.local/) Joomla application -> j00mla\_c0re\_d1rtrav3rsal!\
13\. Identify the Drupal version number in use on [http://drupal-qa.inlanefreight.local](http://drupal-qa.inlanefreight.local/) -> 7.30\
14\. Work through all of the examples in this section and gain RCE multiple ways via the various Drupal instances on the target host. When you are done, submit the contents of the flag.txt file in the /var/www/drupal.inlanefreight.local directory. -> DrUp@l\_drUp@l\_3veryWh3Re!\
15\. What version of Tomcat is running on the application located at [http://web01.inlanefreight.local:8180](http://web01.inlanefreight.local:8180/)? -> 10.0.10\
16\. What role does the admin user have in the configuration example? -> admin-gui\
17\. Perform a login bruteforcing attack against Tomcat manager at [http://web01.inlanefreight.local:8180](http://web01.inlanefreight.local:8180/). What is the valid username? -> tomcat\
18\. What is the password -> root\
19\. Obtain remote code execution on the [http://web01.inlanefreight.local:8180](http://web01.inlanefreight.local:8180/) Tomcat instance. Find and submit the contents of tomcat\_flag.txt -> t0mcat\_rc3\_ftw!\
20\. Log in to the Jenkins instance at [http://jenkins.inlanefreight.local:8000](http://jenkins.inlanefreight.local:8000/). Browse around and submit the version number when you are ready to move on. -> 2.303.1\
21\. Attack the Jenkins target and gain remote code execution. Submit the contents of the flag.txt file in the /var/lib/jenkins3 directory -> f33ling\_gr00000vy!\
22\. Enumerate the Splunk instance as an unauthenticated user. Submit the version number to move on (format 1.2.3). -> 8.2.2\
23\. Attack the Splunk target and gain remote code execution. Submit the contents of the flag.txt file in the c:\loot directory. -> l00k\_ma\_no\_AutH!\
24\. What version of PRTG is running on the target? -> 18.1.37.13946\
25\. Attack the PRTG target and gain remote code execution. Submit the contents of the flag.txt file on the administrator Desktop. -> WhOs3\_m0nit0ring\_wH0?\
26\. Find your way into the osTicket instance and submit the password sent from the Customer Support Agent to the customer Charles Smithson. -> Inlane\_welcome!\
27\. Enumerate the GitLab instance at [http://gitlab.inlanefreight.local](http://gitlab.inlanefreight.local/). What is the version number? -> 13.10.2\
28\. Find the PostgreSQL database password in the example project. -> postgres\
29\. Find another valid user on the target GitLab instance. -> DEMO\
30\. Gain remote code execution on the GitLab instance. Submit the flag in the directory you land in. -> s3cure\_y0ur\_Rep0s!\
31\. After running the URL Encoded 'whoami' payload, what user is tomcat running as? -> feldspar\omen\
32\. Enumerate the host, exploit the Shellshock vulnerability, and submit the contents of the flag.txt file located on the server -> Sh3ll\_Sh0cK\_123\
33\. Perform an analysis of C:\Apps\Restart-OracleService.exe and identify the credentials hidden within its source code. Submit the answer using the format username:password. -> svc\_oracle:#oracle\_s3rV1c3!2010\
34\. What is the IP address of the eth0 interface under the ServerStatus -> Ipconfig tab in the fatty-client application? -> 172.28.0.3\
35\. What ColdFusion protocol runs on port 5500? -> server monitor\
36\. What user is ColdFusion running as? -> arctic\tolis\
37\. What is the full .aspx filename that Gobuster identified? -> transfer.aspx\
38\. After bypassing the login, what is the website "Powered by"? -> w3.css\
39\. We placed the source code of the application we just covered at /opt/asset-manager/app.py inside this exercise's target, but we changed the crucial parameter's name. SSH into the target, view the source code and enter the parameter name that needs to be manipulated to log in to the Asset Manager web application. -> active\
40\. What credentials were found for the local database instance while debugging the octopus\_checker binary? -> SA:N0tS3cr3t!\
41\. Enumerate the target host and identify the running application. What application is running? -> weblogic\
42\. Enumerate the application for vulnerabilities. Gain remote code execution and submit the contents of the flag.txt file on the administrator desktop. -> w3b\_l0gic\_RCE!\
43\. What vulnerable application is running? -> tomcat\
44\. What port is this application running on? -> 8080\
45\. What version of the application is in use? -> 9.0.0.M1\
46\. Exploit the application to obtain a shell and submit the contents of the flag.txt file on the Administrator desktop. -> f55763d31a8f63ec935abd07aee5d3d0\
47\. What is the URL of the WordPress instance? -> [http://blog.inlanefreight.local](http://blog.inlanefreight.local/)\
48\. What is the name of the public GitLab project? -> virtualhost\
49\. What is the FQDN of the third vhost? -> monitoring.inlanefreight.local\
50\. What application is running on this third vhost? (One word) -> nagios\
51\. What is the admin password to access this application? -> oilaKglm7M09@CPL&^lC\
52\. Obtain reverse shell access on the target and submit the contents of the flag.txt file. -> afe377683dce373ec2bf7eaf1e0107eb\
53\. What is the hardcoded password for the database connection in the MultimasterAPI.dll file? -> D3veL0pM3nT!\
\
Module: Linux Privilege Escalation\
1\. Enumerate the Linux environment and look for interesting files that might contain sensitive data. Submit the flag as the answer -> HTB{1nt3rn4l\_5cr1p7\_l34k}\
2\. What is the latest Python version that is installed on the target? -> 3.11\
3\. Find the WordPress database password. -> W0rdpr3ss\_sekur1ty!\
4\. Review the PATH of the htb-student user. What non-default directory is part of the user's PATH? -> /tmp\
5\. Use different approaches to escape the restricted shell and read the flag.txt file. Submit the contents as the answer. -> HTB{35c4p3\_7h3\_r3stricted\_5h311}\
6\. Find a file with the setuid bit set that was not shown in the section command output (full path to the binary). -> /bin/sed\
7\. Find a file with the setgid bit set that was not shown in the section command output (full path to the binary). -> /usr/bin/facter\
8\. What command can the htb-student user run as root? -> /usr/bin/openssl\
9\. Use the privileged group rights of the secaudit user to locate a flag. -> ch3ck\_th0se\_gr0uP\_m3mb3erSh1Ps!\
10\. Escalate the privileges using capabilities and read the flag.txt file in the "/root" directory. Submit its contents as the answer. -> HTB{c4paBili7i3s\_pR1v35c}\
11\. Connect to the target system and escalate privileges using the Screen exploit. Submit the contents of the flag.txt file in the /root/screen\_exploit directory. -> 91927dad55ffd22825660da88f2f92e0\
12\. Connect to the target system and escalate privileges by abusing the misconfigured cron job. Submit the contents of the flag.txt file in the /root/cron\_abuse directory. -> 14347a2c977eb84508d3d50691a7ac4b\
13\. Escalate the privileges and submit the contents of flag.txt as the answer. -> HTB{C0nT41n3rs\_uhhh}\
14\. Escalate the privileges on the target and obtain the flag.txt in the root directory. Submit the contents as the answer. -> HTB{D0ck3r\_Pr1vE5c}\
15\. Escalate the privileges and submit the contents of flag.txt as the answer. -> HTB{l0G\_r0t7t73N\_00ps}\
16\. Review the NFS server's export list and find a directory holding a flag. -> fc8c065b9384beaa162afe436a694acf\
17\. Escalate privileges using a different Kernel exploit. Submit the contents of the flag.txt file in the /root/kernel\_exploit directory. -> 46237b8aa523bc7e0365de09c0c0164f\
18\. Escalate privileges using LD\_PRELOAD technique. Submit the contents of the flag.txt file in the /root/ld\_preload directory. -> 6a9c151a599135618b8f09adc78ab5f1\
19\. Follow the examples in this section to escalate privileges, recreate all examples (don't just run the payroll binary). Practice using ldd and readelf. Submit the version of glibc (i.e. 2.30) in use to move on to the next section. -> 2.23\
20\. Follow along with the examples in this section to escalate privileges. Try to practice hijacking python libraries through the various methods discussed. Submit the contents of flag.txt under the root user as the answer. -> HTB{3xpl0i7iNG\_Py7h0n\_lI8R4ry\_HIjiNX}\
21\. Escalate the privileges and submit the contents of flag.txt as the answer. -> HTB{SuD0\_e5c4l47i0n\_1id}\
22\. Escalate the privileges and submit the contents of flag.txt as the answer. -> HTB{p0Lk1tt3n}\
23\. Escalate the privileges and submit the contents of flag.txt as the answer. -> HTB{D1rTy\_DiR7Y}\
24\. Submit the contents of flag1.txt -> LLPE{d0n\_ov3rl00k\_h1dden\_f1les!}\
25\. Submit the contents of flag2.txt -> LLPE{ch3ck\_th0se\_cmd\_l1nes!}\
26\. Submit the contents of flag3.txt -> LLPE{h3y\_l00k\_a\_fl@g!}\
27\. Submit the contents of flag4.txt -> LLPE{im\_th3\_m@nag3r\_n0w}\
28\. Submit the contents of flag5.txt -> LLPE{0ne\_sudo3r\_t0\_ru13\_th3m\_@ll!}\
\
Module: Windows Privilege Escalation\
1\. What is the IP address of the other NIC attached to the target host? -> 172.16.20.45\
2\. What executable other than cmd.exe is blocked by AppLocker? -> powershell\_ise.exe\
3\. What non-default privilege does the htb-student user have? -> SeTakeOwnershipPrivilege\
4\. Who is a member of the Backup Operators group? -> sarah\
5\. What service is listening on port 8080 (service name not the executable)? -> Tomcat8\
6\. What user is logged in to the target host? -> sccm\_svc\
7\. What type of session does this user have? -> console\
8\. What service is listening on 0.0.0.0:21? (two words) -> filezilla server\
9\. Which account has WRITE\_DAC privileges over the \pipe\SQLLocal\SQLEXPRESS01 named pipe? -> NT SERVICE\MSSQL$SQLEXPRESS01\
10\. Escalate privileges using one of the methods shown in this section. Submit the contents of the flag file located at c:\Users\Administrator\Desktop\SeImpersonate\flag.txt -> F3ar\_th3\_p0tato!\
11\. Leverage SeDebugPrivilege rights and obtain the NTLM password hash for the sccm\_svc account. -> 64f12cddaa88057e06a81b54e73b949b\
12\. Leverage SeTakeOwnershipPrivilege rights over the file located at "C:\TakeOwn\flag.txt" and submit the contents. -> 1m\_th3\_f1l3\_0wn3r\_n0W!\
13\. Leverage SeBackupPrivilege rights and obtain the flag located at c:\Users\Administrator\Desktop\SeBackupPrivilege\flag.txt -> Car3ful\_w1th\_gr0up\_m3mberSh1p!\
14\. Using the methods demonstrated in this section find the password for the user mary. -> W1ntergreen\_gum\_2021!\
15\. Leverage membership in the DnsAdmins group to escalate privileges. Submit the contents of the flag located at c:\Users\Administrator\Desktop\DnsAdmins\flag.txt -> Dll\_abus3\_ftw!\
16\. Follow the steps in this section to escalate privileges to SYSTEM, and submit the contents of the flag.txt file on administrator's Desktop. Necessary tools for both methods can be found in the C:\Tools directory, or you can practice compiling and uploading them on your own. -> Pr1nt\_0p3rat0rs\_ftw!\
17\. Escalate privileges using the methods shown in this section and submit the contents of the flag located at c:\Users\Administrator\Desktop\ServerOperators\flag.txt -> S3rver\_0perators\_@ll\_p0werfull!\
18\. Follow the steps in this section to obtain a reverse shell connection with normal user privileges and another which bypasses UAC. Submit the contents of flag.txt on the sarah user's Desktop when finished. -> I\_bypass3d\_Uac!\
19\. Escalate privileges on the target host using the techniques demonstrated in this section. Submit the contents of the flag in the WeakPerms folder on the Administrator Desktop. -> Aud1t\_th0se\_s3rv1ce\_p3rms!\
20\. Try out the 3 examples in this section to escalate privileges to NT AUTHORITY\SYSTEM on the target host. Submit the contents of the flag on the Administrator Desktop. -> D0nt\_fall\_b3h1nd\_0n\_Patch1ng!\
21\. Work through the steps above to escalate privileges on the target system using the Druva inSync flaw. Submit the contents of the flag in the VulServices folder on the Administrator Desktop. -> Aud1t\_th0se\_th1rd\_paRty\_s3rvices!\
22\. Search the file system for a file containing a password. Submit the password as your answer. -> Pr0xyadm1nPassw0rd!\
23\. Connect as the bob user and practice decrypting the credentials in the pass.xml file. Submit the contents of the flag.txt on the desktop once you are done. -> 3ncryt10n\_w0nt\_4llw@ys\_s@v3\_y0u\
24\. Using the techniques shown in this section, find the cleartext password for the bob\_adm user on the target system. -> 1qazXSW@3edc!\
25\. Using the techniques covered in this section, retrieve the sa password for the SQL01.inlanefreight.local user account. -> S3cret\_db\_p@ssw0rd!\
26\. Which user has credentials stored for RDP access to the WEB01 host? -> amanda\
27\. Find and submit the password for the root user to access [https://vc01.inlanefreight.local/ui/login](https://vc01.inlanefreight.local/ui/login) -> ILVCadm1n1qazZAQ!\
28\. Enumerate the host and find the password for [ftp.ilfreight.local](http://ftp.ilfreight.local/) -> Ftpuser!\
29\. Submit the user flag from C:\Users\pmorgan\Downloads -> CitR1X\_Us3R\_Esc@p3\
30\. Submit the Administrator's flag from C:\Users\Administrator\Desktop -> C1tr!x\_3sC@p3\_@dm!n\
31\. Using the techniques in this section obtain the cleartext credentials for the SCCM\_SVC user. -> Password1\
32\. Access the target machine using Peter's credentials and check which applications are installed. What's the application installed used to manage and connect to remote systems? -> mRemoteNG\
33\. Find the configuration file for the application you identify and attempt to obtain the credentials for the user Grace. What is the password for the local account, Grace? -> Princess01!\
34\. Log in as Grace and find the cookies for the slacktestapp.com website. Use the cookie to log in into slacktestapp.com from a browser within the RDP session and submit the flag. -> HTB{Stealing\_Cookies\_To\_AccessWebSites}\
35\. Log in as Jeff via RDP and find the password for the restic backups. Submit the password as the answer. -> Superbackup!\
36\. Restore the directory containing the files needed to obtain the password hashes for local users. Submit the Administrator hash as the answer. -> bac9dc5b7b4bec1d83e0e9c04b477f26\
37\. Using the techniques in this section, find the cleartext password for an account on the target host. -> !QAZXSW@3edc\
38\. Obtain a shell on the target host, enumerate the system and escalate privileges. Submit the contents of the flag.txt file on the Administrator Desktop. -> L3gacy\_st1ill\_pr3valent!\
39\. Enumerate the target host and escalate privileges to SYSTEM. Submit the contents of the flag on the Administrator Desktop. -> Cm0n\_l3ts\_upgRade\_t0\_win10!\
40\. Which two KBs are installed on the target system? (Answer format: 3210000&3210060) -> 3199986&3200970\
41\. Find the password for the ldapadmin account somewhere on the system. -> car3ful\_st0rinG\_cr3d$\
42\. Escalate privileges and submit the contents of the flag.txt file on the Administrator Desktop. -> Ev3ry\_sysadm1ns\_n1ghtMare!\
43\. After escalating privileges, locate a file named confidential.txt. Submit the contents of this file. -> 5e5a7dafa79d923de3340e146318c31a\
44\. Find left behind cleartext credentials for the iamtheadministrator domain admin account. -> Inl@n3fr3ight\_sup3rAdm1n!\
45\. Escalate privileges to SYSTEM and submit the contents of the flag.txt file on the Administrator Desktop -> el3vatEd\_1nstall$\_v3ry\_r1sky\
46\. There is 1 disabled local admin user on this system with a weak password that may be used to access other systems in the network and is worth reporting to the client. After escalating privileges retrieve the NTLM hash for this user and crack it offline. Submit the cleartext password for this account. -> password1\
\
Module: Documenting and Reporting\
1\. Inlanefreight has contracted Elizabeth's firm to complete a type of assessment that is mostly automated where no exploitation is attempted. What kind of assessment is she going to be contracted for? -> Vulnerability Assessment\
2\. Nicolas is performing an external & internal penetration test for Inlanefreight. The client has only provided the company's name and a network connection onsite at their office and no additional detail. From what perspective is he performing the penetration test? -> Black Box\
3\. What component of a report should be written in a simple to understand and non-technical manner? -> Executive Summary\
4\. It is a good practice to name and recommend specific vendors in the component of the report mentioned in the last question. True or False? -> FALSE\
5\. "An attacker can own your whole entire network cause your DC is way out of date. You should really fix that!". Is this a Good or Bad remediation recommendation? (Answer Format: Good or Bad) -> bad\
6\. Connect to the testing VM using Xfreerdp and practice testing, documentation, and reporting against the target lab. Once the target spawns, browse to the WriteHat instance on port 443 and authenticate with the provided admin credentials. Play around with the tool and practice adding findings to the database to get a feel for the reporting tools available to us. Remember that all data will be lost once the target resets, so save any practice findings locally! Next, complete the in-progress penetration test. Once you achieve Domain Admin level access, submit the contents of the flag.txt file on the Administrator Desktop on the DC01 host. -> d0c\_pwN\_r3p0rt\_reP3at!\
7\. After achieving Domain Admin, submit the NTLM hash of the KRBTGT account. -> 16e26ba33e455a8c338142af8d89ffbc\
8\. Dump the NTDS file and perform offline password cracking. Submit the password of the svc\_reporting user as your answer. -> Reporter1!\
9\. What powerful local group does this user belong to? -> backup operators\
\
Module: Attacking Enterprise Networks\
1\. Perform a banner grab of the services listening on the target host and find a non-standard service banner. Submit the name as your answer (format: word\_word\_word) -> 1337\_HTB\_DNS\
2\. Perform a DNS Zone Transfer against the target and find a flag. Submit the flag value as your answer (flag format: HTB{ }). -> HTB{DNs\_ZOn3\_Tr@nsf3r}\
3\. What is the FQDN of the associated subdomain? -> flag.inlanefreight.local\
4\. Perform vhost discovery. What additional vhost exists? (one word) -> monitoring\
6\. Enumerate the accessible services and find a flag. Submit the flag value as your answer (flag format: HTB{ }). -> HTB{0eb0ab788df18c3115ac43b1c06ae6c4}\
7\. Use the IDOR vulnerability to find a flag. Submit the flag value as your answer (flag format: HTB{}). -> HTB{8f40ecf17f681612246fa5728c159e46}\
8\. Exploit the HTTP verb tampering vulnerability to find a flag. Submit the flag value as your answer (flag format: HTB{}). -> HTB{57c7f6d939eeda90aa1488b15617b9fa}\
9\. Exploit the WordPress instance and find a flag in the web root. Submit the flag value as your answer (flag format: HTB{}). -> HTB{e7134abea7438e937b87608eab0d979c}\
10\. Enumerate the "status" database and retrieve the password for the "Flag" user. Submit the value as your answer. -> 1fbea4df249ac4f4881a5da387eb297cf\
11\. Steal an admin's session cookie and gain access to the support ticketing queue. Submit the flag value for the "John" user as your answer. -> HTB{1nS3cuR3\_c00k135}\
12\. Use the SSRF to Local File Read vulnerability to find a flag. Submit the flag value as your answer (flag format: HTB{}). -> HTB{49f0bad299687c62334182178bfd75d8}\
13\. Register an account and log in to the Gitlab instance. Submit the flag value (flag format : HTB{}). -> HTB{32596e8376077c3ef8d5cf52f15279ba}\
14\. Use the XXE vulnerability to find a flag. Submit the flag value as your answer (flag format: HTB{}). -> HTB{dbca4dc5d99cdb3311404ea74921553c}\
15\. Use the command injection vulnerability to find a flag in the web root. Submit the flag value as your answer (flag format: HTB{}) -> HTB{bdd8a93aff53fd63a0a14de4eba4cbc1}\
16\. Submit the contents of the flag.txt file in the /home/srvadm directory. -> b447c27a00e3a348881b0030177000cd\
17\. Escalate privileges on the target host and submit the contents of the flag.txt file in the /root directory. -> a34985b5976072c3c148abc751671302\
18\. Mount an NFS share and find a flag.txt file. Submit the contents as your answer. -> bf22a1d0acfca4af517e1417a80e92d1\
19\. Retrieve the contents of the SAM database on the DEV01 host. Submit the NT hash of the administrator user as your answer. -> 0e20798f695ab0d04bc138b22344cea8\
20\. Escalate privileges on the DEV01 host. Submit the contents of the flag.txt file on the Administrator Desktop. -> K33p\_0n\_sp00fing!\
21\. Find a backup script that contains the password for the backupadm user. Submit this user's password as your answer. -> !qazXSW@\
22\. Perform a Kerberoasting attack and retrieve TGS tickets for all accounts set as SPNs. Crack the TGS of the backupjob user and submit the cleartext password as your answer. -> lucky7\
23\. Escalate privileges on the MS01 host and submit the contents of the flag.txt file on the Administrator Desktop. -> 33a9d46de4015e7b3b0ad592a9394720\
24\. Obtain the NTLMv2 password hash for the mpalledorous user and crack it to reveal the cleartext value. Submit the user's password as your answer. -> 1squints2\
25\. Set a fake SPN on the ttimmons user. Kerberoast this user and crack the TGS ticket offline to reveal their cleartext password. Submit this password as your answer. -> Repeat09\
26\. After obtaining Domain Admin rights, authenticate to the domain controller and submit the contents of the flag.txt file on the Administrator Desktop. -> 7c09eb1fff981654a3bb3b4a4e0d176a\
27\. Compromise the INLANEFREIGHT.LOCAL domain and dump the NTDS database. Submit the NT hash of the Administrator account as your answer. -> fd1f7e5564060258ea787ddbb6e6afa2\
28\. Gain access to the MGMT01 host and submit the contents of the flag.txt file in a user's home directory. -> 3c4996521690cc76446894da2bf7dd8f\
29\. Escalate privileges to root on the MGMT01 host. Submit the contents of the flag.txt file in the /root directory. -> 206c03861986c0e264438cb6e8e90a19
