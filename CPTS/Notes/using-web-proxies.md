# Using Web Proxies

## Web proxy

### Intercepting Web Requests

**Try intercepting the ping request on the server shown above, and change the post data similarly to what we did in this section. Change the command to read 'flag.txt'**

* modify ip=1 -> ip=;ls;

<figure><img src=".gitbook/assets/image (212).png" alt=""><figcaption></figcaption></figure>

* modify ip=1 -> ip=;cat flag.txt;

<figure><img src=".gitbook/assets/image (213).png" alt=""><figcaption></figcaption></figure>

### Intercepting Responses

* we can enable interception by going to (Proxy>Options) and enabling Intercept Response under Intercept Server Responses

<figure><img src=".gitbook/assets/image (215).png" alt=""><figcaption></figcaption></figure>

### Repeating requests

**Try using request repeating to be able to quickly test commands. With that, try looking for the other flag.**

<figure><img src=".gitbook/assets/image (216).png" alt=""><figcaption></figcaption></figure>

* ;ls /;
* ;cat /flag.txt;

<figure><img src=".gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

### Encoding/Decoding

ENCODING

```
Spaces: May indicate the end of request data if not encoded
&: Otherwise interpreted as a parameter delimiter
#: Otherwise interpreted as a fragment identifier
```

* To URL-encode text in Burp Repeater, we can select that text and right-click on it, then select (Convert Selection>URL>URL encode key characters), or by selecting the text and clicking \[CTRL+U].&#x20;
* Burp also supports URL-encoding as we type if we right-click and enable that option, which will encode all of our text as we type it. On the other hand, ZAP should automatically URL-encode all of our request data in the background before sending the request, though we may not see that explicitly.
* There are other types of URL-encoding, like Full URL-Encoding or Unicode URL encoding, which may also be helpful for requests with many special characters.

DECODING

* While URL-encoding is key to HTTP requests, it is not the only type of encoding we will encounter.&#x20;
  *   It is very common for web applications to encode their data, so we should be able to quickly decode that data to examine the original text.&#x20;


  * On the other hand, back-end servers may expect data to be encoded in a particular format or with a specific encoder, so we need to be able to quickly encode our data before we send it.

The following are some of the other types of encoders supported by both tools:

```
HTML
Unicode
Base64
ASCII hex
```

* To access the full encoder in Burp, we can go to the Decoder tab.&#x20;

**The string found in the attached file has been encoded several times with various encoders. Try to use the decoding tools we discussed to decode it and get the flag.**

* Given string:
  * `VTJ4U1VrNUZjRlZXVkVKTFZrWkdOVk5zVW10aFZYQlZWRmh3UzFaR2NITlRiRkphWld0d1ZWUllaRXRXUm10M1UyeFNUbVZGY0ZWWGJYaExWa1V3ZVZOc1VsZGlWWEJWVjIxNFMxWkZNVFJUYkZKaFlrVndWVmR0YUV0V1JUQjNVMnhTYTJGM1BUMD0=`
* Decode: 4x Base64 + 1x URL

<figure><img src=".gitbook/assets/image (218).png" alt=""><figcaption></figcaption></figure>

### Proxy Tools

* Proxychains
  * routes all traffic coming from any command-line tool to any proxy we specify
  * USAGE: edit /etc/proxychains.conf
    *

        <figure><img src=".gitbook/assets/image (219).png" alt=""><figcaption></figcaption></figure>


    *

        <figure><img src=".gitbook/assets/image (220).png" alt=""><figcaption></figcaption></figure>


* Nmap
  *

      <figure><img src=".gitbook/assets/image (221).png" alt=""><figcaption></figcaption></figure>


* Metasploit
  *

      <figure><img src=".gitbook/assets/image (222).png" alt=""><figcaption></figcaption></figure>



**Try running 'auxiliary/scanner/http/http\_put' in Metasploit on any website, while routing the traffic through Burp. Once you view the requests sent, what is the last line in the request?**

**msfconsole**

msf6 >**search http\_put**

msf6 >**use 0**

msf6 >**set RHOSTS 206.189.117.48**

msf6 >**set RPORT 30301**

msf6 >**set PROXIES HTTP:127.0.0.1:8080**

msf6 >**run**

<figure><img src=".gitbook/assets/image (223).png" alt=""><figcaption></figcaption></figure>

## Web Fuzzer

### Burp Intruder

**Use Burp Intruder to fuzz for '.html' files under the /admin directory, to find a file containing the flag.**

* we can do it in repeater, no intruder needed...
*   `GET`` `<mark style="color:purple;">**`/admin/2010.html`**</mark>` ``HTTP/1.1`

    `Host: 94.237.62.52:50469`

    `Cache-Control: max-age=0`

    `Upgrade-Insecure-Requests: 1`

    `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36`

    `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,`_`/`_`;q=0.8,application/signed-exchange;v=b3;q=0.7`

    `Accept-Encoding: gzip, deflate`

    `Accept-Language: en-US,en;q=0.9`

    `If-None-Match: "3db-5b1a1804e0100-gzip"`

    `If-Modified-Since: Wed, 14 Oct 2020 13:28:04 GMT`

    `Connection: close`

<figure><img src=".gitbook/assets/image (224).png" alt=""><figcaption></figcaption></figure>

### ZAP Fuzzer

**The directory we found above sets the cookie to the md5 hash of the username, as we can see the md5 cookie in the request for the (guest) user. Visit '/skills/' to get a request with a cookie, then try to use ZAP Fuzzer to fuzz the cookie for different md5 hashed usernames to get the flag. Use the "top-usernames-shortlist.txt" wordlist from Seclists.**

<figure><img src=".gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

* Intercept we requests

<figure><img src=".gitbook/assets/image (227).png" alt=""><figcaption></figcaption></figure>

* Fuzzer request:
  * Right mouse click on cookie request -> Fuzz

<figure><img src=".gitbook/assets/image (228).png" alt=""><figcaption></figcaption></figure>

* Set wordlist:top-usernames-shortlist.txt

<figure><img src=".gitbook/assets/image (229).png" alt=""><figcaption></figcaption></figure>

* Set Processors: Hash MD5

<figure><img src=".gitbook/assets/image (230).png" alt=""><figcaption></figcaption></figure>

* Start fuzzing
  * cookie=ee11cbb19052e40b07aac0ca060c23ee = user
  * Try to use hash as cookie

<figure><img src=".gitbook/assets/image (231).png" alt=""><figcaption></figcaption></figure>

## Web Scanner

### ZAP Scanner

**Run ZAP Scanner on the target above to identify directories and potential vulnerabilities. Once you find the high-level vulnerability, try to use it to read the flag at '/flag.txt'**

<figure><img src=".gitbook/assets/image (232).png" alt=""><figcaption></figcaption></figure>

* RCE
  * [http://139.59.191.154:32538/devtools/ping.php?ip=127.0.0.1%26cat+%2Fetc%2Fpasswd%26    ](http://139.59.191.154:32538/devtools/ping.php?ip=127.0.0.1%26cat+%2Fetc%2Fpasswd%26http://139.59.191.154:32538/devtools/ping.php?ip=127.0.0.1%26cat+%2Fflag.txt%26)
  * [http://139.59.191.154:32538/devtools/ping.php?ip=127.0.0.1%26cat+%2Fflag.txt%26](http://139.59.191.154:32538/devtools/ping.php?ip=127.0.0.1%26cat+%2Fetc%2Fpasswd%26http://139.59.191.154:32538/devtools/ping.php?ip=127.0.0.1%26cat+%2Fflag.txt%26)

<figure><img src=".gitbook/assets/image (233).png" alt=""><figcaption></figcaption></figure>

## Skills Assessment - Using Web Proxies

**The /lucky.php page has a button that appears to be disabled. Try to enable the button, and then click it to get the flag.**

<figure><img src=".gitbook/assets/image (234).png" alt=""><figcaption></figcaption></figure>

**We dont need Burp/ZAp....only browser**

* F12 -> Inspector -> Button DISABLED -> remove word "disabled" to be able to click on button
  * afterwards CLICK the button
    * Flag appears...

<figure><img src=".gitbook/assets/image (236).png" alt=""><figcaption></figcaption></figure>

**The /admin.php page uses a cookie that has been encoded multiple times. Try to decode the cookie until you get a value with 31-characters. Submit the value as the answer.**

<figure><img src=".gitbook/assets/image (237).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (238).png" alt=""><figcaption></figcaption></figure>

**Once you decode the cookie, you will notice that it is only 31 characters long, which appears to be an md5 hash missing its last character. So, try to fuzz the last character of the decoded md5 cookie with all alpha-numeric characters, while encoding each request with the encoding methods you identified above. (You may use the "alphanum-case.txt" wordlist from Seclist for the payload)**

<figure><img src=".gitbook/assets/image (239).png" alt=""><figcaption></figcaption></figure>

* edit in intruder -> set cookie to the decoded one from previous question
  * add § marks at the begginning and ending...
  * Payloads - list:
    * /usr/share/seclists/Fuzzing/alphanum-case.txt
  * Payloads - processing:
    * Add Prefix: 3dac93b8cd250aa8c1a36fffc79a17a
    * Base64-encode
    * Encode as ASCII Hex

<figure><img src=".gitbook/assets/image (241).png" alt=""><figcaption></figcaption></figure>

* START ATTACK
  * 59

<figure><img src=".gitbook/assets/image (242).png" alt=""><figcaption></figcaption></figure>

**You are using the auxiliary/scanner/http/coldfusion\_locale\_traversal' tool within Metasploit, but it is not working properly for you. You decide to capture the request sent by Metasploit so you can manually verify it and repeat it. Once you capture the request, what is the 'XXXXX' directory being called in '/XXXXX/administrator/..'?**

* start metasploit
  * search for coldfusion\_locate\_traversal
  * select it
  * activate the payload
  * check options...
  * BURP shows the dir CFIDE/administrator...

<figure><img src=".gitbook/assets/image (243).png" alt=""><figcaption></figcaption></figure>

