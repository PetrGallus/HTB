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



### Union Injection

## Exploitation

### DB Enumeration

### Reading Files

### Writing Files&#x20;

## Mitigations&#x20;

## Closing it Out

### Skills Assessment - SQL Injection Fundamentals
