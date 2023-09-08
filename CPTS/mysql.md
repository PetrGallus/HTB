# MySQL

relational database SQL management system by Oracle

client-server

single file with .sql extension

MariaDB is a fork of original MySQL code (developer left company and created his own)



Database

ideal usage for dynamic websites ... high response speed

combined w Linux OS, PHP and Apache or Nginx web server (LAMP) (LEMP)

PW can be stored in plain-text, but generally encrypted via PHP scripts by one-way-encryption





## Default config

sudo apt install mysql-server -y

cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s\*$/d'





## Dangerous Settings

user

password

admin\_address

debig

sql\_warnings

secure\_file\_priv



## ENUMERATION

Enumerate MySQL server and obtain version in use

**sudo nmap \<IP> -sVC -p3306 --script mysql\***

**mysql -u \<UN> -p\<PW> -h \<IP>**

**select version();**



with obtained credentials (robin:robin) - what is the email address of the customer "Otto Lang"?

**mysql -u \<UN> -p\<PW> -h \<IP>**

**show databases;**

**use customers;**

**show tables;**

**select \* from myTable where name = "Otto Lang";**
