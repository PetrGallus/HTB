# MSSQL

Microsoft SQL - closed source code, for running on Windows OS

popular with .NET framework cause of its strong native support for .NET&#x20;



MSSQL Clients

SQL Server Management Studio (SSMS)

SQLPro

mssql-cli

SQL Server PowerShell

HeidiSQL



## Dangerous settings

* MSSQL clients dont use encryption to connect to the MSSQL server
* self-signed certs for encryption ... we can spoof self-signed certs
* use of named pipes
* weak or default sa credentians



## Enumeration

enumerate the target - list the HOSTNAME of MSSQL server

**msfconsole**

**use auxiliary/scanner/mssql/mssql\_ping**

**set rhosts \<IP>**

**run**



Connect to MSSQL instance w onbtained account backdoor:Password1 -> list the non-default database present on the server

**python3 examples/mssqlclient.py backdoor@10.129.74.93 -windows-auth**

**select name from sys.databases**

