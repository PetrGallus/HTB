# SNMP

Simple Network Management Protocol

to monitor network devices and handle config tasks + change settings remotely

routers, switches, servers, IoT

SNMPv3

\-p 161 over UDP + traps (packets without being requested) on -p 162



MIB (Management Information base) for storing device info

text file written in ASN.1 based ASCII text format



OID (Onject Identifier Registry)

node in a hierarchical namespace for MIB



SNMPv1 -> no auth, no encryption

SNMPv2 -> auth, but no encryption

SNMPv3 -> auth + encryption (via pre-shared key)





## Dafault config

SNMP Daemon cfg

cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s\*$/d'





## Dangerous settings

rwuser noauth

rwcommunity \<community string> \<IPv4 address>

rwcommunity6 \<community string> \<IPv6 address>





## ENUMERATION

Enumerate SNMP service and obtain admin email address

**snmpwalk -v2c -c public 10.129.251.166**

onesixtyone -c /usr/share/SecLists/Discovery/SNMP/snmp.txt 10.129.251.166



customized version of SNMP server

**snmpwalk -v2c -c public 10.129.251.166**



find custom script running on the system as a flag

**snmpwalk -v2c -c public 10.129.251.166 | grep "HTB"**
