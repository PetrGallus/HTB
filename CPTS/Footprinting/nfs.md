# NFS

same purpose as SMB, but different protocol - is used between Linux and Unix sys

cant communicate directly w SMB servers

NFSv4 - user auth (includes Kerberos, supports ACLs)

based on ONC-RPC/SUN-RPC ... TCP and UDP ports 111 -> NFS doesnt have auth mechanism, thats why RPC protocol (Remote Procedure Call)

has less options than FPT/SMB ... easier to configure



## Work w NFS

table of physical filesystens on NFS server in /etc/exports&#x20;

cat /etc/exports



show available NFS Shares

showmount -e \<IP>



mount NFS Share

mkdir target-NFS

sudo mount -t nfs \<IP>:/ ./target-NFS/ -o nolock

cd target-NFS

tree .

sudo umount ./target-NFS



List Contents w UN\&Group names ; UIDs\&GUIDs

ls -l mnt/nfs/

ls -n mnt/nfs/





## Enumeration

sudo nmap 10.129.172.42 -p111,2049 -sVC

sudo nmap --script nfs\* 10.129.172.42 -p111,2049 -sV

sudo showmount -e 10.129.172.42

sudo mount -t nfs 10.129.172.42:/ ./target-NFS/ -o nolock

cd target-NFS

tree .

cat mnt/nfsshare/flag.txt

cat var/nfs/flag.txt

