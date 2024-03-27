---
title: ransoware逆向分析
date: 2024-03-27
categories: [ctf, re，nese]
tags: [openssl,bindiff]     # TAG names should always be lowercase
---

# 0x01 Write in front 
该题为nese 3月升级赛逆向题。
欣哥发我让我做一做，那我就做一下，没想到一做做了半个月（欣哥吐槽说半个月都够他挖个洞了orz），不过还是解出了这道题，特此记录一下


# 0x02 CRC32 against debug
![picture 0](/images/101c2883ff14c3e7e09e7d8aa54e1e513658ea2a19ae72740c3b5928e708b54e.png)  
这里_DAT_0079ac6c是经过crc32整个.text段，所以直接下断点，会影响crc32真正的值（软件断点会在断点位置置换为int3（x86下））  
这里有两种办法得到_DAT_0079ac6c的值
1. 直接还原crc32算法 用ida python或者ghidra python 算出来（我用的这个）
2. 直接把断点下在库上（不是.text段上就行）或者直接不断，本题的特殊性子进程会自己raise(0x13),所以直接gdb 跟子进程 直接读（简单 高效）

具体的crc32算法原理可以见我上一篇文章。
这里贴出我算crc32的代码：
```python
from IPython import embed
DAT_0079ac68 = 0xedb88320
arr = [0] * 256
# gen crc32 table
for uVar2 in range(256):
    uVar4 = -(uVar2 & 1) & DAT_0079ac68 ^ (uVar2 >> 1)
    uVar4 = -(uVar4 & 1) & DAT_0079ac68 ^ (uVar4 >> 1)
    uVar4 = -(uVar4 & 1) & DAT_0079ac68 ^ (uVar4 >> 1)
    uVar4 = -(uVar4 & 1) & DAT_0079ac68 ^ (uVar4 >> 1)
    uVar4 = -(uVar4 & 1) & DAT_0079ac68 ^ (uVar4 >> 1)
    uVar4 = -(uVar4 & 1) & DAT_0079ac68 ^ (uVar4 >> 1)
    uVar4 = -(uVar4 & 1) & DAT_0079ac68 ^ (uVar4 >> 1)
    arr[uVar2] = -(uVar4 & 1) & DAT_0079ac68 ^ (uVar4 >> 1)

# for num in arr:
#     print(hex(num))
# embed()

# calc xor_value
from ghidra.program.model.address import Address
# start_address = currentProgram.getAddressFactory().getAddress("0x465000")
# end_address = currentProgram.getAddressFactory().getAddress("0x682bb1")
start_address = 0x465000
end_address = 0x682bb1
uVar4 = 0xffffffff

while start_address <= end_address:
    current_address = currentProgram.getAddressFactory().getAddress(hex(start_address))
    byte_value = getByte(current_address)
    uVar4 = (uVar4 >> 8) ^ arr[byte_value ^ (uVar4 & 0xff)]
    start_address += 1

xor_value = uVar4 ^ 0xffffffff # 0xae1c9fc
```

# 0x03 主进程
可以看到主进程就是修改子进程的内存，就是用的_DAT_0079ac6c
直接用ghidra python进行patch，如下：
```python
#patch 1
## clear code bytes(access conflict)
from ghidra.program.model.address import AddressSet
startAddress = currentProgram.addressFactory.getAddress("0x4648a0")
endAddress = currentProgram.addressFactory.getAddress("0x464cea")
addressSet = AddressSet(startAddress, endAddress)
for address in addressSet.getAddresses(True):
    clearListing(address)


import struct
start_addr = 0x4648a0
uVar1 = 0
while uVar1 < 1099:
    current_address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(hex(start_addr + uVar1))
    data = getBytes(current_address, 4)
    original_value =  struct.unpack("<I", data)[0]
    new_value = original_value ^ xor_value
    newData = struct.pack("<I", new_value)
    setBytes(current_address, newData)
    uVar1 += 4
    # print("Patched address", current_addr, "with value", newData)

#patch2 
startAddress = currentProgram.addressFactory.getAddress("0x682bd0")
endAddress = currentProgram.addressFactory.getAddress("0x682db4")
addressSet = AddressSet(startAddress, endAddress)
for address in addressSet.getAddresses(True):
    clearListing(address)


start_addr = 0x682bd0
uVar1 = 0
while uVar1 < 0x1e4:
    current_address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(hex(start_addr + uVar1))
    data = getBytes(current_address, 4)
    original_value =  struct.unpack("<I", data)[0]
    new_value = original_value ^ xor_value
    newData = struct.pack("<I", new_value)
    setBytes(current_address, newData)
    uVar1 += 4
```

还原出来后，我们看一下子进程到底干了什么，进入这个函数
![picture 1](/images/8d22c658516a04f64b68ed1dfaa2e794e5a2f261c4318cc1390645b701d594f7.png)  

如图：
![picture 3](/images/d19e9910a335413ce25904000ad91317b85d980fb308b00c0fcc095d0a2886ca.png)  

这里可以看出大致思路，加密文件flag.gif.enc,思路就是解密flag.gif.enc就结束了。但是还有很多函数没有恢复出来，仔细查看这些函数，可以发现使用openssl库，在字符串搜索中找到相应的版本信息-〉‘3.0.2’

那就直接bindiff一下，这里我在ghidra上用binexport导出然后bindiff打开，一直报错（在这卡了好久）  
没办法了只能再次投入ida的怀抱（pd启动！）
使用ida就是爽啊，直接识别bindiff不说，其实还可以直接在ida里面对比并apply，省了我不少事（没有！，记住这个没有） 

好了恢复出来，我就看啊，一顿看，看见有个evp_aes_256_gcm,但是没看见它计算tag，就很怪，然后我就找gcm的资料，在openssl官网上一顿查，后来欣哥告诉我这个函数其实是evp_aes_256_ecb模式，一切都合理了起来。（因为我第一次使用bindiff，看见similarity是1我就直接还原了，谁知道这也能出错啊）。

# 0x04 轻舟已过万重山

好了到这里，就是预测时间戳，推测密钥了（那个伪随机数生成器真逆不了！）
```shell
stat flag.gif.enc
```
用这个modify time推测。然后gdb调试把时间戳改成这个，然后把key提取出来，用python解密一下就结束了，芜湖！

```python
from Crypto.Cipher import AES
from datetime import datetime, timezone, timedelta
# 给定的日期时间字符串
datetime_str = "2024-03-27 14:33:13 +0800"
# 将日期时间字符串转换为 datetime 对象
datetime_obj = datetime.strptime(datetime_str, "%Y-%m-%d %H:%M:%S %z")
# 将 datetime 对象转换为 UTC 时间
datetime_obj_utc = datetime_obj.astimezone(timezone.utc)
# 获取时间戳
timestamp = datetime_obj_utc.timestamp() #1711521193
keyStr = '''0x7afeb0:	0x6c	0xbc	0xc0	0x8d	0xff	0xc5	0x24	0x8c
0x7afeb8:	0xcb	0xdc	0x47	0x8f	0xbb	0xf1	0x52	0x41
0x7afec0:	0xbe	0x87	0x7d	0x2a	0xdb	0x13	0xc4	0x28
0x7afec8:	0x24	0x37	0xd4	0xae	0x9e	0xdf	0x79	0xa1'''
arr =  []
for s in keyStr.splitlines():
    for ss in s.split('\t')[1:]:
        arr.append(int(ss,16))
ciphertext = b''
key = bytes(arr)
print(key)
with open('flag.gif.enc','rb') as f:
    ciphertext = f.read()
cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
print(plaintext)
# print(ciphertext)
with open('flag.gif','wb') as f:
    f.write(plaintext)
```

# 0x05 总结
这是我第一次做nese的升级赛（事后），学到了很多，但是做题速度太慢了，菜就多练！
祝我早日加入nese， fighting cool！