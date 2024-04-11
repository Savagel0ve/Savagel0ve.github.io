---
title: 魔幻差异
date: 2024-04-11
categories: [UCAS_LESSION,SOFT_SEC]
tags: [re]     # TAG names should always be lowercase
---

## 0x01 said it in front 

**实验环境**  

win11  
x86_64  
(一开始用mac启动pd用win虚拟机自带的x86仿真，在这个环境上进行调试，但是遇到很奇怪的调试问题，什么调试工具都不管用包括x32dbg windbg ida pro,遂放弃)

**实验工具**  
windbg    
idapro  
010editor  

## 0x02 find differences
两个程序a1.exe和a2.exe bindiff一下很像，没有差别很大的地方，similarity都是1 这两个程序在汇编层面上的指令都是一样的，需要深一步找不同（pe结构）

简单写个脚本找一下内存上的不同
```python
with open('A1.exe', 'rb') as f1:
    data1 = f1.read()

with open('A2.exe', 'rb') as f2:
    data2 = f2.read()

for i in range(len(data1)):
    if data1[i] != data2[i]:
        print(hex(i),data1[i],data2[i])
```

脚本结果表明在文件0x9a,0x9b内存地址上的不同
```
0x9a 6 2
0x9b 0 24
```

打开010editor看看是哪个数据结构的不同
可以看到两个程序的链接器版本不同，a1.exe使用的6.0,a2.exe使用的2.24
![picture 4](/images/a78d5415db46b0dd627d96742bdef2e296d8319027c0e059c4d554e55aa3690c.png)  
![picture 5](/images/5591d40cd2b2afc00cba5e2038b773194e174125887d9e2ea2d05d50ff8afa66.png)  


这就是两个程序产生的输出不同的缘由

## 0x02 a1.exe调试与a2.exe调试
使用windbg调试a1.exe  
```
ba w4 the_addr_%n_var
```
ba断点发现在msvcrt_output_1+0x704处对这个变量进行了修改（10 -> 15）

下面还原从printf到msvcrt_output_1+0x704处都经过了哪些函数，长度是怎样一步步算出来的
1. 跟进到第一个printf
2. 继续跟进到printf源码中的msvcrt_output_1
3. msvcrt_output_1: write_string [esp-220h] -> 0xe
4. msvcrt_output_1: write_char   [esp-220h] -> 0xf
5. msvcrt_output_1: __get_printf_output_count  检查是否允许修改 检查成功
6. 长度修改成功

a2.exe同理
1. 跟进到第一个printf
2. 继续跟进到printf源码中的msvcrt_output_1
3. msvcrt_output_1: write_string [esp-220h] -> 0xe
4. msvcrt_output_1: write_char   [esp-220h] -> 0xf
5. msvcrt_output_1: __get_printf_output_count  检查是否允许修改 检查失败
6. 长度修改失败

## 0x03 msvcrt.dll 逆向
所以是 __get_printf_output_count的原因
逆向一下msvcrt.dll 看看这个函数干了啥
 ![picture 6](/images/3aeb2724fc3ccfeb09c45247c0cbbaf3e2ffbb3a2686623ca8716370f98bf559.png)  
大概就是将内存里的一个值和(__security_cookie | 1)相比较 相等则可以修改成功 不相等则跳转errno

## 0x04 why different
所以为什么a1.exe可以判定想等 a2.exe则判定不想等
进入__get_printf_output_count动态调试一下

a1.exe如下
 ![picture 7](/images/984c1455f085f7e48cfb55195781417fbdd24cf7e584efc17a29e0edeef56574.png)  

可以看到[7704b9cch] == ecx

a2.exe如下
![picture 8](/images/519355a41c1ad95fd953253bced0bab6bfc404f9ffa91591d0c003b7d6d6d126.png)  
可以看到[7704b9cch] = 0 所以导致检查失败

## 0x05 [7704b9cch]何时被写入
```
ba w4 7704b9cc
```
发现是在__set_printf_output_count处修改了
![picture 9](/images/d599946afcef93a4095208346c7814c4a97ffeeea7693fd097fd7cc87edb8ed6.png)  

__set_printf_output_count在__core_crt_dll_init被调用  
深入跟进__core_crt_dll_init找到调用逻辑

![picture 10](/images/8c80bb8e9210cc10f326fd84971372abe08eacbb6dd7e9bc455de841c5cdec5b.png)  


只有链接器版本6.0 才可以支持开启%n 支持  
而我们的a1.exe的链接器版本是6.0  
破案了
## 0x06 总结

两个程序的汇编指令上没有任何差别，在PE结构上是NTheader中OptionHeader中的链接器主次版本的不同，通过逐步深入printf的实现，发现两个程序在__set_printf_output_count处的调用不同，a1.exe调用了该函数因此获取了%n的支持，a2.exe没有调用该函数，因此没有%n支持走了invalid parameter那一套流程，究其原因就是在__core_crt_dll_init中会判断链接器版本号只有6.0支持%n，会调用__set_printf_output_count,开启%n支持。
而由前面提到的a1.exe的链接器版本号就是6.0，这就是原因所在。  
分析完毕， 感谢阅读。