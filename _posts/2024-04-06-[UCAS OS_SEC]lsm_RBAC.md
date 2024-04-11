---
title: 基于RBAC的lsm模块开发
date: 2024-04-06
categories: [UCAS_LESSION, OS_SEC]
tags: [lsm]     # TAG names should always be lowercase
---

# 0x01
经过一周的各种实验环境的折磨，已经完成从花一天到20分钟速成的蜕变了，特此记录学习过程中踩过的坑和心得
（今天s送我铜锣烧 我很开心）

# 0x02 说在前面
求你别碰重新编译内核的方案（编译时间又长，动辄40G+的内存）

# 0x03 实验环境
实验环境： ubuntu20.04 16G 16CPU 50G （另一个课的实验机 中科院就是豪横）
实现方案： qemu + busybox 打包根文件系统（他不香吗）

>   关于busybox 打包可以看下面的文章
> 
> [LSM内核模块 Demo 保姆级教程](https://blog.csdn.net/weixin_40788897/article/details/123374309)
{: .prompt-tip }

>   关于lsm开发的好文章
> 
> [LSM安全模块开发](https://rlyown.github.io/2021/07/14/LSM安全模块开发/)
> [Linux Security Module 框架介绍](https://liwugang.github.io/2020/10/18/introduce_lsm.html#:~:text=1%20将之前的%20early_lsm%20名字添加到全局变量%20lsm_names；%202%20ordered_lsm_init%20函数首先会调用,ordered_lsm_parse%20来获取模块，然后调用%20prepare_lsm%20和%20initialize_lsm，这两个函数和%20early_security_init%20中类似%E3%80%82%20系统默认的模块加载顺序：lockdown%2Cyama%2Cloadpin%2Csafesetid%2Cintegrity%2Cselinux%2Csmack%2Ctomoyo%2Capparmor%2Cbpf)
> [基于Linux Security Module的基于角色的权限管理模块](https://blog.csdn.net/jmh1996/article/details/88935907)
> [LSM安全模块开发-文件打开2FA](https://www.neko.ooo/lsm-mod/#开始前的小提示)
{: .prompt-tip }

# 0x04 我踩的一些坑
1. 重新编译内核费时费力（还疯狂报错）
2. linux 4.x 和 linux5.x 配置lsm模块的方式不一样 一开始用的4.x lsm死活不加载，换了5.x才好
3. 实现内核读文件 网上大多数实现方案都是get_fs(get_ds()) 取消地址限制 + vfs_read
   3.1. 4.x(具体忘了) vfs_read 就已经过时了
   3.2. set_fs()在5.10.x 以上废弃了 我尝试重新配置arch/X86/Kconfig 还是报错 不懂
   3.3. 使用kernel_read 代替vf_read  但是filp_open又报错了 不懂 无奈😮‍💨
4. gdb 调试 qemu 怎么没有符号啊 那我还调个集贸啊

