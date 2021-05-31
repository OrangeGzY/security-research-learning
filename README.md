# security-research-learning
记录自己安全研究的学习过程。跳过了[早期的CTF阶段](https://orangegzy.github.io)。

看雪：[ScUpax0s](https://bbs.pediy.com/user-876323-2.htm)

艺无止境，功不唐捐。

# Done
**1. Fuzz源码分析**
- [AFL源码阅读笔记之gcc与fuzz部分](https://bbs.pediy.com/thread-265936.htm)
- [AFL编译插桩部分源码分析](https://bbs.pediy.com/thread-265973.htm)
- [AFL之llvm mode部分源码分析](https://bbs.pediy.com/thread-266025.htm)
- [sslab-DIE,js-fuzz,变异阶段源码分析](https://github.com/OrangeGzY/security-research-learning/blob/main/DIE/DIE.md)


**2. malloclab实现自己的malloc分配器**
- [tiny_malloc](https://github.com/OrangeGzY/csapp-lab/blob/main/malloclab/mm.c)


**3. IDA插件（还需完善）**


**4. Linux内核源码分析**
- [内核boot源码分析](https://orangegzy.github.io/2020/07/16/Linux内核基础/)
- eBPF模块

**5. 0xffff**
- [2020年中随笔](https://orangegzy.github.io/2020/07/26/2020年中随笔/)
- [2020年终总结](https://orangegzy.github.io/2020/12/27/lost-in-2020/)
- [从期末考试说开去](https://orangegzy.github.io/2021/01/05/从期末考试说开去/)
- [随便说点什么，关于CTF入门这些事情](https://orangegzy.github.io/2021/02/04/lost-in-books/)

**5. Linux内核漏洞利用**
- [Kernel_ROP_LKM_debug](https://bbs.pediy.com/thread-262425.htm)
- [Double_fetch](https://bbs.pediy.com/thread-262426.htm)
- [Kernel_UAF](https://bbs.pediy.com/thread-262427.htm)
- prctl
- modprobe_path
- [ret2usr](https://bbs.pediy.com/thread-262434.htm)
- [Heap_Spraying](https://bbs.pediy.com/thread-263954.htm)
- [ret2dir](https://bbs.pediy.com/thread-263992.htm)


**6. 已分析的CVE**
- Linux Kernel,DirtyCOW,[CVE-2016-5195](https://bbs.pediy.com/thread-264199.htm)
- Linux Kernel,waitpid,[CVE-2017-5123](https://bbs.pediy.com/thread-265232.htm)
- Linux Kernel,UDF Fragment Offload,[CVE-2017-10000112](https://bbs.pediy.com/thread-265319.htm)
- Linux Kernel,eBPF,[rc-整数溢出](https://bbs.pediy.com/thread-266200.htm)
- Linux Kernel,eBPF,CVE-2020-8835
- Linux Kernel,eBPF,CVE-2020-27194
- Linux Userspace,sudo不完全分析,[CVE-2021-3156](https://github.com/OrangeGzY/AFL_learning/blob/main/intro_to_CVE-2021-3156.md)

# Week10,5.30-6.6,2021
### tiny_kernel
1. lab0 √
### others
1. 读了一下《Fuzzing the Linux Kernel》再理解一些宏观上的kernel fuzz的东西。[ppt](https://github.com/OrangeGzY/security-research-learning/blob/main/Fuzzing%20the%20Linux%20Kernel/2021%2C%20PHDays_%20Fuzzing%20the%20Linux%20kernel.pdf)
2. 读了一下 [DIE](https://github.com/sslab-gatech/DIE) 的源码，是一个魔改AFL的**js-fuzz**，主要理解了一下魔改的样本变异阶段（Typescript编写），形成了一些[笔记](https://github.com/OrangeGzY/security-research-learning/blob/main/DIE/DIE.md)。虽然我不是做js-fuzz的，但是还是学到许多。
