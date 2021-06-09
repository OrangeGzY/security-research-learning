# security-research-learning
重新记录自己安全研究的学习过程。跳过了[早期的CTF阶段](https://orangegzy.github.io)。

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


**5. Linux内核漏洞利用**
> 本部分随缘梳理成文
- [Kernel_ROP_LKM_debug](https://bbs.pediy.com/thread-262425.htm)
- [Double_fetch](https://bbs.pediy.com/thread-262426.htm)
- [Kernel_UAF](https://bbs.pediy.com/thread-262427.htm)
- VDSO
- tty_struct
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

**0xffff. 杂记**
- [2020年中随笔](https://orangegzy.github.io/2020/07/26/2020年中随笔/)
- [2020年终总结](https://orangegzy.github.io/2020/12/27/lost-in-2020/)
- [从期末考试说开去](https://orangegzy.github.io/2021/01/05/从期末考试说开去/)
- [随便说点什么，关于CTF入门这些事情](https://orangegzy.github.io/2021/02/04/lost-in-books/)
- [2021年中随笔](https://github.com/OrangeGzY/security-research-learning/blob/main/2021-mid.md)

# Week10,5.30-6.6,2021
### tiny_kernel
1. lab0 √
2. lab1 √
### others
1. 读了一下《Fuzzing the Linux Kernel》再理解一些宏观上的kernel fuzz的东西。[ppt](https://github.com/OrangeGzY/security-research-learning/blob/main/Fuzzing%20the%20Linux%20Kernel/2021%2C%20PHDays_%20Fuzzing%20the%20Linux%20kernel.pdf)
2. 读了一下 [DIE](https://github.com/sslab-gatech/DIE) 的源码，是一个魔改AFL的**js-fuzz**，**主要理解了一下魔改的样本变异阶段（Typescript编写）**，形成了一些[笔记](https://github.com/OrangeGzY/security-research-learning/blob/main/DIE/DIE.md)。虽然我不是做js-fuzz的，但是还是学到许多。
3. 用中断机制来提高内核中条件竞争漏洞的利用成功率：[【bsauce读论文】2021-USENIX-EXPRACE-采用中断机制来利用多变量竞争漏洞](https://www.jianshu.com/p/eaabf0b3cec7)，感觉挺有意思的，mark一下，原paper在：[ExpRace: Exploiting Kernel Races through Raising Interrupts](https://www.usenix.org/conference/usenixsecurity21/presentation/lee-yoochan),然后blackhat上的ppt：[ppt_in_black_hat](https://www.usenix.org/conference/usenixsecurity21/presentation/lee-yoochan)
4. ciscn-CTF 西南赛区分区赛

# Week11,6.7-6.13,2021
### others
1. 这几周的主线应该是**复习期末考试。**
2. 申请了中科院软件所的开源项目实习（如果可以的话，提高一下码力）：https://summer.iscas.ac.cn/#/?lang=chi
3. 星阑正式离职，交接文档。
