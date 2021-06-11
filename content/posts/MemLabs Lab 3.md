---
title: "MemLabs Lab 3"
date: 2021-04-14T10:34:34+05:30
draft: false
toc: false
tags:
  - volatility
  - MemLabs
  - Forensics
---

![](https://i.imgur.com/N65koqO.png)

As usual finding profile using `imageinfo`

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab3.raw imageinfo

![](https://i.imgur.com/BquoWpA.png)

Finding active process using `pslist`

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 pslist

![](https://i.imgur.com/M5rqXNa.png)
We can find that some of the active processes to be considered are internet explorer, notepad

So, Let us find Internet Explorer history using `iehistory` plugin

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 iehistory

![](https://i.imgur.com/2j9Jsts.png)
We can find some python script file (*.py*) and a *.txt* file

So, looking for those files in specified location(Desktop) using `filescan`

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 filescan | grep Desktop

![](https://i.imgur.com/1EGR1f9.png)
We can find one more *.jpeg* which is suspicious(because we were asked to use **steghide** - steganographic tool for images)

Dumping the files using `dumpfiles`

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003de1b5f0 -D ./ -n

![](https://i.imgur.com/Fjnwe0D.png)
We can see the python script now. Here the text inside *vip.txt* was used

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003e727e50 -D ./ -n

![](https://i.imgur.com/4s2NEtX.png)

So after getting the text, by reversing the python script, we can get the 1st half of the flag
![](https://i.imgur.com/q8ox2iA.png)

Dumping the jpeg

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab3.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x0000000004f34148 -D ./ -n

![](https://i.imgur.com/e3GSZh9.png)
Applying steghide on the jpeg with key as the first part of flag gives the other part of flag

```
inctf{0n3_h4lf_1s_n0t_3n0ugh}
``` 

---
