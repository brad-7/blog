---
title: "MemLabs Lab 1"
date: 2021-04-08T09:06:31+05:30
draft: false
toc: false
images:
tags:
  - volatility
  - MemLabs
  - Forensics
---


![Lab1](https://i.imgur.com/ug3ULDe.png)

---
First analysing the image type we use `imageinfo` to do that

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab1.raw imageinfo

![](https://i.imgur.com/MhvK0v1.png)

Now we want to analyse the active proccess that are running, for this we may use `pslist` or `pstree` plugins

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab1.raw --profile=Win7SP1x64 pslist

![](https://i.imgur.com/AGu2EJD.png)

We can find that command prompt, MS Paint, Internet Explorer, WinRAR are active processes.

---

So to explore command prompt, We use `consoles` plugin.

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab1.raw --profile=Win7SP1x64 consoles

![](https://i.imgur.com/KzSto3m.png)

Here, we can observe a string in base64.. decoding it from [base64](https://www.base64decode.org/) gives us the 1st flag.

```
flag{th1s_1s_th3_1st_st4g3!!}
```

---
Now we have MS Paint, Internet Explorer, WinRAR to be analysed. 

For analysis of Internet Explorer, we have `iehistory` plugin.

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab1.raw --profile=Win7SP1x64 iehistory

But here we didn't get anything.. so this might be a loop-hole.

---
Now to analyse WinRAR, We need to try to get a RAR file. so for that we will use filescan to find a *.rar* file.

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab1.raw --profile=Win7SP1x64 filescan | grep .rar

![](https://i.imgur.com/tKjJoz0.png)

Dumping the *.rar* file will give us the RAR.. So we will use `dumpfiles` plugin to dump these files.

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab1.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fa3ebc0 -D ./ -n

![](https://i.imgur.com/enGbKUN.png)

We got a RAR which was password protected.. And the password is NTLM hash of Alissa's password

So to get her password we will use `mimikatz` plugin

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab1.raw --profile=Win7SP1x64 mimikatz

![](https://i.imgur.com/RrTWFYL.png)

Converting the password into [NTLM hash](https://codebeautify.org/ntlm-hash-generator) gives us the password to RAR

Extracting the RAR, gives an image of flag.

![](https://i.imgur.com/c3vSh1U.png)

```
flag{w3ll_3rd_stage_was_easy}
```

---
Now we are left with stage 2 and only active process is MS Paint.. So looking for that doesnt give any thing initially

`clipboard` is a plugin that gives us the list that are in clipboard

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab1.raw --profile=Win7SP1x64 clipboard

But nothing will be displayed.

So let us dump the Paint file using `memdump` plugin.

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab1.raw --profile=Win7SP1x64 memdump -p 2424 -D ./

![](https://i.imgur.com/e120tbR.png)

So to analyse this *.dmp* file we will use [Gimp](https://www.gimp.org/) tool.

We can see flag in inverse after adjusting height, width.

![](https://i.imgur.com/sh3jyKs.png)

![](https://i.imgur.com/9tl5JOm.png)

By inversing this image using an [online tool](https://www.img2go.com/rotate-image) gives us the flag

![](https://i.imgur.com/2nfj4Qg.png)

```
flag{G00d_Boy_good_girl}
```

[Reference](https://www.rootusers.com/google-ctf-2016-forensic-for1-write-up/). 

---
