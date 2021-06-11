---
title: "MemLabs Lab 2"
date: 2021-04-13T17:12:35+05:30
draft: false
toc: false
images:
tags:
  - volatility
  - MemLabs
  - Forensics
---


![](https://i.imgur.com/NlBgyht.png)

First we need to analyse the type of the image.. `imageinfo`

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab2.raw imageinfo


![](https://i.imgur.com/dbj7iym.png)

So now we will check for the active proccess using `pslist`

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab2.raw --profile=Win7SP1x64 pslist

![](https://i.imgur.com/Z07eA9z.png)

Here, we have Internet Explorer, Command Prompt, Google Chrome, KeePass, Notepad as active

So, let us analyze them one by one

---
Let us begin with command prompt.. Using the plugin `consoles`

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab2.raw --profile=Win7SP1x64 consoles

we can find this *Nothing here kids :)*.. But from the question we can find that environmental is highlighted.
So let us look into environment vairables using the plugin `envar`

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab2.raw --profile=Win7SP1x64 envars

![](https://i.imgur.com/8NHjUUo.png)

Here, we will find a base64 encoded string.. By [decoding](https://www.base64decode.org/) it we will get the first flag.


```
flag{w3lc0m3_T0_$T4g3_!_Of_L4B_2}
```

---
Now looking into Internet Explorer using `iehistory`, gives us nothing.

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab2.raw --profile=Win7SP1x64 iehistory

So let us go through Google Chrome with `chromehistory`.

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab2.raw --profile=Win7SP1x64 chromehistory

![](https://i.imgur.com/N7EaxLU.png)

We got a Mega link, which has a zip file.

![](https://i.imgur.com/krXCRsQ.png)

Password of zip is SHA1 of flag3 in Lab1. So by extracting the zip we will get flag3.

![](https://i.imgur.com/eJ7Mxi3.png)

```
flag{oK_So_Now_St4g3_3_is_DoNE!!}
```

---
We are left with Notepad and KeyPass.
For notepad, I tried with clipboard so that I can retrieve some thing.

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab2.raw --profile=Win7SP1x64 clipboard

Nothing useful was found here.

So finally, we are left with KeyPass.. KeyPass stores passwords of our files in a database in [.kdbx](https://www.reviversoft.com/file-extensions/kdbx) extension and secures this with a master password. 

So let us find *.kdbx* files.

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab2.raw --profile=Win7SP1x64 filescan | grep .kdbx

We got a *.kdbx* file.. so let us dump it using `dumpfiles`

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab2.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000003fb112a0 -D ./ -n

![](https://i.imgur.com/k6yP1qe.png)

By this we will get a kdbx file which can be opened using KeyPass. But we need to find the master password now. 

So I look into files for Password..

>volatility --plugins=volatility-plugins/ -f MemoryDump_Lab2.raw --profile=Win7SP1x64 filescan | grep -i password

I got a *PNG* file.. So let us dump it with `dumpfiles`.

![](https://i.imgur.com/2aRRiiK.png)

We got an image that has a password..

![](https://i.imgur.com/pT61YFM.png)

Using this password we can login to the kdbx file and we will have our flag as a password in recyclebin

```
flag{w0w_th1s_1s_Th3_SeC0nD_ST4g3_!!}
```

---
