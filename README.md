```
    __  __           __   _____           
   / / / /___ ______/ /__/ ___/__  _______
  / /_/ / __ `/ ___/ //_/\__ \/ / / / ___/
 / __  / /_/ / /__/ ,<  ___/ / /_/ (__  ) 
/_/ /_/\__,_/\___/_/|_|/____/\__, /____/  
                            /____/        
			Extreme Vulnerable Driver
							Exploits
```

### HackSys Extreme Vulnerable Driver - Windows 10 x64 StackOverflow Exploit using GDI

Classic StackOverflow exploit, which exploits a vulnerable function within the HEVD Kernel driver.

# How does this exploit work:

* 64 Bit version of the https://github.com/Cn33liz/HSEVD-StackOverflow exploit
* Works almost the same as my Windows 10 x64 exploit with SMEP Bypass, but instead of disabling SMEP using a ROP chain, i'm using a ROP chain which turns our exploit into a Arbitrary Read/Write exploit using GDI/Bitmaps.
* This is based on the same technique described in the following document from Core Security: https://www.coresecurity.com/system/files/publications/2016/10/Abusing-GDI-Reloaded-ekoparty-2016_0.pdf, which i'm also using in this exploit: https://github.com/Cn33liz/HSEVD-ArbitraryOverwriteGDI

Runs on:

```
This exploits has been tested succesfully on Windows 10 x64 v1607 (Version 10.0.14393).
``` 

Compile Exploit:

```
This project is written in C and can be compiled within Visual Studio.
```

Load Vulnerable Driver:

```
The HEVD driver can be downloaded from the HackSys Team Github page and loaded with the OSR Driver loader utility.
To run on x64, you need to install the Windows Driver Kit (WDK), Windows SDK and recompile with Visual Studio.
```

