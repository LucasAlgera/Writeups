## SmokeLoader's Loading/Anti-Analysis

SmokeLoader is a notorious modular downloader Trojan which has been active since 2011. Smoke is as a MaaS loader and eventually sets up a C2 inside of an injected thread in a legitimate software (explorer.exe).  
It is wellknown for its anti analysis capabilities, which is what I wanted to focus on in this analysis. 

**MITRE ATT&CK mapping**
| ID | Meaning |
|---|---|
|T1027.007|Obfuscated Files or Information: Dynamic API Resolution|
|T1036 | Masquerading the PEB | 
| T1622  | Debugger evasion |
| T1027  | Code obfuscation |
| T1055.003 | Process Injection: Thread Execution Hijacking |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks|

## Static analysis
Looking at SmokeLoader's IAT it looks like there aren't too many really interesting imports. There are a bunch of imports, none are too alarming so there might be some API resolving coming up.  

Looking at the .text section I can see there is a 7.1 entropy rating. This suggests that the file might be packed, which is to be expected in a loader. 

## Stage 1 - Setup and unpacking
The first stage of SmokeLoader is a setup and the unpacking of code which eventually calls Stage 2.  

### 1.1 Indications of Stack Spoofing
The first thing SmokeLoader does before it enters it's loading part of the code is load and switch around a lot of data in the stack. To me this is a signal of stack spoofing and/or prepping the stack for the unpacking.

![Stack](image-6.png)

### 1.2 Unpacking into memory
SmokeLoader first writes some encrypted bytes into a place in memory.   
After this it dynamically resolves `VirtualProtect()` to make this memory segment have the PAGE_EXECUTE_READWRITE permissions. It uses the regular LoadLibrary and GetProcAddress for this api resolving.   
Finally it starts decrypting this memory page. Using something that looks like a custom implemented xor and shift algorithm. 

The entirety of stage 1 is filled with empty API calls like: GlobalFlags(0x0), LocalSize(0x0).   
I suspect these exist to trick up automated analysis tools and/or anti viruses. Although there is 1 GlobalFlags(0x0) call inside of a loop which, when in a Debugger, will break execution and throw an exception somewhere in ntdll.dll. This happens inside of a loop where the loader will decide the offset in the unpacked memory to step into, so I manually patched  these bytes out instead of skipping this loop.  

Loading this newly allocated code into Ghidra I saw it did 2 things: 
1. Resolve API's: 
    - Sleep
    - GlobalAlloc, VirtualAlloc
    - CreateTool32Snapshot, Module32First
    - CloseHandle
2. Dumps a new PE file into a buffer
3. Jump into a new codespace in memory
4. Resolve API's
    - VirtualAlloc, VirtualProtect, VirtualFree
    - GetVersionA
    - TerminateProcess, ExitProcess, SetErrormode
5. Copies the earlier allocated PE into itself (Process Hollowing)
6. Call some address (stored in EAX) inside of .text in this PE which leads to Stage 2



## Stage 2 - Anti Analysis 
Entering stage 2 I immediately saw a bunch of heavily obfuscated assembly instructions.  

![Stage 2 entry](image-7.png)   

SmokeLoader uses a combination of techniques which makes code analysis a lot harder: 
1. **Control flow obfuscation:** Smoke sometimes enters long jumpchains and does not use call instructions how they were intended. By altering the return address stored in the callstack (callstack spoofing), the `RET` instruction doesn't do it's expected behavior anymore. 
2. **Opaque Predicates:** The disassembly is filled with a combination of `JNE` `JE` instructions. Even though the result will always stay the same since the ZF doesn't change that much, it does reduce readability and makes it impossible for decompilers to give accurate results. 
3. **Junk byte insertions:** Looking at the image above the `C7` byte is an invalid x86-32 assembly instruction, and its also unused. These "Junk Bytes" are scattered around the code which sometimes tricks the disassembler into showing invalid/incorrect disassembly. 


### Some custom scripts
I solved these problems by creating these 2 simple scripts in Python and C++:   

1. **Anti-OP (Opaque Predicates) - Python:** 
    ```py
    # data is a bytearray of a read file
    for i in range(len(data) - 3):
        a, b, c = data[i], data[i+1], data[i+2]

        # opcode: 0x74 == JE  //   0x75 == JNE
        if (a == 0x75 and c == 0x74) or (a == 0x74 and c == 0x75):
            data[i] = 0xEB
            data[i+2] = 0x90
            data[i+3] = 0x90
    ```

    Here I read the .text segment in memory and I scan for `JNE` and    `JE` instructions.  
    Since they both point to the same jump address I can patch `JNE`    for `JMP` and I can NOP out `JE`. This makes the disassembly a     lot easier to handle for any decompiler. 


2. **Resolving jump chains - C++:**  
    I decided to write this tool in C++ since i'd have to make use of live disassembly, I used the Zydis library for my disassembly.   

    *This code is stripped down a lot and wont work, it's just to showcase the general workings.*

    ```cpp
    int instructionCount = 400;

    for (int i = 0; i < instructionCount; i++)
    {
        ZyanStatus status = ZydisDecoderDecodeFull( /* ... */ );

        if (instruction.mnemonic == ZYDIS_MNEMONIC_JNZ || 
            instruction.mnemonic == ZYDIS_MNEMONIC_JZ || 
            instruction.mnemonic == ZYDIS_MNEMONIC_JMP)
        {
            // Get the address the jump instruction wants to go to
            ZydisCalcAbsoluteAddress(&instruction, &operands[0],    EIP, &targetAddress);

            // This becomes our next instruction
            EIP = targetAddress;
            continue;
        }

        if (ZYAN_SUCCESS(status)) 
        {
            // Format and print
            ZydisFormatter formatter;
            ZydisFormatterInit(&formatter,  ZYDIS_FORMATTER_STYLE_INTEL);

            ZydisFormatterFormatInstruction( /* instr params */ );

            printf( /* the formatted instruction */ );

            EIP += instruction.length;
        }
    }
    ```

    This converted the disassembly from an unreadable state to an   easier to read state:  
    ![code transformation](image-10.png)

    With this I can now easier spot what SmokeLoader is trying to do    instead of getting lost in jump loops. 


### Stealthy in memory
SmokeLoader uses Decrypt On Demand mechanism in it's code to avoid detection from antivirus memory scanners. This pretty much means that all of it's code in this 2nd Stage is encrypted in memory and only decrypted right before it needs it.  
For this it uses a simple xor algorithm where the key is stored in EDX:  
![decryption](image-11.png)  
After the decrypted code is ran Smoke of course encrypts it again to stay as stealthy as possible. 

### Anti Analysis Checks
1. **OS Version Check:** SmokeLoader walks the PEB and accesses OSMajorVersion, it checks the version and the build. Smoke targets any windows version 7 > and build < 22000.
2. **Debugger Check:** Using NtQueryInformationProcess with flags set to 0x7 (DebugPort), Smoke is able to detect wether it's process is being run in a debugger. 
3. **SandBox/Anti Virus detection:** Going through the loaded module on the machine, SmokeLoader compares them to:
    - sbiedll → Sandboxie Environment
    - aswhook → Avast Anti-virus
    - snxhk → Avast Anti-virus
4. **Registry set values:** Smoke goes into the registry and tries to query: 
    - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\SCSI  
    - Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\IDE  
    Inside of these registries it looks for enums like: `vmware, vbox, etc.`

### Injection into explorer.exe
Using the following windows API functions SmokeLoader injects it's payload into a new thread inside of explorer.exe:
```C++
// Get the processid of explorer.exe
HWND hWnd = GetShellWindow();
LPDWORD processId;
GetWindowThreadProcessId(hWnd, &processId);

// First creates a section with PAGE_READWRITE permissions

if(NtCreateSection(&SectionHandle, a, b, &MaxSize, PAGE_READWRITE, AllocAttr, fH))
{
    // Current Process
    if(NtMapViewOfSection(SectionHandle, 0xFFFFFFFF, &BaseAddr, 0,0,0,&ViewSize, 0, 4))
    {
        // Explorer.exe
        NtMapViewOfSection(NtMapViewOfSection(SectionHandle, Hexpl, &BaseAddr2, 0,0,0,&ViewSize, 0, 4);
    }
}

// Then creates a section with PAGE_EXECUTE_READWRITE permissions

if(NtCreateSection(&SectionHandle, a, b, &MaxSize, PAGE_EXECUTE_READWRITE, AllocAttr, fH))
{
    // Current Process
    if(NtMapViewOfSection(SectionHandle, 0xFFFFFFFF, &BaseAddr, 0,0,0,&ViewSize, 0, 4))
    {
        // Explorer.exe
        NtMapViewOfSection(NtMapViewOfSection(SectionHandle, Hexpl, &BaseAddr2, 0,0,0,&ViewSize, 0, 4);
    }
}

```

## Stage 3 - C2 and actual payload

(I might go into this at a later moment since I had set my scope for analyzing the loading phase of this sample..)
