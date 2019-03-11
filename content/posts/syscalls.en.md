+++
categories = ["Kernel", "Syscall", "Windows x64"]
tags = ["Kernel", "Syscall", "Windows x64"]
date = "2019-03-11"
description = "Little overview on how System calls work on Windows x64"
images = ["https://n4r1b.netlify.com/images/syscall/syscall.jpg"]
featured = ["https://n4r1b.netlify.com/images/syscall/syscall.jpg"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "System calls on Windows x64"
slug = "System calls on Windows x64"
type = "posts"
+++

Those who know me know that I've been always interested in Kernel stuff, but due to lack of time I've never been available to focus on this topic. But this year I took the decision to spend my free time looking into this (I even bought Windows Internals... And I'm reding it!! 😆😆). Also, I've been taking notes on everything I research. And I decided to clean it all and share it on this blog, maybe It can help someone starting

Having said that, today I'm going to talk about System calls, this is the point where we jump from userland to kernel so I thought it would be a good start point. System calls, from now on I will call them Syscall or Systenter (It depends on the mode or the processor, you can get more info in this [StackOverFlow answer](https://reverseengineering.stackexchange.com/a/16511)), are the way a ring 3 program has to request a services to the OS.

The "jump" is always preceded by a stub which looks like this:
```nasm
4C 8B D1            mov r10, rcx
B8 ?? 00 00 00      mov eax, {Syscall Number}
0F 05               syscall
C3                  retn
```
if we look at the Intel reference of the instruccion [syscall](https://www.felixcloutier.com/x86/syscall) it says that the code will jump into the address specified on IA32_LSTAR (besided changing the CPL). On windws 64 bits this address points to the function ```KiSystemCall64``` inside "ntoskrnl.exe", so we are already in the Kernel. Right now the machine context is pretty complex because we have the IP pointing to CPL0 code but the state of the stack and the register still belongs to a CPL3 process (these can be seen on the next image). 

![alt img](/images/syscall/enter_syscall.jpg "Syscall jump")

As I said, the situation is quiet complex, that's the point where the instruction [```swapgs```](https://www.felixcloutier.com/x86/swapgs) comes in handy (actually it was created for this). Again going into the reference first we notices this is a privilege instruction and second its "only" function is to change the base of the GS segment with the value inside the address C0000102H of the MSR. This value corresponds to the base of the GS segment on the Kernel (IA32_KERNEL_GS_BASE)

> More info on this excellent article  https://www.andrea-allievi.com/blog/x64-memory-segmentation-is-the-game-over <br/>By [@aall86](https://twitter.com/aall86)

The value IA32_KERNEL_GS_BASE point to the PCR structure (Processor control region) and through this structure whe can get everything necessary to achieve the transition into the Kernel function. (You can get the PCR by using the windbg extension ```!pcr``` other way is to use the value of gs:0 as the addres in ```dt nt!_KPCR```)

So, the next the syscall handler will do is save the calling process stack with the instruction ```mov gs:10, rsp``` the PCR structure has a member called "UserRsp" on offset ```10h```. Following this, the handler will get the Kernel stack with the instruction ```mov rsp, gs:1A8h``` here things are a little bit more complex because on offset ```28h``` inside the structure PRCB (Processor Control Block) which is on offset ```180h``` of the structure PCR we can find a member called "RspBase" which point to the top of the Kernel Stack

<img src="/images/syscall/kernel_stack.jpg" style="margin-left:auto; margin-right:auto"/>

Now, we already have the stack pointer pointing to Kernel memory so now we can save the state of the calling process. During this process the handler will obtain a pointer to the KTHREAD structure with this instruction ```mov rsp, gs:188h``` again through the PCR, it access to the PRCB and in offset ```8h``` of PRCB we can find the pointer to the KTRHEAD structure. The pointer to this structure will come in handy when checking to see if the "DebugActive" bit is set and to save some values from the calling process context into this structure. These values are the following:  

<table border="0">
 <tr>
    <td><img src="/images/syscall/kthread_values.jpg" style="width:450px"alt="Avatar"></td>
    <td>
        <ul>
            <li> Offset 80h: SystemCallNumber </li>
            <li> Offset 88h: FirstArgument </li>
            <li> Offset 90h: TrapFrame (KTRAP_FRAME struct) </li>
        </ul>
    </td>
 </tr>
</table>

After that, the handler will start to calculate the address of the corresponding function for that corresponding Syscall number, for this purpose it will obtain pointer to two tables:

-   KeServiceDescriptorTable
-   KeServiceDescriptorTableShadow

these tables (Service Descriptor Tables) hold a structure called System Service Table (SST) inside, the SST among other things has a pointer to an array of function addresses and a DWORD with the number of entries on the table

> I'm not going to jump into much detail of how these tables work, but if your are interested (and I really encourage you) you can read this great article https://resources.infosecinstitute.com/hooking-system-service-dispatch-table-ssdt/#gref by "InfoSec Institute".

Having both tables, next thing to do is check if we are executing a "GuiThread" ```cmp [rbx+78h], 40``` where the bit 6 of offset ```78h``` inside structure KTHREAD match with the "GuiThread" member. If this bit is set the code will use ```KeServiceDescriptorTableShadow``` to obtain the address of the kernel function.

<img src="/images/syscall/sdt.jpg" style="margin-left:auto; margin-right:auto"/>

then the handler will proceed to obtain the address of the Kernel function by doing something similar to the following pseudo-code:
```C
typdef QWORD(__fastcall * KernelFunction)(...)
QWORD service_table = poi(nt!KeServiceDescriptorTableShadow);
DWORD offset = (DWORD) poi(service_table + syscall_number*4)
KernelFunction kernel_function = (KernelFunction) service_table + (offset >> 4) 
```
And here there is an image following those steps by hand on windbg to obtain the address of nt!NtOpenSection (Sycall number 36h)

![alt img](/images/syscall/obtain_func.jpg "Get kernel function address")

Finally, these function will get called by the instruction ```call r10 \\ The address of the kernel function is on r10``` and that's pretty much all folks. That's how the Syscall handler transfer the syscall request from ring 3 into ring 0

I hope everything is more or less clear, I've tried to explain everything in the simplest terms possible (Probably I didn't break it down as much as the topic deserve). If theres any mistakes (I wouldn't be surprised, I'm not an expert on the topic..) or anything that's not clear please don't hesitate to contact me!! (it's free!) [@n4r1b](https://www.twitter.com/n4r1b). <br/>
And that's all folks. Until the next! 🤪🤪

**Note1: Every image of windbg has been taken from a remote kernel debugging of a Virtual Machine running Windows 8.1 Pro**<br/><br/>
**Note2: At least on my VMware eveytime I tried to step into or break into the instruction ```swapgs``` it caused a fault error on my virtual machine. I haven't researched on this topic but if anyone know why this happens please let me know!**