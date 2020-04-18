+++
categories = ["Kernel", "Bootloader", "UEFI"]
tags = ["Kernel", "Bootloader", "UEFI"]
date = "2019-09-18"
description = "Overview of how the transition from the EFI Bootloader to the Kernel is done in Windows x64"
images = ["https://n4r1b.com/images/transKernel/transKernel.jpg"]
featured = ["https://n4r1b.com/images/transKernel/transKernel.jpg"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "Transition from an EFI Bootloader to the Kernel in Windows x64"
slug =  "Transition from an EFI Bootloader to the Kernel in Windows x64"
type = "posts"
+++

In my previous post I explained how the Bootloader loads the essential Drivers so the Kernel can run. On that post I mentioned how the Bootloader has two main tasks. First task is to load the OS into memory and the second task is to manage the transition from the Bootloader to this recently loaded OS. I roughly explained first task. And I thought it could be interesting to give a little overview on how the second task is done. So, here we go!

This task is done by the function `OslExecuteTransition`, specifically `OslArchTransferToKernel`. In the following image you can see the decompiled code of this function:

<img src="/images/transKernel/transfer_2_kernel.jpg" alt="OslArchTransferToKernel" style="margin:auto;"/>

First instruction basically stands for [*Write back and Invalidate Cache*](https://www.felixcloutier.com/x86/wbinvd) and basically writes back modified cache lines to main memory and invalidates the internals caches. Next, the corresponding values are assigned to the GDTR(``lgdt``) and the IDTR(`lidt`), then the following bits from [CR4](https://en.wikipedia.org/wiki/Control_register#CR4) are set:

- Bit 7: Page Global Enabled
- Bit 9: OSFXSR
- Bit 10: OSXMMEXCPT

The same is done with the following bits of [CR0](https://en.wikipedia.org/wiki/Control_register#CR0):

- Bit 5: Numeric error
- Bit 16: Write protect
- Bit 18: Alignment mask

and the bits 0 (System call Extensions) and 8 (Long Mode Enable) from the [EFER](https://en.wikipedia.org/wiki/Control_register#EFER)(This value is obtained reading the MSR `0xC0000080`). Being in a x64 machine we have the new [CR8](https://en.wikipedia.org/wiki/Control_register#CR8) which prioritize external interrupts, this value is set to zero which means no external interruptions will be prioritized. Lastly the selector pointed by [TSS](https://en.wikipedia.org/wiki/Task_state_segment) to the register TR, and after this everything is ready to execute the *far return* (Previously the EIP of the kernel and the *Segment Selector* of type Code and CPL 0 have been pushed to the stack).

> The far return takes the IP and the CS from the stack, that's why those values where pushed into it. The instruction `retfq` is used instead of the instruction `retf` because the Bootloader runs in Long Mode, this means that each entry in the stack is 64 bits long, so in order to retrieve the IP and the CS from the stack it needs to read 64 bits not 32 bits.

![alt img](/images/transKernel/transition_retfq.jpg "retfq transition")

As indicated in the Chapter 7 of the [**UEFI Specification v2.8**](https://uefi.org/specifications), if the load of the OS was successful then the UEFI Loader can call the function `ExitBootService` which frees all the EFI Drivers of type `EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER`, if this call returns `EFI_SUCCESS` then the UEFI Loader owns all available memory in the system and is also responsible for system execution to continue. The EFI Drivers of type `EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER` are kept in memory and can be used with paging and virtual addresses as long as the service has described all the virtual space it will use by calling to the function `SetVirtualAddressMap`. Having in mind that **Winload.efi** is a UEFI Loader, logically it has to take charge of everything I just said. And it does! Inside the function `OslExecuteTransition` the first function getting called is `OslFwpKernelSetupPhase1` which is in charge of doing what I explained previoulsy. This function only receive one parameter (The `LOADER_PARAMETER_BLOCK`)

<img src="/images/transKernel/ExitBootService.jpg" alt="ExitBootService" style="margin:auto;"/>

this function also sets does the mapping of the physical to the virtual addresses, as explained before, calling `SetVirtualAddressMap`. (**NOTE:** The member *EfiInformation* seen in the following picture doesn't have that name, corresponds to the last member of the structure `_FIRMWARE_INFORMATION_LOADER_BLOCK` and in the symbols it shows as `u`. I coined that name because it contains the structure `_EFI_FIRMWARE_INFORMATION`)

![alt img](/images/transKernel/SetVirtualAddress.jpg "SetVirtualAddressMap")


> **Curious fact:** Quarkslab presented a POC of a Bootkit in 2013, [Dreamboot](https://github.com/quarkslab/dreamboot) which relies on hooking the function `OslArchTransferToKernel`. At this point, in memory we can find all the structures the kernel needs to work by itself, so clearly is a good moment to have a "hook"

> More info on their paper (French) https://www.sstic.org/media/SSTIC2013/SSTIC-actes/dreamboot_et_uefi/SSTIC2013-Article-dreamboot_et_uefi-kaczmarek.pdf

## Conclusions

This is a big overview, I skipped a lot of stuff that's going on inside `OslFwpKernelSetupPhase1` I just wanted to explain in a "simple" way how this goes and the role UEFI plays in all this. On the other hand, I still need to read the book *Rootkits and Bootkits* by Alex Matrosov, Eugene Rodionov, and Sergey Bratus, but I'm pretty sure they explain all this much better and detailed, so I believe it should be a good read for everyone interested on this topic (Also the UEFI Specification is an incredible source of knowledge). As always, I hope you enjoyed and feel free to contact me to discuss more or if there's any mistake