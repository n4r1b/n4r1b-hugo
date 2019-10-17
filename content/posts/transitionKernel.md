+++
categories = ["Kernel", "Bootloader", "UEFI"]
tags = ["Kernel", "Bootloader", "UEFI"]
date = "2019-09-18"
description = "Breve explicacion de como se produce la transicion del Bootloader EFI al Kernel en Windows x64"
images = ["https://n4r1b.netlify.com/images/transKernel/transKernel.jpg"]
featured = ["https://n4r1b.netlify.com/images/transKernel/transKernel.jpg"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "Transicion del Bootloader EFI al Kernel en Windows x64"
slug = "Transicion del Bootloader EFI al Kernel en Windows x64"
type = "posts"
+++


Hable en su dia de como el Bootloader cargaba los Drivers esenciales para que el Kernel pudiera comenzar su ejecucion sin problema. En ese post comente que la funcion principal del Bootloader tenia dos tareas, la primera cargar el SO y la segunda ejecutar la transicion a dicho SO. De la primera hable a grandes rasgos en dicho post, pero la segunda tarea del bootloader la deje en el aire y creo que es interesante, por eso he pensado en dar una breve explicacion de cuales son los pasos que se llevan a cabo para que esto suceda.

De esta tarea se encarga la funcion `OslExecuteTransition` y mas especificamente la funcion  `OslArchTransferToKernel`, en la siguiente imagen podeis ver el pseudocodigo de esta funcion:

<img src="/images/transKernel/transfer_2_kernel.jpg" alt="OslArchTransferToKernel" style="margin:auto;"/>

La primera instruccion basicamente hace que las lineas de cache modificadas se escriban a la memoria principal e invalida estas caches. Luego se asignan los valores correspondientes al GDTR(``lgdt``) y al IDTR(`lidt`), a continuacion se van a activar los bits 7 (Page Global Enabled), 9 (OSFXSR) y 10 (OSXMMEXCPT) del [registro de control 4](https://en.wikipedia.org/wiki/Control_register#CR4), se hace lo mismo con los bits 5 (Numeric error), 16 (Write protect) y 18 (Alignment mask) del [registro de control 0](https://en.wikipedia.org/wiki/Control_register#CR0) y los bits del 0 (System call Extensions) y 8 (Long Mode Enable) del [EFER](https://en.wikipedia.org/wiki/Control_register#EFER) (Se obtiene leyendo del MSR con el valor `0xC0000080`), tambien se pone a cero el [registro de control 8](https://en.wikipedia.org/wiki/Control_register#CR8)(Es un registro nuevo solo en 64bits para priorizar las interrupciones externas), se asigna el selector que apunta al [TSS](https://en.wikipedia.org/wiki/Task_state_segment) al registro TR y finalmente se realiza un far return (Previamente se han pusheado el valor del EIP de **ntoskrnl.exe** y el *Segment Selector* de tipo Code y CPL 0)

> El far return obtiene el IP y el CS del stack, por eso se han pusheado previamente. Y se usa la instruccion `retfq` en vez de la instruccion `retf` porque el Bootloader ejecuta en Long Mode, por tanto cada entrada del stack es de 64bits por tanto para recuperar el IP y el CS tiene que leer 64 bits no 32 bits

![alt img](/images/transKernel/transition_retfq.jpg "retfq transition")

Como se indica en el Capitulo 7 de la especificacion [**UEFI v2.7**](https://uefi.org/specifications), si la carga del del SO ha ido bien el UEFI Loader puede llamar a la funcion `ExitBootService` que descarta todos los Drivers UEFI de tipo `EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER` (Servicios de arranque), si esta llamada devuelve el valor `EFI_SUCCESS` el UEFI Loader dispone de toda la memoria del sistema y ademas es responsable de que la ejecucion del sistema continue. Los Drivers UEFI de tipo `EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER` se mantienen y pueden ser usados con paginamiento y direcciones virtuales siempre y cuando el servicio haya descrito todo el espacio virtual que utiliza mediante la llamada a la funcion `SetVirtualAddressMap`. **winload.efi** al ser un UEFI Loader, logicamente, tiene que encargarse de esto, y lo hace! Dentro de `OslExecuteTransition` la primera funcion a la que se llama es `OslFwpKernelSetupPhase1` que es la encargada de realizar esto, dicha funcion recibe un solo parametro (`LOADER_PARAMETER_BLOCK`) y basicamente se va encargar de lo que he mencionado anteriormente.

<img src="/images/transKernel/ExitBootService.jpg" alt="ExitBootService" style="margin:auto;"/>

Y la llamada a `SetVirtualAddressMap` (El miembro *EfiInformation* realmente no tiene ese nombre, es el ultimo miembro de la estructura `_FIRMWARE_INFORMATION_LOADER_BLOCK` y actualmente en los simbolos no tiene nombre (*u*), le he puesto ese nombre porque contiene la estructura `_EFI_FIRMWARE_INFORMATION`):

![alt img](/images/transKernel/SetVirtualAddress.jpg "SetVirtualAddressMap")


> **Dato Curioso:** Quarkslab presento una POC de un Bootkit en el 2013, [Dreamboot](https://github.com/quarkslab/dreamboot) que una de las tecnicas que usa es hookear la funcion `OslArchTransferToKernel`. Tened en cuenta que en este punto en memoria se encuetran todas las estructuras que el kernel necesita para ejecutar o sea que es un buen punto para hacer "cosas" 🤣

> Mas info en el Paper (Esta en Frances..) https://www.sstic.org/media/SSTIC2013/SSTIC-actes/dreamboot_et_uefi/SSTIC2013-Article-dreamboot_et_uefi-kaczmarek.pdf