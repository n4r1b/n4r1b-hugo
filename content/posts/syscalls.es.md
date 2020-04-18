+++
categories = ["Kernel", "Syscall", "Windows x64"]
tags = ["Kernel", "Syscall", "Windows x64"]
date = "2019-03-11"
description = "Pequeño introduccion a como funcionan las llamadas a sistema en Windows x64"
images = ["https://n4r1b.com/images/syscall/syscall.jpg"]
featured = ["https://n4r1b.com/images/syscall/syscall.jpg"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "Llamadas a sistema en Windows x64"
slug = "Llamadas a sistema en Windows x64"
type = "posts"
+++

Los que me conozcan sabran que siempre he estado muy interesado por todo lo relacionado con el kernel, pero nunca he tenido tiempo para centrarme en ese tema. Pero este año he decidido dedicar mi tiempo libre a esto (me he comprado el Windows Internals e incluso lo estoy leyendo 😆😆). 

Por otro lado, estoy tomando nota de todo lo que hago y he decidido ponerlo bonito y compartirlo que quiza ayude a alguien! Y he decidido escribir tanto en español como en ingles (porque tengo mucho tiempo libre) y porque toda la informacion que he leido/visto investigando sobre el Kernel esta o en ingles o en ruso/chino y creo que no viene mal que tambien se hable de esto en español.

Dicho esto, hoy voy a hablar sobre las llamadas a sistema en Windows x64, que es el punto donde comenzamos a entrar en el Kernel por eso me ha parecido un buen punto para empezar. Las llamadas a sistema, a partir de ahora las llamare Syscall o Sysenter (Depende del modo y el procesador mas info [aqui](https://reverseengineering.stackexchange.com/a/16511)) son la manera que tiene una aplicacion de ring 3 de comunicarse con el SO. 

El "salto" siempre viene predecido de una funcion que tiene el siguiente prototipo:
```nasm
4C 8B D1            mov r10, rcx
B8 ?? 00 00 00      mov eax, {Numero de Syscall}
0F 05               syscall
C3                  retn
```
cuando se ejecuta la instruccion [syscall](https://www.felixcloutier.com/x86/syscall), Intel indica que se salta a la direccion que se encuentra en IA32_LSTAR (ademas de cambiar el CPL), en los sistemas de 64bits de Windows esta direccion apunta a la funcion ```KiSystemCall64``` dentro de "ntoskrnl.exe", ya en el Kernel. Por tanto ahora la maquina esta en una situacion "critica" porque se esta ejecutando codigo con CPL0 pero el estado de registros y stack sigue siendo el de un proceso con CPL3 (en la siguiente imagen se puede ver esto).

![alt img](/images/syscall/enter_syscall.jpg "Syscall jump")

Como ya he dicho la situacion es compleja, por tanto lo primero que necesita obtener el Kernel es un puntero al Kernel Stack, para llevar a cabo esto se creo la instruccion [```swapgs```](https://www.felixcloutier.com/x86/swapgs) que como indica el manual es una instruccion privilegiada que su unica funcion es cambiar la base del segmento GS por el valor contenido en la direccion C0000102H del MSR, este valor es la base del segmento GS en el Kernel (IA32_KERNEL_GS_BASE). 

> Mas info sobre esto en este articulo https://www.andrea-allievi.com/blog/x64-memory-segmentation-is-the-game-over <br/>De [@aall86](https://twitter.com/aall86)

Este valor apunta la estructura PCR (Processor Control Region) ~~la cual podemos obtener con la extension ```!pcr``` de windbg~~ **Leyendo el capitulo 2 de Windows Internals 7 hablan de la estrucutra KPCR y se comenta que el comando !pcr esta obsoleto y muestra valores incorrectos (la documentacion de [Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-pcr) no lo menciona) por tanto es mejor utilizar el comando ```dt nt!_KPCR @$pcr**, mediante esta estructura se pueden obtener todos los valores que necesita el Kernel para llevar a cabo la transicion. 

Por tanto, lo siguiente que hara el manejador de la syscall sera guardar el Stack del proceso que ha causado la llamada ```mov gs:10, rsp``` en el miembro "UserRsp" de la estructura PCR y obtener la direccion del Stack del Kernel (instruccion ```mov rsp, gs:1A8h```) esta direccion se encuentra en el offset ```28h``` dentro de la estructure PRCB (Processor Control Block) y a su vez esta estructura se encuentra en el offset ```180h``` de la estrucutara PCR

<img src="/images/syscall/kernel_stack.jpg" style="margin-left:auto; margin-right:auto"/>

Llegados a este punto ya se puede guardar el estado del proceso en el stack del Kernel, y se obtiene el KTHREAD (instruccion ```mov rsp, gs:188h```) a partir ```PCR+180h->PRCB+8h->KTHREAD``` y esta estructura se utilizara, primero para comprobar si esta activo el bit "DebugActive" en la cabecera del KTHREAD y luego para guardar los siguientes valores:

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


Una vez hecho esto, ya se comienza a calcular con que funcion se corresponde el Numero de Syscall, para esto se obtiene dos tablas:

-   KeServiceDescriptorTable
-   KeServiceDescriptorTableShadow

y estas tablas (Service Descriptor Tables), contiene una estructura llamada System Service Table (SST) que entre otros campos tiene un puntero a un array con direcciones de funciones y un DWORD con el numero de entradas en la tabla. 

> No voy a entrar en mucho mas detalle para mas informacion sobre esto podeis leer este articulo https://resources.infosecinstitute.com/hooking-system-service-dispatch-table-ssdt/#gref de "InfoSec Institute" que realmente vale la pena.

Obtenidas ambas tablas se va a comprobar si el Thread en ejecucion es un "GuiThread" ```cmp [rbx+78h], 40``` donde el bit 6 del offset ```78h``` de la estructura KTHREAD coincide con "GuiThread". Si el bit esta activo la tabla que se usara para obtener la direccion a la funcion sera ```KeServiceDescriptorTableShadow```

<img src="/images/syscall/sdt.jpg" style="margin-left:auto; margin-right:auto"/>

a continuacion se obtiene la direccion del array de funciones, se obtiene el valor del incide "Numero de Syscall"*4 (Cada entrada del array es un DWORD), este valor se divide entre 16 (```sar 4```) y este valor se suma a la direccion del array. 
```C
typdef QWORD(__fastcall * KernelFunction)(...)
QWORD service_table = poi(nt!KeServiceDescriptorTableShadow);
DWORD offset = (DWORD) poi(service_table + syscall_number*4)
KernelFunction kernel_function = (KernelFunction) service_table + (offset >> 4) 
```
Y una imagen siguiendo estos pasos en windbg para la syscall 36h (nt!NtOpenSection)

![alt img](/images/syscall/obtain_func.jpg "Obtencion direccion de funcion del kernel")

Finalmente se llamara a esta funcion ```call r10 // La direccion se encuentra en r10``` y asi es como el manejador de las syscall traslada la peticion de ring3 a ring0. 

Espero que haya quedado mas o menos claro, he intentado explicarlo de la manera mas simple posible (no he profundizado todo lo que se merece el tema por no hacer esto ilegible). Y si algo no esta del todo claro o hay algun error no dudeis en poneros en contacto conmigo (es gratis!) [@n4r1b](https://www.twitter.com/n4r1b).<br/>
Y eso ha sido todo por hoy, a ver que mas nos depara el Kernel! Hasta la proxima!! 🤪🤪

**Nota1: Todas las imagenes de windbg se han sacado haciendo remote kernel debugging de una maquina virtual con Windows 8.1 Pro**<br/><br/>
**Nota2: Al menos en mi VMware al intentar parar en la instruccion ```swapgs``` la maquina virtual daba un fault error y se reiniciaba. No he investigado mucho, pero si alguien sabe mas de esto que me lo haga saber, porfavor!**