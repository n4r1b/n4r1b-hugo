+++
categories = ["Kernel"]
tags = ["Kernel", "LoadLibrary", "NtOpenSection"]
date = "2019-03-16"
description = "Investigando como el kernel gestiona la funcion LoadLibrary"
images = ["https://n4r1b.netlify.com/images/loadLibrary/loadLibrary.jpg"]
featured = ["https://n4r1b.netlify.com/images/loadLibrary/loadLibrary.jpg"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "Parte 1: Profundizando en la funcion LoadLibrary"
slug = "Parte 1: Profundizando en la funcion LoadLibrary"
type = "posts"
+++

Hola otra vez! Volvemos con el kernel, esta vez vamos a investigar la que quiza sea una de las funciones mas famosas de la API de windows, LoadLibrary. La motivacion para llevar a cabo esta investigacion (A parte de conocer mas el kernel y como funciona) viene de un proyecto que estaba realizando hace un par de semanas donde estaba programando un Loader Reflectivo de una DLL y por ciertos motivos no conseguia hacerlo funcionar (Al final era un tema de las "relocations" que en Windows son un infierno) y claro, para encontrar mi error me parecio la mejor idea el investigar como carga las librerias Windows.

## Avisos!
Voy a centrarme principalmente en lo que sucede en el Kernel cuando se llama a LoadLibrary, voy a mostrar muy por encima lo que sucede en Userland. Por otro lado, no voy a hacer hincapie en todo lo que sucede en el kernel porque, creedme, es **MUCHO** codigo. Me centrare en las funciones que realizan las acciones mas importantes y por supuesto en todas las estructuras que estan involucradas.

## LoadLibrary!
Para la investigacion usaremos este pequeño fragmento de codigo:

```cpp
int WinMain(...) {
    HMODULE hHandle = LoadLibraryW(L"kerberos.dll");
    return 0;
}
```
Utilizo la funcion Unicode porque el Kernel solo trabaja con Strings en este formato y esto que me ahorraba a la hora de investigar 😁 

Lo primero que sucede cuando se ejecuta la funcion LoadLibraryW es que la ejecucion se redirige a la DLL **KernelBase.dll** (Esto tiene que ver con el MinWin kernel que implemento Windows a partir de Windwos 7. [Mas Info](https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html)) una vez dentro de KernelBase lo primero que se hace es llamar a la funcion **RtlInitUnicodeStringEx** para obtener una UNICODE_STRING (Es una struct no una string!) a continuacion ya se entra en la funcion **LdrLoadDll** (Ldr -> Loader) donde el parametro pasado en ```r9``` es un parametro de salida que tendra finalmente el HANDLE del modulo ya cargado. Esta funcion es donde esta todo el codigo interesante de Userland relacionado con la carga de una Dll (Realmente la funcion interesante es la homonima pero en version privada Ldr**p**LoadDll). Despues de varios sanity checks y entrando en un par de funciones mas se llega a la primera funcion que salta al Kernel y en la cual nos centraremos en esta parte **NtOpenSection**. El call stack justo antes de saltar al Kernel es el siguiente:

![alt img](/images/loadLibrary/call_stack_userland.jpg "UserLand CallStack")

## NtOpenSection
Lo primero es saber que se entiende por "Section", si nos vamos a la documentacion de Drivers de Windows en la seccion de Manejo de Memoria encontramos el apartado ["Section Objects and Views"](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views) donde se dice que un "Section Object" representa una zona de memoria que puede ser compartida y que este objeto provee los mecanismos para que un procesos pueda mapear un fichero en su propio espacio de memoria.

> Tened en cuenta que el Kernel de Windows a pesar de estar escrito practicamente entero en C, esta basado en objetos (No orientado a objetos, no sigue al 100% los principios de herencia de la programacion orientada a objetos) por esto se habla de "Section Object", mas adelante hablare sobre las diferentes estructuras y comandos en windbg que nos permiten obtener informacion de un objeto

Por tanto, teniendo en cuenta esa definicion, es logico que **NtOpenSection** sea la primera funcion del Kernel que se ejecuta cuando se va a cargar una DLL. Metiendonos ya en el codigo, esta funcion recibe 3 parametros.

-  ```rcx``` -> PHANDLE un puntero que recibira el Handle
-  ```rdx``` -> ACCESS_MASK con los permisos que se quieren obtener sobre el Objeto
-  ```r8```  -> POBJECT_ATTRIBUTES un puntero con los atributos de la DLL que se quiere cargar

En la siguiente imagen se pueden ver estos parametros:

![alt img](/images/loadLibrary/params_opensection.jpg "Params NtOpenSection")

la mascara de acceso se corresponde con los siguientes valores que se pueden obtener del archivo de cabecera [winnt.h](https://www.codemachine.com/downloads/win10/winnt.h)
```cpp
#define SECTION_QUERY                0x0001
#define SECTION_MAP_WRITE            0x0002
#define SECTION_MAP_READ             0x0004
#define SECTION_MAP_EXECUTE          0x0008
```
Lo primero que hara esta funcion, como muchas otras dentro del Kernel, es obtener el [PreviousMode](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/previousmode), este campo indica basicamente si el codigo proviene de Kernel o de Userland, cuando es este el caso mediante una syscall el manejador activa este campo en el KTHREAD

> Curiosamente hace un par de dias [@benhawkes](https://twitter.com/benhawkes) difundio una vulnerabilidad del Kernel de Windows que tenia que ver con este campo https://googleprojectzero.blogspot.com/2019/03/windows-kernel-logic-bug-class-access.html

a continuacion se hace una comprobacion, tambien bastante recurrente en el Kernel, de si la direccion del PHANDLE esta por encima del MmUserProbeAddress (```7fffffff0000h```), en caso de ser asi la funcion LoadLibrary fallara con el error 998 ("Se realizo un acceso no valido a la ubicasion de memoria"). De no ser asi, se llamara a la funcion **"ObOpenObjectByName"** esta funcion como parametro interesante recibe en ```rdx``` un Section Object que el Kernel obtiene de la direccion MmSectionObjectType

![alt img](/images/loadLibrary/section_object.jpg "Section Object")

A partir de aqui ya entramos en verdadero Kernel Code 😆😆, lo primero que se realiza es una comprobacion de que se ha recibido un OBJECT_ATTRIBUTES(```rcx```) y un OBJECT_TYPE(```rdx```) si se pasa este chequeo se comprueba que la Lookaside List 8 (KTHREAD->PPLookAsideList[8].P) este inicializada (Muy resumidamente las Lookaside list funcionan como una especie de cache. [Mas info](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-lookaside-lists)) y se obtendra la direccion de un Pool a partir de la ListHead de esta Lookaside List. A continuacion se llama a la funcion **ObpCaptureObjectCreateInformation** esta funcion lo primero que hara sera comprobar que el previousMode este activo (User Mode) y que la direccion del OBJECT_ATTRIBUTES sea menor que el MmUserProbeAddress, comprobado esto se chequea que el tamaño del OBJECT_ATTRIBUTES.Length sea de ```30h```, pasadas estas comprobaciones se almacenara en el Pool obtenido anteriormente la estructura OBJECT_CREATE_INFORMATION con los datos de la estructura OBJECT_ATTRIBUTES y por otro lado si esta estructura tiene un ObjectName, mediante la funcion  **ObpCaptureObjectName** se copiara este ObjectName a la direccion apuntada por el puntero pasado en ```r9``` modificando el campo MaximumLength al valor ```F8h``` en caso de que sea menor. 

![alt img](/images/loadLibrary/object_create_info.jpg "Create Information")

volviendo de esta funcion si todo ha ido bien, comienza la diversion con las estructuras 🤣🤣 primero se obtiene un puntero al KTHREAD (```gs:188h```), a partir de este puntero se obtiene un puntero al KPROCESS (KTHREAD+```98h```->ApcState+```20h```->Process) pero el KPROCESS es el primer elemento de la estructura EPROCESS (El PEB de los procesos en el Kernel.. por simplificar) por tanto si tenemos un puntero al KPROCESS tenemos un puntero al EPROCESS.

![alt img](/images/loadLibrary/eprocess_kprocess.jpg "Executive Process, Kernel Process")

y de esta forma el kernel obtiene el UniqueProcessId que se encuentra en el offset ```2E0h``` del EPROCESS, por otro lado tambien se ha obtenido un puntero al miembro GenericMapping (Offset ```0xc```) dentro de la estrcutura OBJ_TYPE_INITIALIZER que a su vez se encuentra en el offset ``40h`` de la estructura OBJECT_TYPE. Por ultimo se comprueba si esta activo el bit ActiveImpersonationInfo del ETHREAD (Misma situacion que con el EPROCESS, si tenemos el KTHREAD tenemos el ETHREAD), en este caso no esta activo y la verdad no he investigado mucho que significa ese bit, lo dejo como tarea pendiente. 

Seguido de todos estos checks se va a llamar a la funcion **SepCreateAccessStateFromSubjectContext** que como su propio nombre indica nos devolvera un Objeto [ACCESS_STATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_access_state) (En el parametro pasado en ```rdx```) en base al contexto de quien ha realizado la peticion. (Esta funcion pertenece al componente ["Security Reference Monitor"](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-security-reference-monitor) que es el que se encarga de comprobar que antes de realizar una accion se tienen los permisos requeridos, estas funciones se distingue por el prefijo **Se**)

El siguiente paso, es quiza uno de los mas importantes en este proceso, se llama a la funcion **ObpLookupObjectName** que como el nombre indica, va a buscar el Objeto por su nombre (EL nombre de la DLL en este caso). Con solo mirar el grafico de la funcion sabemos que es importante 🤣

<img src="/images/loadLibrary/graph.jpg" alt="ObpLookupObjectName Graph" style="margin:auto; width:50%"/>

Algo importante para entender esta funcion es saber los parametros que recibe, muchas de las funciones que encontramos en el kernel no esta documentadas. Por tanto, nuestras mejores opciones son o reversear hasta este punto e intentar comprender que parametros se le estan pasando o buscar esta funcion en el proyecto [ReactOS](https://reactos.org/) que es un super proyecto que os recomiendo que investigueis, es una especie de Windows Open Source y el Kernel se parece bastante al de Windows. Para que os hagais una idea seria algo asi:

<a name="params_obp">
<img src="/images/loadLibrary/params_obplookupobjectname.jpg" alt="Params ObpLookupObjectName" style="margin:auto;"/>
</a>

Una vez dentro de la funcion, lo primero que se hara es inicializar la estructura [OBP_LOOKUP_CONTEXT](https://doxygen.reactos.org/dd/d94/struct__OBP__LOOKUP__CONTEXT.html), por otro lado mediante la llamada **ObReferenceObjectByHandle** se obtendra el objeto de tipo "Directory" llamado "KnownDlls", este objeto contiene una lista de Objetos de tipo seccion con el nombre de la DLL a la cual corresponde esa seccion 

> **Spoiler:** Como podeis ver en el call stack antes de entrar al kernel, la funcion que llama a **NtOpenSection** se llama **LdrpFindKnownDll** por tanto si la DLL que se esta buscando no se encuentra en esta lista la llamada devolvera un error como veremos a continuacion, y mas adelante veremos el caso contrario)

![alt img](/images/loadLibrary/known_dlls.jpg "Known DLLs")

a continuacion, se va a proceder a calcular un Hash con el Nombre de la DLL y se va a comprobar si este Hash coincide con alguno de los Hashes de las DLLs que se encuentran entre las "KnownDlls", en caso de no ser asi se va a proceder a retornar el valor "c0000034" que se corresponde con el msj de error "Object Name not found." A partir de aqui el flujo consiste en limpar las referencias a objetos (Mediante la funcion **ObfDereferenceObject**)

![alt img](/images/loadLibrary/error_name.jpg "Error c0000034")

y lo mismo sucedera al salir de esta funcion, se procedera a borrar el ACCESS_STATE creado anteriormente y limpar mas estructuras que no he mencionado por no hacer esto muy denso. Finalmente se volver a Userland con el valor "c0000034" y se actuara en consecuencia, pero esto lo veremos en la Parte 2.

> **Otro Spoiler:** Basicamente se va a buscar el path de la DLL y se va a llamar a la funcion NtOpenFile, para que os hagais una idea de por donde van los tiros

### KnownDll

Ahora vamos a estudiar el mismo caso pero suponiendo que la DLL se encuentra dentro de las KnownDlls. Para esto podemos añadir la DLL "kerberos.dll" a la lista de KnownDlls, dicha lista se encuentra en la siguiente clave de registro ```*HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\KnownDLLs*```

> **NOTA!** Tened en cuenta que a esta clave de registro no se puede editar como usuario sin privilegios, por tanto tendreis que hacerlo como administrador o cambiando los permisos de la clave

En la siguiente imagen podeis ver como la DLL de Kerberos se ha cargado como una KnownDll (No me hagais mucho caso porque no he investigado mucho, pero creo que el nombre tiene que ser en mayusculas ya que a la hora de calcular el Hash el nombre de la DLL se pasa a mayusculas, tengo que investigar porque hay ciertas DLLs en las que no es necesario por ejemplo: kernel32.dll)

<a name="kerberos">![alt img](/images/loadLibrary/kerberos_knowndll.jpg "Kerberos KnownDll")</a>

Y en la siguiente imagen, haciendo un Fast-Forward podeis ver como la llamada a **ObpLookupObjectName** esta vez ha devuelvo 0 como NTSTATUS.

![alt img](/images/loadLibrary/return_knowndll.jpg "Sucessfull ObpLookupObjectName")

Para esta parte vamos a comenzar directamente desde la funcion **ObpLookupObjectName**, mas concretamente desde donde se calcula el Hash (El proceso hasta este punto es identico para ambos casos que estamos estudiando). En este caso si que vamos a estudiar como se calcula el hash. En el siguiente Pseudocodigo podemos mas o menos ver como se calula

> **NOTA!** Esta es una funcion sin documentar, por tanto es posible que cambie de una version de Windows a otra, incluso de un SP a otro. En este caso yo estoy ejecutando con la siguiente version **Windows 8.1 Kernel Version 9600 MP (2 procs) Free x64**

```cpp
// El merito aqui es de Hex-Rays xD
QWORD res = 0;
DWORD hash = 0;
DWORD size = Dll.Length >> 1;
PWSTR dll_buffer = unicode_string_dll.Buffer;

if (size > 4) {
    do {
        QWORD acc = dll_buffer;
        if (!(Dll_Buffer & ff80ff80ff80ff80h))
            acc = (QWORD *) Dll_Buffer & ffdfffdfffdfffdfh;
        }
        /* Realmente ese codigo se ejecuta en un else y el caso del 
        if seria un while que va elemento a elemento restando 20h a 
        los elementos que se encuentran entre 61h y 7Ah, pero 
        logicamente esto es mucho mas lento */
        size -= 4;
        dll_buffer += 4;
        res = acc + (res >> 1) + 3 * res;
    } while (size >= 4)
    hash = (DWORD) res + (res >> 20h)
    /* En el caso de que el size no sea multiplo de 4 se haria 
    una ultima iteracion como la que se ha explicado antes */
}

obpLookupCtx.HashValue = hash;
obpLookupCtx.HashIndex = hash % 25;
```

Si realizais esta operacion para "kerberos.dll", con algo de suerte, vereis que el HashIndex que os da es ```20h``` que se corresponde con 32 en decimal, si vais a la imagen mas arriba donde se ve el que esta DLL esta en la lista de [KnownDlls](#kerberos) y mirais el campo Hash de la tabla podeis ver que coincide. A partir de aqui se comprueba que el hash de la seccion en ese index coincide con el que se ha calculado y se ha escrito en la estructura ```OBP_LOOKUP_CONTEXT``` 

![alt img](/images/loadLibrary/directory_entry.jpg "Hashes Match")

Si esta primera comprobacion ha ido bien se obtiene la estrucutura ```OBJECT_HEADER_NAME_INFO``` mediante la formula ```ObjectHeader - ObpInfoMaskToOffset - ObpInfoMaskToOffset[InfoMask & 3]```, de aqui se obtiene el nombre y en resumidas cuentas se comprueba que el nombre del objeto coincida con el que hemos pasado como parametro a la funcion LoadLibrary (Para esta comprobacion el nombre en minusculas se pasa a mayusculas). Si todo esto ha ido bien se proceden a rellenar el campo Object y el campo EntryLink de la estructura ```OBP_LOOKUP_CONTEXT``` y finalmente despues de alguna comprobacion mas se copiara el puntero del objeto al argumento de salida y se retornara de la funcion. Esta funcion tiene dos argumentos de salida uno el puntero al objeto y otro un puntero a la estructura ```OBP_LOOKUP_CONTEXT```

![alt img](/images/loadLibrary/return_obplookupobjectname.jpg "return ObpLookupObjectName")

Si observais los argumentos que recibe esta funcion ([aqui](#params_obp)) el FoundObject se encontrara en ```rsp+68h``` mientras que la estructura ```OBP_LOOKUP_CONTEXT``` se encontrara en ```rsp+48h```. Fijaro que el objeto no tiene ningun handle abierto, esto sucedera en la ultima funcion que vamos a estudiar hoy **ObpCreateHandle** esta funcion sera la encargada de obtener un handle a dicho objeto.

Esta funcion tambien tiene muchisimo codigo, y como esto ya es bastante largo no voy a entrar tan en detalle como con la funcion anterior (En otra entrada quiza pueda profundizar en esta funcion que tiene lo suyo tambien).

Los argumentos mas importantes que recibe **ObpCreateHandle** son en ```rcx``` recibira un valor de la enum ```OB_OPEN_REASON```, este valor puede ser uno de los siguientes:
```cpp
ObCreateHandle      =   0
ObOpenHandle        =   1
ObDuplicateHandle   =   2
ObInheritHandle     =   3
ObMaxOpenReason     =   4
```
luego en ```rdx``` se recibira la referencia al objeto en cuestion, en ```r9``` se recibira un puntero a una estructura ACCESS_STATE esta estructura entre otras cosas contiene la ACCESS_MASK con los permisos solicitados.

Con todo esto, y teniendo en cuenta que en ```rcx``` se pasa el valor ObOpenHandle, lo primero que hara la funcion sera comprobar si el manejador es para un [kernel handle](https://docs.microsoft.com/en-us/windows/desktop/sysinfo/kernel-objects) o no, en caso de que no sea asi se obtendra la tabla de manejadores del proceso de la siguiente manera ```KTHREAD->ApcState->Process->(EPROCESS) ObjectTable``` despues de algunas comprobaciones se va a llamar a la funcion [**ExAcquireResourceSharedLite**](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-exacquireresourcesharedlite) para obtener el recurso referente al PrimaryToken (Por recursos en el Kernel no se entiende lo mismo que en Userland, aqui hablamos de la estructura ERESOURCES y vendrian a ser una especie de Mutex podeis leer mas sobre esto [aqui](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-eresource-routines))

Si se ha obtenido el Recurso se llama a la funcion [**SeAccessCheck**](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-seaccesscheck), esta funcion se encarga de determinar si se tiene permisos para acceder al objeto o no. Si se tiene los permisos se terminara por llamar a la funcion **ObpIncrementHandleCountEx**, que es la encargada de aumentar la cuenta de manejadores abiertos tanto para este objeto como para la cuenta general del tipo "Section" (Solo se aumenta el contador, el manejador todavia no esta abierto lo podeis comprobar en windbg si haceis ```!object [objeto]``` el valor HandleCount esta a 1, pero si mirais los manejadores del proces ```!handle``` no vereis la referencia a este manejador)

Por utlimo se procede a abrir el manejador, para ahorrarnos tiempo voy a poner el pseudocodigo añadiendo comentarios para que se entienda que esta pasando (Otra vez patrocinado por Hex-Rays 🤣) 

```cpp
// Voy a simplificar, no hay ni checks ni casts
HANDLE_TABLE * HandleTable = {};
HANDLE_TABLE_ENTRY * NewHandle = {};
HANDLE_TABLE_FREE_LIST * HandlesFreeList = {};

// Se obtiene una referencia al objeto y sus atributos (rsp+28h), para
// obtener el objeto se utiliza la cabecera (OBJECT_HEADER) que se
// obtiene a partir del objeto menos 30h (OBJECT_HEADER+30h == Body) 
QWORD LowValue = 
    (((DWORD) Attributes & 7 << 11) | (Dll_object - 30h << 10) | 1)
// Se obtiene el tipo de objeto, a partir del objeto
// menos el Offset del tipo (OBJECT_HEADER+18h == TypeIndex)
HIDWORD(HighValue) = Dll_Object - 18h
// Se obtienen los permisos con los que ha sido requerido el objeto
LODWORD(HighValue) = ptrAccessState.PrevGrantedAccess & 0xFDFFFFFF;
// Se obtiene la HandleTable del proceso
HandleTable = KeGetCurrentThread()->ApcState.Process->ObjectTable;
// Se calcula el indice en base al numero de procesador  
indexTable = Pcrb.Number % nt!ExpUuidSequenceNumberValid+0x1;

// Se obtiene la lista de Handles libres
HandlesFreeList = HandleTable->FreeLists[indexTable];
if(HandlesFreeList) {
    Lock(HandlesFreeList); // Realmente es mas complejo
    // Se obtiene el primer handle libre
    NewHandle = HandlesFreeList->FirstFreeHandleEntry;
    if (NewHandle) {
        // Se hace que la lista de manejadores libres
        // apunte al siguiente manejador libre
        tmp = NewHandle->NextFreeHandleEntry;
        HandlesFreeList->FirstFreeHandleEntry = tmp;
        // Se aumenta el contador de handles abiertos
        ++HandlesFreeList->HandleCount;
    }
    UnLock(HandlesFreeList);
}

if (NewHandle) {
    // Se obtiene el valor del handle para devolverlo 
    tmp = *((NewHandle & 0xFFFFFFFFFFFFF000) + 8)
    tmp1 = NewHandle - (NewHandle & 0xFFFFFFFFFFFFF000) >> 4;
    HandleValue = tmp + tmp1*4;
    // Se asignan los valores correspondientes al handle
    // para que sepa a que objeto apunta, que tipo de objeto es
    // y que permisos tiene
    NewHandle->LowValue = LowValue;
    NewHandle->HighValue = HighValue;
}
```

La funcion devolvera el manejador en ```rsp+48```. Y para finalizar, como es logico, se limpia todo el estado (Estructuras, Single Lists, Access States, etc..) y se retorna a Userland (**LdrpFindKnowDll**) con el manejador y el STATUS igual a 0.

![alt img](/images/loadLibrary/handle.jpg "Created Handle")

> Este manejador no tiene nada que ver con el manejador que va a devolver la funcion LoadLibrary, es mas, la DLL todavia no esta cargada en el espacio de memoria del programa. Esto lo veremos en la segunda parte, donde se usara este manejador para, ya de una vez por todas, cargar la DLL en la memoria del proceso.

## Conclusiones

Ya veis la cantidad de codigo y lo complejo que es el kernel, y esto es algo relativamente sencillo... ya iremos viendo cosas mas complejas 😀😀. Por otro lado, me he dejado **mucho** codigo, estructuras, listas enlazadas, etc... sin comentar, no me mateis pero tenia que resumir en la medida de lo posible. Igual que siempre si teneis alguna duda o hay algo que este mal no dudeis en contactarme (Es gratis!!). 
Eso ha sido todo! Espero que os haya gustado y nos vemos en la segunda parte!! Hasta la proxima!! 🤪🤪

[@n4r1b](https://www.twitter.com/n4r1b)
