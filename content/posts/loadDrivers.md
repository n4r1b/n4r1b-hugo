+++
categories = ["OS Loader", "ELAM", "OslLoadDrivers"]
tags = ["OS Loader", "OslLoadDrivers", "ELAM"]
date = "2019-03-24"
description = "Pequeña explicacion sobre como el Loader del SO se encarga de cargar los drivers esenciales, centrandonos en el ELAM Driver"
images = ["https://n4r1b.netlify.com/images/oslLoadDrivers/oslLoadDrivers.jpg"]
featured = ["https://n4r1b.netlify.com/images/oslLoadDrivers/oslLoadDrivers.jpg"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "Como carga los Drivers esenciales el BootLoader"
slug = "Como carga los Drivers esenciales el BootLoader"
type = "posts"
+++

Hola otra vez! Esta vez vamos a ver algo anterior al Kernel (Si! hay vida antes del Kernel 😅), mas especificamente vamos a ver como durante el proceso de carga del SO se cargan en memoria los drivers que Windows necesita para poder comenzar su ejecucion. Y para el estudio voy a centrarme en un Driver en especifico, el Early Launch Anti-Malware Driver, mas conocido como ELAM. La motivacion principal es que mas adelante quiero hacer una entrada explicando y hablando a fondo de como este Driver ayuda a proteger al sistema de posibles Rootkits.

## Bootloader
Una vez el Boot Manager termina de cargar el Loader del SO le pasa el control y este se encargara de cargar gran parte de los componentes del Kernel de Windows, finalmente la ejecucion pasara al Kernel y a partir de este punto es cuando comienza a ejecutar Windows como tal. 

> Dado que UEFI es el estandar actual para el arranque del sistema voy a centrarme en el bootloader de windows para EFI (**winload.efi**)

<img src="/images/oslLoadDrivers/bcdedit.jpg" alt="bcdedit EFI" style="margin:auto;"/>

Para poder debugear este proceso tendremos que activar la opcion ```/bootdebug``` en la entrada correspondiente al Bootloader de Windows mediante el comando ```bcdedit.exe``` (Comando para editar las entradas del **Boot Configuration Data**). Una vez activada esta opcion si reiniciamos la maquina con una sesion de debugging remoto podremos ver como se activa un punto de ruptura dentro de la funcion ```BlBdStart``` (Intuyo que el prefijo viene de BootLoader BootDebug) y es la funcion que se encarga de comprobar la conexion a la maquina remota y de cargar los simbolos para poder debugear ```DbgLoadImageSymbols```. La funcion ```BlBdStart``` a su vez viene de  ```BlBdInitalize``` que es la encargada de inicializar los componentes para poder hacer debugging, esta funcion viene a su vez de la funcion de inicializacion principal ```InitializeLibrary``` que es la encargada de inicializar todo lo necesario para poder ejecutar el Loader del SO y aqui hayamos funciones como:

- ```PltInitializePciConfiguration```
- ```SpaceBootInitialize```
- ```BlNetInitialize```
- ```BlpIoInitialize```

Los nombres son bastante descriptivos por lo que no voy a entrar en detalles de cada una. Finalmente, saliendo de toda esta inicializacion llegamos al codigo principal del Bootloader (Funcion ```OslMain```), que llamara a la funcion ```OslpMain``` y esta si es la encargada de todo el proceso de carga del SO.
 
Esta funcion tiene que realizar dos tareas fundamentales, la primera cargar el SO (```OslPrepareTarget```) y la segunda ejecutar la transicion al SO cargado recientemente (```OslExecuteTransition```). En esta entrada solo hablare de la primera funcion y a grandes rasgos, como podreis imaginar tiene bastante codigo 🤣🤣. El proceso de carga del Kernel podra variar segun las opciones que se tengan activadas en el **BCD** y para determinar si una opcion esta activa se utiliza la funcion ```BcdUtilGetBootOption``` esta funcion es relativamente importante por tanto vamos a ver como funciona de forma rapida:

<img src="/images/oslLoadDrivers/bcdGetOption.jpg" alt="BcdUtilGetBootOption pseudocode" style="margin:auto;"/>

Como podeis ver solo consiste en recorrer una estructura y comparar si el tipo que se busca (Por tipo se entiende opcion) se encuentra entre las opciones de la configuracion de arranque. La estructura que se utiliza es la siguiente (Todo el credito para [ReactOS](https://doxygen.reactos.org/d5/d8b/struct__BL__BCD__OPTION.html))

```cpp
struct _BL_BCD_OPTION
{
  ULONG Type;
  ULONG DataOffset;
  ULONG DataSize;
  ULONG ListOffset;
  ULONG NextEntryOffset;
  ULONG Active;
};
```
> Para obtener el nombre correspondiente con las constante que se pasa como tipo podemos buscarlo en la documentacion de [Microsoft](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bcd-settings-and-bitlocker) y si no lo encotramos ahi podemos buscar en la **increible** pagina de [Geoff Chappell](https://www.geoffchappell.com/notes/windows/boot/bcd/elements.htm)

## OslpLoadAllModules

Hacemos un fast-forward y pasamos directamente a la funcion que se va a encargar de cargar todo lo necesario para el arranque del SO (```OslpLoadAllModules```) , esta funcion tiene bastante tralla pero voy a intentar resumir hasta llegar al punto que me interesa.

Primero obtiene las Flags de arranque (```OslpGetBootDriverFlags```), luego comprueba si esta activo el paginamiento de 5 niveles (Si es el kernel que se carga es **ntkrla57.exe**), comprueba si las opciones de arranque ```BCDE_OSLOADER_TYPE_KERNEL_PATH``` y ```BCDE_OSLOADER_TYPE_HAL_PATH``` (Si es asi cargara la string indicada en esa opcion), se comprobara la arquitectura de la maquina para saber si tiene que cargar el Driver de actualizaciones de AMD o de Intel 

> Estos Drivers que tienen el nombre **mcupdate_[OsArch]** basicamente contienen el microcodigo con las actualizaciones especificas para dicha CPU, si teneis el PC actualizado y veis que la fecha de modificacion de ambas DLLs (Estan en System32) no coincide probablemente algun KB haya actualizado el Driver correspondiente a vuestra arquitectura. Vease como ejemplo https://support.microsoft.com/en-us/help/4465065/kb4465065-intel-microcode-updates

Volviendo a la funcion, a continuacion reservara espacio para alojar el Kernel y el Hal, y se procedera a cargarlos mediante la llamada a ``OslLoadImage``, lo siguiente es cargar el ApiSetSchema, se busca la seccion ```.apiset``` de la DLL ```apisetschema.dll``` y a partir de esa seccion se crea (```ApiSetCreateSchema```) y compone (```ApiSetComposeSchema```) el esquema. Luego se comprueba si esta activo el Kernel Debugging o el Event Logging, y en caso de ser asi se cargan las DLLs relacionadas con KD. A continuacion se comprobara la flag LastGoodSettingFlag (Solo voy a hablar del caso que no se toma el salto) en caso de no tomarse el salto se procede a cargar del Driver *mcupdate.dll* que es el nombre generico que se usa a pesar de que se solo se carga la que va acorde con la CPU. Despues y ya casi uno de los ultimos pasos antes de comenzar a cargar los Drivers, es buscar las Extensiones del SO si las hubiera, para esto se va a buscar la firma *CSRT* en la tabla ACPI 

> Esa firma corresponde con la tabla *Core System Resources Table*, y basicamente si el sistema tiene algun *Core System Resource* (Controladores DMA, Controlador de Interrupciones, etc...) que no sea estandar debe estar indicado en esta tabla y por tanto la *Root System Description Table* (RSDT) debe tener un puntero a esta *System Description Tables* (SDT).
En este [enlace](https://uefi.org/sites/default/files/resources/CSRT%20v2.pdf) teneis mas informacion sobre esta tabla 

<a name="go_back"></a>
Por ultimo se van a cargar los Drivers de los cuales *ntoskrnl.exe* y *hal.dll* importan funciones y esto es lo que quedaria en el miembro *LoadOrderListHead* del [`LOADER_PARAMETER_BLOCK`](#loader_param_block_notes) (Esta estructura es BASTANTE importante en las notas hablo de ella mas en dellates, no estaria mal leerlo antes de seguir 😅)

<img src="/images/oslLoadDrivers/modules_loaded_before_drivers.jpg" alt="LoadOrderListHead" style="margin:auto;"/>

> Os voy a decir una tecnica que os va a salvar la vida si vais a debugear el Bootloader. Todos estos modulos han sido cargados pero tanto la llamada `OslLoadImage` como la llamada `OslLoadDrivers` no cargan los simbolos (Es decir no llaman a `DbgLoadImageSymbols`) por tanto no tendremos los simbolos de ninguno de estos modulos, y la verdad que los simbolos del modulo **ntoskrnl** vienen bastante bien 🤣. Pero WinDBG nos da la posibilidad de cargar los simbolos y como sabemos la base (La podemos obtener del `LOADER_PARAMETER_BLOCK` podemos cargar los simbolos que queramos. 

> El comando es `.reload /f /i [NombreDelModulo]=[BaseDelModulo]`
> 
> <video style="margin-top:10px" width="100%" controls>
  <source src="/videos/oslLoadDrivers/video_reload.mov" type="video/mp4">
</video>


## Carga de los Drivers

En este apartado hablare finalmente de como se cargan los Drivers. Continuamos en la funcion ```OslpLoadAllModules```, como ya mencione al principio voy a centrarme en como se carga el ELAM Driver (Y con esto ya acabo por hoy 😅) pero se puede extrapolar a los otros drivers (Si hay algo exclusivo del ELAM lo mencionare)

La primera funcion necesaria para cargar los drivers es ```OslGetBootDrivers```, que lo primero que hara sera obtener la lista de Drivers que se van a cargar, esta lista se obtiene dentro de la funcion ```OslHiveFindDrivers```, que principalmente llama a ```CmpFindDrivers``` que va a cargar la Celda de Datos (```_CELL_DATA```) de la clave *Service* dentro del *CurrentControlSet*, despues cargara la Celda de Datos de la subclave *GroupOrderList* dentro la clave *Control* del *CurrentControlSet*, con estas dos Celdas se comienza a recorrer los elementos de la clave *Service* y mediante la funcion ```CmpIsLoadType``` se comprobara si la entrada tiene la clave *Start* y si el valor de esta clave es ```0x0```, en caso de que sea asi se procede a iniciliazar la ```_BOOT_DRIVER_LIST_ENTRY``` mediante la funcion ```CmpAddDriverToList```, esta funcion basicamente va a leer los datos de la entrada y va a ir rellenando la estructura. Y asi se procede con todos los elementos dentro de ```HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services``` y finalmente tendremos el miembro *BootDriverListHead* del ```LOADER_PARAMETER_BLOCK``` con todos los drivers que se van a cargar.

> El elemento *BootDriverListHead* no he conseguido encontrar una estructura que lo representara (Si alguien la conoce que me lo diga!), lo mas parecido es la estructura [_BOOT_DRIVER_LIST_ENTRY](https://doxygen.reactos.org/d2/d92/struct__BOOT__DRIVER__LIST__ENTRY.html) de ReactOS, pero parece haber variado un poco o no estar completa, segun lo que he podido ver seria algo asi:
```cpp
struct _BOOT_DRIVER_LIST_ENTRY 
{
    LIST_ENTRY Link;
    UNICODE_STRING PathToDriver;
    UNICODE_STRING RegistryPath;
    PLDR_DATA_TABLE_ENTRY DriverLdrTableEntry;
    ULONG DriverLoadNtStatus;
    ULONG Unknown; /* Se obtiene en la funcion ImgpValidateImageHash, 
                      creo que tiene esta relacionado con Device Guard o con 
                      la integridad del codigo (Ya lo investigare xD) */  
    PHHIVE Hive;
    UNICODE_STRING HiveName;
    UNICODE_STRING DriverDependencies;
    UNICODE_STRING DriverGroup;
    UNICODE_STRING DriverRootName;
    ULONG DriverTag;
    ULONG DriverErrorControl;
}
```

A continuacion se cargaran, en el caso de que haya, los Drivers que son necesarios como dependencias (Se comprueba que existe la subclave *PendingDriverOperations*) y finalmente, mediante la funcion ```CmpSortDriverList```, se ordena la lista de Drivers segun el orden estableccido en el valor de *List* dentro de la subclave *ServiceGroupOrder* en la clave *Control* del hive System 🤣.

> Esto que he explicado tampoco tiene ninguna ciencia, Microsoft lo explica (No con tanto detalle) en el siguiente articulo https://docs.microsoft.com/en-us/windows-hardware/drivers/install/specifying-driver-load-order


Finalmente la lista quedaria algo asi (El comando para obtener la lista es muy simple pero por si a alguien le viene bien es el siguiente ```r @$t0=[Direccion de BootDriverList]; r @$t1=[Direccion de BootDriverList.Link]; .while(@$t0 != @$t1) {dS /c 80 @$t1+10; r @$t1=poi(@$t1)}```)

![alt img](/images/oslLoadDrivers/BootOrderedList.jpg "Boot Ordered List")

A continuacion se van a aplicar dos filtros, uno por grupo (```OslpFilterDriverListOnGroup```) al que se le pasara la string **Early-Launch**, este sera el que copie el ELAM Driver de la *BootDriverListHead* al miembro *EarlyLaunchListHead*. En la imagen podeis ver como el Driver **WdBoot.sys** (ELAM Driver de Windows Defender) peretence el grupo Early-Launch (Intuyo que si mirais Drivers de otros AVs tambien pertenencen a este grupo)

![alt img](/images/oslLoadDrivers/wdboot.jpg "Boot Ordered List")

El siguiente filtro, esta vez por Servicio (```OslpFilterDriverListOnServices```) se ejecutara dos veces, en primera instancia para copiar los **CoreDrivers** de la *BootDriverListHead* a la *CoreDriverListHead*, se compara el **DriverRootName** con los siguientes nombres (Estan en la seccion .rdata del binario):

- VERIFIEREXT
- WDF01000
- ACPIEX
- CNG
- MSSECFLT
- SGRMAGENT
- LXSS
- PALCORE

A continuacion se aplica el mismo filtro pero en este caso para los **TmpCoreDrivers** y por ultimo se aplica este mismo filtro para los **Extension Drivers** (Platform y Security) y con esto ya estaria todo listo para empezar a cargar los Drivers.

### OslLoadDrivers

Bueno, ahora si que si! La carga de los Drivers en cuestion. Primero se cargaran los **Core Drivers**, luego los **TmpCore Drivers** y a continuacion se pasa a los **ELAM Drivers**, antes de cargar el ELAM Driver se va a comprobar que la opcion de arranque ```0x260000E1```(BCDE_OSLOADER_TYPE_DISABLE_ELAM_DRIVERS) no este activada, esta opcion basicamente deshabilita estos Drivers. Si no esta activada se procede a llamar a la funcion ```OslLoadDrivers```, esta funcion basicamente va a generar el full path del driver uniendo el path del driver con el SystemPath mediante la llamada a ```BlLdrBuildImagePath``` y a continuacion llama a ```OslLoadImage``` y a partir de aqui basicamente se van pasando los parametro a funciones mas internas tal que el Stack seria al siguiente una vez se llega a la que realmente carga el driver:

![alt img](/images/oslLoadDrivers/stack_osload.jpg "Call Stack OS Load")

Como podeis ver la funcion principal es ```LdrpLoadImage```, y es en la que me voy a centrar (En realidad en las funciones a las que llama 🤣🤣). Lo primero que va a comprobar esta funcion es si el Driver que se quiere cargar ya se encuentra en la tabla ```LDR_DATA_TABLE```, basicamente se pasa la tabla y el nombre del Driver a cargar a la funcion ```BlLdrFindDataTableEntry``` y se itera sobre la tabla comprobando el nombre, en el caso de que no se encuentre (Me voy a centrar en este caso) se van a procesar las *Flags* del binario con la funcion ```OslpLdrExProcesssImageFlags``` (Esta funcion se obtiene a partir de una especie de vTable que contiene funciones para ayudar en el proceso de carga)

![alt img](/images/oslLoadDrivers/vtable.jpg "Load Process vTable")

Despues de procesar las *Flags*, por fin llegamos a la funcion que va a escribir el Driver en memoria, esta funcion es ```BlImgLoadPEImageEx```, esta funcion lo primero que hara sera abrir un *handle* al fichero mediante la llamada a ```ImgpOpenFile```

> Le llamo Handle, pero en realidad es una estructura que en ReactOS le llaman [`_BL_IMG_FILE`](https://doxygen.reactos.org/d4/d94/struct__BL__IMG__FILE.html) y entre otras cosas tiene el *FileName* y el *FileSize*

y a continuacion llama a la funcion ```ImgpLoadPEImage``` que como podeis ver por el nombre va a cargar el PE, voy a comentarla un poco por encima pero se siguen los pasos para cargar un PE igual que en userland (**NOTA:** No voy a entrar en todo el tema de Firma Digital y Checksum porque es bastante denso y pienso hablar de ello en otra entrada). Bueno vamos a ello, la funcion primero obtiene los atributos de la imagen (```BlFileGetInformation```) a continuacion se carga la cabecera NT y se van a comprobar principalmente tres cosas:

- ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64
- ntHeaders->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION
- ntHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY

si se cumplen se obtiene el tipo de hash que se utiliza para la integridad de la imagen (```0x8004``` -> ```CALG_SHA_256```), despues se va a obtener el tamaño de la imagen (En memoria) y se va a reservar este espacio (Ahora mismo la imagen esta en memoria tal cual esta en disco) ya con esto se hace el tipico procedimiento de iterar sobre las secciones e ir copiandolas (Tamaño Virtual). Una vez se tiene la imagen mapeada en memoria se va a proceder a comprobar que el digest coincide (Como ya he dicho anteriormente de esto hablare en otra entrada), luego se relocaran los *offsets* necesarios (```LdrRelocateImage```) y se obtendra la direccion fisica de la imagen (Todavia no tengo muy claro para que hace esto, si alguien lo sabe que me lo diga porfavor)

![alt img](/images/oslLoadDrivers/physical_address.jpg "Physical Address Image")

Y eso seria basicamente todo (Me he saltado mucho! Pero teneis el nombre de la funcion y si estais leyendo esto imagino que teneis IDA!! 😉😉). Bueno logicamente, esta funcion va a liberar toda la memoria que ha reservado (Obviamente no libera la imagen que acaba de cargar 🤣) y va a cerrar el Handle del fichero.

Una vez esta funcion acaba ya queda poco para terminar con el proceso, se obtiene el *SymbolicPath* (Basicamente pasar de ```\Windows\``` a ```\SystemRoot\``` y esto quiza os suene de ```%SYSTEMROOT%```) y a continuacion, se añade el Driver cargado a la tabla ```LDR_TABLE_ENTRY```, en este punto realizar esto es bastante trivial puesto que ya se tiene toda la informacion que se necesita por tanto no voy a entrar en mucho detalle y como una imagen vale mas que mil palabras os dejo una imagen de IDA y con eso mas o menos veis por donde van los tiros (La funcion que se encarga de esto es ```BlLdrAllocateDataTableEntry```)

![alt img](/images/oslLoadDrivers/add_data_table_entry.jpg "Add entry LDR_TABLE")

Finalmente se van a colocar el *Flink* y el *Blink* de la ```LIST_ENTRY``` de forma que apunten a la entrada anterior y al principio de la la lista y se va a proceder a cargar los imports del Driver que se ha cargado. De esto se va a encargar la funcion ```LdrpLoadImports``` que no voy a detallar porque funciona igual en Userland, para que os hagais una idea obtiene el ```IMAGE_DATA_DIRECTORY``` de la tabla de imports y con esto obtiene el ```IMAGE_IMPORT_DESCRIPTOR``` y a continuacion itera llamando a ```LdrpLoadImage``` para cargar la imagen y a ```BlLdrBindImportReferences``` para enlazar los imports al binario y eso seria todo, ahora se empezaria a salir de las funciones hasta volver a la funcion ```OslLoadDrivers``` que es la encargada  de asignar el campo *DriverLoadNtStatus* y se devuelve el *NTSTATUS* correspondiente a la funcion que ha intentado cargar el Driver (En este caso ```OslpLoadAllModules```) 

Aqui podeis ver como quedaria la estructura _BOOT_DRIVER_LIST_ENTRY una vez se ha cargar el ELAM Driver de Windows:

![alt img](/images/oslLoadDrivers/boot_driver_entry.jpg "Boot Driver entry")

Siento mis dotes con el Paint, si haceis zoom se ven mejor los colores!! El DriverTag es 0xFFFFFFFF porque el Driver WdBoot no tiene clave DriverTag en el registro.

## Conclusiones

Esto ha sido todo por hoy, debajo dejare unas Notas que quiza os interese leer si quereis entender mejor ciertas cosas. Como ya he comentado me gustaria hablar del ELAM de Windows en una proxima entrada y espero que esto os haya levantado algo de curiosidad por este Driver y en general por el Bootloader de Windows.

Como siempre, espero que os haya gustado y que no se os haya hecho muy pesado!! Si teneis cualquier duda no dudeis en poneros en conctacto conmigo! (Es gratis 🤣🤣) y se que he dejado muchisimas cosas de lado y quiza cosas sin explicar que he dado por echo, pero creedme que el Bootloader tiene muchisimo codigo y para que engañarnos cosas bastante complejas 🤣 por eso he intentado centrarme en ciertos puntos que me parecian interesantes. Y si he metido la pata en algo, por favor, decidmelo sin problema! (Podeis hasta meteros conmigo si os hace ilusion y tambien es gratis!!)

## Notas
Aqui voy a comentar un par de temas que he dejado sin explicar arriba porque no eran del todo relevantes para el articulo en si, pero creo que si que son interesantes y no esta de mas comentarlos un poco.

<a name="loader_param_block_notes">
#### LOADER_PARAMETER_BLOCK
</a>
El [```LOADER_PARAMETER_BLOCK```](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/loader_parameter_block.htm) es posiblemente la estructura mas importante en el Bootloader. En esta estructura se ira recopilando informacion durante el proceso de carga del SO y posteriormente toda esta informacion sera pasada al Kernel y al HAL (Se guarda una referencia en la variable ```KeLoaderBlock```). Por suerte, Microsoft ha cambiado de parecer con esta estructura y parece ser que desde la version **Windows 10 1803 Redstone 4 (Spring Creators Update)** han decidido hacer publica esta estructura en un fichero de cabecera (Antes estaba en los simbolos, pero no en un Header file)
```
kd> dt nt!_LOADER_PARAMETER_BLOCK
   +0x000 OsMajorVersion   : Uint4B
   +0x004 OsMinorVersion   : Uint4B
   +0x008 Size             : Uint4B
   +0x00c OsLoaderSecurityVersion : Uint4B
   +0x010 LoadOrderListHead : _LIST_ENTRY
   +0x020 MemoryDescriptorListHead : _LIST_ENTRY
   +0x030 BootDriverListHead : _LIST_ENTRY
   +0x040 EarlyLaunchListHead : _LIST_ENTRY
   +0x050 CoreDriverListHead : _LIST_ENTRY
   +0x060 CoreExtensionsDriverListHead : _LIST_ENTRY
   +0x070 TpmCoreDriverListHead : _LIST_ENTRY
   +0x080 KernelStack      : Uint8B
   +0x088 Prcb             : Uint8B
   +0x090 Process          : Uint8B
   +0x098 Thread           : Uint8B
   +0x0a0 KernelStackSize  : Uint4B
   +0x0a4 RegistryLength   : Uint4B
   +0x0a8 RegistryBase     : Ptr64 Void
   +0x0b0 ConfigurationRoot : Ptr64 _CONFIGURATION_COMPONENT_DATA
   +0x0b8 ArcBootDeviceName : Ptr64 Char
   +0x0c0 ArcHalDeviceName : Ptr64 Char
   +0x0c8 NtBootPathName   : Ptr64 Char
   +0x0d0 NtHalPathName    : Ptr64 Char
   +0x0d8 LoadOptions      : Ptr64 Char
   +0x0e0 NlsData          : Ptr64 _NLS_DATA_BLOCK
   +0x0e8 ArcDiskInformation : Ptr64 _ARC_DISK_INFORMATION
   +0x0f0 Extension        : Ptr64 _LOADER_PARAMETER_EXTENSION
   +0x0f8 u                : <unnamed-tag>
   +0x108 FirmwareInformation : _FIRMWARE_INFORMATION_LOADER_BLOCK
   +0x148 OsBootstatPathName : Ptr64 Char
   +0x150 ArcOSDataDeviceName : Ptr64 Char
   +0x158 ArcWindowsSysPartName : Ptr64 Char
```
Esto aplica para la siguiente version de Windows:
**Windows 10 Kernel Version 17763.1.amd64fre.rs5_release.180914-1434** y en este [enlace](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1809%20Redstone%205%20(October%20Update)/_LOADER_PARAMETER_BLOCK) lo teneis en formato struct de C

Si venis de el enlace que he puesto arriba [pulsad aqui](#go_back) y subis de nuevo! (Si no venis de ahi, omitid esto 🤣🤣)

<a name="system_hive_notes">
#### SystemHive
</a>
La funcion encargada de cargar el [Hive](https://docs.microsoft.com/en-us/windows/desktop/sysinfo/registry-hives) del Sistema (```OslpLoadSystemHive```) esta funcion recibe tres parametros:

-   Un **DeviceID** este valor simplemente es un indice en la tabla ```DmDeviceTable``` que es la tabla que contiene los los *dispositivos* abiertos ([Notas DeviceId](#device_notes))
-   Una ```UNICODE_STRING``` con el path de la raiz del sistema (Obtenido antes con la funcion ```OslpInitializeSystemRoot ```)
-   Por ultimo un puntero al ```LOADER_PARAMETER_BLOCK```

Esta funcion simplemente va a generar tres strings mediante la fucion ```swprintf_s```, la primera es el FullPath (El path de todos los Hives es ```system32\config\```) del Hive y las dos siguientes son el log de los cambios de nombres y valores en el Hive, a continuacion se llamara a la funcion ```OslLoadAndInitializeHive``` que tiene recibira los siguientes argumentos:

```cpp
__int64 OslLoadAndInitializeHive(
  IN      ULONG DeviceID,
  IN      WCHAR *FullHivePath,
  IN      CHAR FlagControlSet,
  IN      WCHAR *Log1Path,
  IN      WHCAR *Log2Path,
  OUT     PVOID RegistryBase,
  OUT     ULONG *RegistryLength,
  IN      PLOADER_HIVE_RECOVERY_INFO HiveRecoveryInfo,
  OUT     PVOID HiveId
);
```
![alt img](/images/oslLoadDrivers/OslLoadAndInitializeHive.jpg "OslLoadAndInitializeHive")

Lo primero que hara esta funcion es abrir el fichero mediante la funcion [```BlImgLoadImageWithProgress2```](https://doxygen.reactos.org/d5/de2/boot_2environ_2lib_2misc_2image_8c_source.html#l00358) y guardara el puntero a este fichero en la variable ```RegistryBase```. A continuacion se comenzara a rellenar el [File Header](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md#windows-81-system-hive) y finalmente se inicializara el Hive con la llamada ```HiveInitializeAndValidate```, esta funcion inicializa y valida la estrcutura [HHIVE](https://www.nirsoft.net/kernel_struct/vista/HHIVE.html) como tal. No voy a entrar mas en ella por no alargar esto mucho mas, pero hay codigo tal que asi:

```cpp
  Hive = 0xBEE0BEE0; // Poner la 'firma' de la estructura
  Hive->GetCellRoutine = HvpGetCellPaged; // Metodo para obtener un CellPage
  Hive->ReleaseCellRoutine = HvpReleaseCellPaged; // Metodo para liberar un CellPage
```

A continuacion, se añade este Hive a la tabla de de Hives (```HiveTable```), mediante la funcion ```HiveAddTableEntry```. Como esta es la primera vez que se llama a esta funcion, se inicializara la tabla y el numero de entradas que tiene esta tabla (El numero de entradas esta fijado a 4) y se llamara a la funcion ```BlTblSetEntry``` que sera la encargada de copiar la direccion del Hive inicializado anteriormente en la Tabla y actualizar el **HiveId** con el indice de la posicion en la tabla.

Por ultimo entra en juego el parametro **FlagControlSet** en caso de no estar activo ya estaria acabado y tendriamos en el **HiveId** el indice en la ```HiveTable```, en caso de estar activo se llamara a la funcion ```OslSetControlSet``` que basicamente va a comprobar que para el valor *Default* de la Key *Select* en el Hive existe un ControlSet con ese valor (El famoso **ControlSet001**) y cambiara el valor *Current* por este numero. Finalmente tendremos en memoria algo como lo que se puede ver en la siguiente imagen:

![alt img](/images/oslLoadDrivers/System_Hive.jpg "System Hive")


<a name="attach_hive_notes">
#### OslAttachHiveToLoaderBlock
</a>

Esta funcion es relativamente generica, pero en este caso voy a hablar de ella porque una vez se ha cargado el ELAM Driver se va a llamar a esta funcion para añadir el Hive referente al ELAM al Loader Block (Todavia no he investigado como funciona el ELAM Driver pero imagino que necesitara este Hive y por eso el Loader lo carga y lo añade al Loader Block).

Lo primero que hace la funcion es obtener el Path al Hive, en este caso al hive del ELAM

![alt img](/images/oslLoadDrivers/elam_hive_path.jpg "ELAM Hive Path")

Lo siguiente es cargar este Hive mediante la funcion ```HiveLoadHiveFromLocation``` que al igual que he comentado en las Notas sobre el [SystemHive](#system_hive_notes) va a genera los path a ambos ficheros de Log y se va a cargar e inicializar el hive con la llamada ```OslLoadAndInitializeHive```. con el Hive ya cargado se comienza a crear una estructura que no conseguido encontrar informacion de ella en ningun sitio y tienen mas o menos el siguiente formato

```cpp
struct _ATTACHED_HIVE_ENTRY 
{
  LISTR_ENTRY Link;
  WCHAR * HiveName;
  ULONG Unknow; /* Intuyo que puede ser una especie 
                  de ID pero no me hagais mucho caso */
  PVOID HiveBase;
  ULONG HiveSize;
  WCHAR *StandardHiveName;
  WCHAR *HiveSubtree;
}
```

A continuacion se pondra el Flink de la ```LIST_ENTRY``` apuntando hacia el miembro ```LoaderParamBlock->Extension->AttachedHives``` (Se hace lo propio con el Blink, que en este caso al solo haber un Hive en la lista de *AttachedHives* coinciden)

![alt img](/images/oslLoadDrivers/attached_hive_struct.jpg "Attached Hive")

<a name="device_notes">
#### DeviceId
</a>

El **DeviceId** se obtiene mediante la funcion ```OslpOpenDevices```, esta funcion en primera instancia va a buscar si el *dispositivo* esta ya abierto (```BlpDeviceOpen```) para comprobar esto se llama a la funcion ```BlTblFindEntry``` donde pasara como primer parametro la tabla de *dispositivos* abiertos (```DmDeviceTable```), como segundo parametro se pasa el numero de entradas en dicha tabla (```DmTableEntries```) y el parametro pasado en ```r9``` es un callback a la funcion ```DeviceTableCompare``` que sera la encargada de comparar si el *dispositivo* que buscamos se encuentra en dicha tabla (Si el *dispositivo* no se encuentra en la tabla se procedera a abrirlo, pero eso esta fuera del scope)

La funcion ```OslpOpenDevices``` abrira el *dispositivo* al que apunta la variable ```OslLoadDevice``` y en el caso de que alguna de las opciones ```BCDE_OSLOADER_TYPE_BSP_DEVICE``` o ```BCDE_OSLOADER_TYPE_OS_DATA_DEVICE``` esten activadas tambien se abrira el *dispositivo* correspondiente. En este caso solo hablare del primer caso, la variable ```OslLoadDevice``` se ha asignado previamente y se obtiene de la opcion ```0x21000001``` que se corresponde con la Macro ```BCDE_OSLOADER_TYPE_OS_DEVICE```. Este *dispositivo* no es mas que el Volumen en el cual se encuentra el BootLoader. En este caso el bootloader(**winload.efi**) se encuentra dentro del Volumen ```C:```, en la siguiente imagen se puede observar el *dispositivo* accediendo desde la variable ```OslLoadDevice``` y accediendo desde la ```DmDeviceTable``` (En este caso se que es el 4 dispositivo en el array)

![alt img](/images/oslLoadDrivers/guid_deviceObject.jpg "Device Object")

> En ReactOS la estructura a la que apunta la variable ```OslLoadDevice``` la llaman [```_BL_DEVICE_DESCRIPTOR```](https://doxygen.reactos.org/dd/d76/struct__BL__DEVICE__DESCRIPTOR.html#a67f2887f7c88a8e27757add9d869c39d), en la MSDN/WDM no he encontrado ninguna referencia a una estructura similar a esta, por lo que intuyo que sera privada.

En la siguiente imagen podemos ver como el GUID obtenido anteriormente del *dispositivo* se corresponde con el Volumen ```C:```, que a su vez se corresponde con el Volumen en el cual esta el BootLoader

 <img src="/images/oslLoadDrivers/guid_check.jpg" alt="Device Object Check" style="margin:auto;"/>

Por ultimo, y de esto no estoy seguro por eso lo dejo para el final 🤣🤣, antes he comentado que el *dispositivo* se encontraba en la posicion 4 del array (Los arrays empiezan en 0... de toda la vida!), si observamos con la herramienta [WinObj](https://docs.microsoft.com/en-us/sysinternals/downloads/winobj) el HardDisk0, vemos que la particion 4 apunta al HardDiskVolume4, y por otro lado si observamos el objeto BootPartition y el objeto BootDevice, vemos que apuntan al mismo volumen. Que quiero insinuar con esto, que posiblemente cuando el BootLoader se encarga de cargar los *dispositivos* va rellenando la ```DmDeviceTable``` en el orden en que estan las particiones.

> Si no estoy equivocado creo que los dispositivos los carga en la funcion ```SpaceBootInitialize``` con la llamada a ```SB_CONTROL::BuildDevices``` (Esto no lo he reverseado, lo intuyo por el nombre 🤣)

![alt img](/images/oslLoadDrivers/harddisk_volume4.jpg "HardDisk Volume 4")

#### Transicion al Kernel

Este ultimo apartado no tiene ninguna relacion con todo lo que se ha hablado hasta ahora, pero creo que es interesante al menos comentar un poco el codigo de como se realiza la transicion del BootLoader al Kernel. De esta tarea se encarga la funcion ```OslExecuteTransition``` y mas especificamente la funcion  ```OslArchTransferToKernel```, en la siguiente imagen podeis ver el pseudocodigo de esta funcion:

<img src="/images/oslLoadDrivers/transfer_2_kernel.jpg" alt="OslArchTransferToKernel" style="margin:auto;"/>

La primera instruccion basicamente hace que las lineas de cache modificadas se escriban a la memoria principal e invalida estas caches. Luego se asignan los valores correspondientes al GDTR(``lgdt``) y al IDTR(```lidt```), a continuacion se van a activar los bits 7 (Page Global Enabled), 9 (OSFXSR) y 10 (OSXMMEXCPT) del [registro de control 4](https://en.wikipedia.org/wiki/Control_register#CR4), se hace lo mismo con los bits 5 (Numeric error), 16 (Write protect) y 18 (Alignment mask) del [registro de control 0](https://en.wikipedia.org/wiki/Control_register#CR0) y los bits del 0 (System call Extensions) y 8 (Long Mode Enable) del [EFER](https://en.wikipedia.org/wiki/Control_register#EFER) (Se obtiene leyendo del MSR con el valor ```0xC0000080```), tambien se pone a cero el [registro de control 8](https://en.wikipedia.org/wiki/Control_register#CR8)(Es un registro nuevo solo en 64bits para priorizar las interrupciones exteernas) y se asigna el selector que apunta al [TSS](https://en.wikipedia.org/wiki/Task_state_segment) al registro TR y finalmente se realiza un far return (Previamente se han pusheado el valor del EIP de **ntoskrnl.exe** y el *Segment Selector* de tipo Code y CPL 0)

> El far return obtiene el IP y el CS del stack, por eso se han pusheado previamente. Y se usa la instruccion ```retfq``` en vez de la instruccion ```retf``` porque el Bootloader ejecuta en Long Mode, por tanto cada entrada del stack es de 64bits por tanto para recuperar el IP y el CS tiene que leer 64bits no 32bits

![alt img](/images/oslLoadDrivers/transition_retfq.jpg "retfq transition")

Como se indica en el Capitulo 7 de la especificacion [**UEFI v2.7**](https://uefi.org/specifications), si la carga del del SO ha ido bien el UEFI Loader puede llamar a la funcion ```ExitBootService``` que descarta todos los Drivers UEFI de tipo ```EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER``` (Servicios de arranque), si esta llamada devuelve el valor ```EFI_SUCCESS``` el UEFI Loader dispone de toda la memoria del sistema y ademas es responsable de que la ejecucion del sistema continue. Los Drivers UEFI de tipo ```EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER```  se mantienen y pueden ser usados con paginamiento y direcciones virtuales siempre y cuando el servicio haya descrito todo el espacio virtual que utiliza mediante la llamada a la funcion ```SetVirtualAddressMap```. **Winload.efi** al ser un UEFI Loader, logicamente, tiene que encargarse de esto, y lo hace! Dentro de ```OslExecuteTransition``` la primera funcion a la que se llama es ```OslFwpKernelSetupPhase1``` que es la encargada de realizar esto, dicha funcion recibe un solo parametro (```LOADER_PARAMETER_BLOCK```) y basicamente se va encargar de lo que he mencionado anteriormente.

<img src="/images/oslLoadDrivers/ExitBootService.jpg" alt="ExitBootService" style="margin:auto;"/>

Y la llamada a ```SetVirtualAddressMap``` (El miembro *EfiInformation* realmente no tiene ese nombre, es el ultimo miembro de la estructura ```_FIRMWARE_INFORMATION_LOADER_BLOCK``` y actualmente en los simbolos no tiene nombre (*u*), le he puesto ese nombre porque contiene la estructura ```_EFI_FIRMWARE_INFORMATION```):

![alt img](/images/oslLoadDrivers/SetVirtualAddress.jpg "SetVirtualAddressMap")


> **Dato Curioso:** Quarkslab presento una POC de un Bootkit en el 2013, [Dreamboot](https://github.com/quarkslab/dreamboot) que una de las tecnicas que usa es hookear la funcion ```OslArchTransferToKernel```. Tened en cuenta que en este punto en memoria se encuetran todas las estructuras que el kernel necesita para ejecutar o sea que es un buen punto para hacer "cosas" 🤣

> Mas info en el Paper (Esta en Frances..) https://www.sstic.org/media/SSTIC2013/SSTIC-actes/dreamboot_et_uefi/SSTIC2013-Article-dreamboot_et_uefi-kaczmarek.pdf