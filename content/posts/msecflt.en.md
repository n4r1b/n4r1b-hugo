+++
categories = ["mssecflt", "PatchGuard", "Windows Defender", "Microsoft Security"]
tags = ["msecflt", "PatchGuard", "Windows Defender", "Microsoft Security"]
date = "2019-12-23"
description = "Getting to know what is the MsSecFlt driver and how it works"
images = ["https://n4r1b.com/images/wdELAM/wdElam.png"]
featured = ["https://n4r1b.com/images/wdELAM/wdElam.png"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "What is and how does MsSecFlt works (Part 1: Initialization)"
slug =  "What is and how does MsSecFlt works (Part 1: Initialization)"
type = "posts"
+++

I'm back again, this time I will release a serie of post studying a not very well-known component from Microsoft Security. The Microsoft Security Events Component Minifilter, from now on we will refer to it as MsSecFlt. The motivation for this post comes from the [last research](https://github.com/0xcpu/ExecutiveCallbackObjects/tree/master/542875F90F9B47F497B64BA219CACF69) I made with [@0xcpu](https://twitter.com/0xcpu) where we looked into the PatchGuard Callback, and as we explained there, the component in charge of triggering that Callback (Verify routine of PG) is MsSecFlt. And afterwards skimming through the driver I found out that is a really well crafted piece of code (Against props to the Microsft dev team) where we can find things from ETW Tracing to FS minifilter, including Kernel Extensions and Registry calls filtering. That's why I decided to divide this research into multiple posts. So without further ado, let's get into the initialization process.

> For this research we are going to study the MsSecFlt (**SHA256:** `D83BF4D84A463D2A73F7C7095E85294361F823810DFE8A605273BBF097AF11F3`) from Windows 10 build 19536.

## Initialization

Let's start from the beginning, the `DriverEntry`. First function that will execute is `SecInitializeGlobals` which, as the name implies, will be in charge of initializing the Global structure (Defined in the symbols as `SecData`), this structure will be allocated in a NonPagedPoolNx of size `0x540` and tag **Scgd** (Every pool with tag allocated inside this driver will start by **Sc**). The definition of the structure looks something like this:

```C
typdef struct _SEC_DATA
{
  INT MagicAndSize;
  PDRIVER_OBJECT DriverObject;
  PDEVICE_OBJECT DeviceObject;
  PFLT_FILTER Filter;
  __int64 field_20;
  PFLT_PORT ServerPort;
  __int64 field_30;
  __int64 field_38;
  __int64 field_40;
  __int64 field_48;
  __int64 field_50;
  __int64 field_58;
  __int64 field_60;
  __int64 field_68;
  __int64 field_70;
  __int64 field_78;
  __int64 field_80;
  __int64 field_88;
  __int64 field_90;
  __int64 field_98;
  __int64 field_A0;
  __int64 field_A8;
  __int64 field_B0;
  __int64 field_B8;
  __int64 field_C0;
  __int64 field_C8;
  __int64 field_D0;
  __int64 field_D8;
  __int64 field_E0;
  __int64 field_E8;
  __int64 field_F0;
  __int64 field_F8;
  __int64 field_100;
  __int64 field_108;
  __int64 field_110;
  __int64 field_118;
  __int64 field_120;
  __int64 field_128;
  LIST_ENTRY AnotherListEntry;
  WCHAR *MsSecFltParameters;
  ERESOURCE eResource1;
  __int64 field_1B0;
  __int64 field_1B8;
  _PAGED_LOOKASIDE_LIST PagedLookasideListScix;
  _PAGED_LOOKASIDE_LIST PagedLookasideListFileQuery;
  _PAGED_LOOKASIDE_LIST FilterLookasideScEc;
  _PAGED_LOOKASIDE_LIST PagedLookasideListScHs;
  _PAGED_LOOKASIDE_LIST PagedLookasideListSetW;
  PVOID RegistrationHandle;
  __declspec(align(16)) _ERESOURCE eResource2;
  int DeviceOpenFlag;
  int field_4BC;
  _KEVENT kEvent;
  EX_PUSH_LOCK PushLock;
  LIST_ENTRY SomeListEntry;
  __int64 field_4F0;
  EX_PUSH_LOCK PushLock1;
  LIST_ENTRY SomeListEntry1;
  int field_510;
  char field_514;
  char field_515;
  char field_516;
  char field_517;
  int field_518;
  int FiltersSetFlag;
  __int64 field_520;
  __int64 field_528;
  __int64 field_530;
  __int64 field_538;
} SEC_DATA, *PSEC_DATA;
```

This function, will only initialize the Magic, Executive Resources, PushLocks and Lookaside Lists. Also, this function will concat the registry path with the string `\Parameters` and save this value in the field `MsSecFltParameters`. With all this done, the code will proceed to build a [Security Descriptor](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_descriptor) inside function `SecBuildDefaultSecurityDescriptor`, this function will use the [`SeExports`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_se_exports) value `SeLocalSystemSid` to create a Security Descriptor, this is done inside `SecCreateSecurityDescriptor`, function that will allocate a pool where it will save the `_SECURITY_DESCRIPTOR` and the `DACL`:

![alt image](/images/mssecflt/SecurityDescriptorPool.png "Security Descriptor Pool")

This security descriptor will be then provided to function `ObSetSecurityObjectByPointer` to set the security state of the object `Microsoft_Windows_Sec_Provider` (**GUID:** CHEEEK!!!! 16C6501A-FF2D-46EA-868D8F96CB0CB52D) that was previously obtained with a call to `IoWMIOpenBlock`. This whole process is done inside `SecSetProviderSecurity`. Once this is done, the driver will proceed to create the device object, this is done inside `SecCreateDeviceObject`, this function pseudocode looks like this (As always **huge** thanks to Hex-Rays):

![alt image](/images/mssecflt/SecCreateDevice.png "Pseudocode SecCreateDeviceObject")

We can see that this function is registering an IRP Dispatch routine for `IRP_MJ_CREATE` (We will get into this routine soon), after that is creating the device with name `\Device\MSSECFLTSYS` and lastly is creating a symbolic link with name `\??\MSSECFLTSYS`. If everything goes well, then a pointer to the `DEVICE_OBJECT` will be saved in the `SEC_DATA` struture.

> The symbolic link is created in order for an userspace module to be able to open this device, this is the case of `MsSecUser.dll`. We will see more of that module in the next parts of the serie, but just but looking at the string we can find the DLL opening this device:
>
> ![alt image](/images/mssecflt/mssecuser.png "CreateFileW MsSecUser")

Before returning from the DriverEntry the driver will execute one last step, which consist in calling `SecInitializeKernelIntegrityCheck`, function which is in charge of registering the callback function (`SecKernelIntegrityCallback`) for the callback object **542875F90F9B47F497B64BA219CACF69**. 

> I won't get into much detail on this process since is already explained on the [callback-creation-and-mssecfltsys](https://github.com/0xcpu/ExecutiveCallbackObjects/tree/master/542875F90F9B47F497B64BA219CACF69#callback-creation-and-mssecfltsys) section of the research we did about this callback.

## IRP_MJ_CREATE - SecDeviceOpen

As we saw in the previous section, a IRP dispatch routine for `IRP_MJ_CREATE` is register, this dispatch routine is the one that will be in charge of setting every different way that this drivers has to filter and trace events. First thing function `SecDeviceOpen` will check is if the calling process is protected or not (Protection level: WINDOWS_LIGHT - 0x51), in case is not then the dispatch routine will return **ACCESS_DENIED**. In case it is a protected process, then function `SecIntilization` will be called, this function is actually the one that will initialize the different filtering mechanisms. I will divide each type of filter in subsections in order to make it as clear as possible. Also, after each mechanism has been activated the driver will OR the flag `SEC_DATA.FilterSetFlag` with a specific value, this value will be used in case something goes wrong to deinitialize only the filters that were activated, in the end of each subsection I will remark against which value is the flag OR'ed.

### Kernel Extension

> I encourage reading this [post](https://medium.com/yarden-shafir/yes-more-callbacks-the-kernel-extension-mechanism-c7300119a37a) by [@yarden_shafir](https://twitter.com/yarden_shafir) and having a look at this [presentation](https://vimeo.com/335166152) by her, [@aionescu](https://twitter.com/aionescu) and [@pwissenlit](https://twitter.com/pwissenlit) to get a better understanding on what are and how do kernel extensions work.

First thing `SecIntilization` will do is register an extension with the following **ExtensionId** and **ExtensionVersion** `0x1000E`. This extension won't register any callback, but will receive the unexported `PsIsProcessPrimaryTokenFrozen` function from the `nt`. The register extension will be saved in the exported symbol `SecKernelExtension` while the function/interface received from the `nt` will be saved in `SecKernelInterface`. This can be seen in the following image (Thanks again to Yarden for the struct definition):

![alt image](/images/mssecflt/SecKernelExtension.png "SecKernelExtension & SecKernelInterface")

And the received frunction from `nt` looks something like this:

```C
BOOLEAN __fastcall PsIsProcessPrimaryTokenFrozen(_EPROCESS *Process) 
{
  return Process.Flags2.PrimaryTokenFrozen & 0x1;
}
```

We will leave how and when this function is used for the next section, for now let's keep going with `SecIntilization`. Once the extension is register, the function will proceed to set the limits (`SecSetBufferLimits`) for two buffers:
- FunctionInputBufferLength
- FunctionMinimumOutputBufferLength

This limits will be used inside the **MessageNotifyCallback** function that will be register for a communication port that will be open afterwards.

Next step is to determine some crypto features based on the processor characteristics, this is going to be done inside `SymCryptInit`. This function will first check if is running in a OS version over 8.1, in case it's not it will bug check with code `0x171`, in the other case it will call `SymCryptDetectCpuFeaturesByCpuid` which will iterate over an array of structures with the following definition:

```
typedef struct _CPUID_BIT_INFO
{
  BYTE  EAX_value;
  BYTE  RegToCheck;
  BYTE  BitToTest;
  BYTE  Reserved;
  DWORD OrValue;
} CPUID_BIT_INFO, *PCPUID_BIT_INFO;
```

> I coined the structure as `CPUID_BIT_INFO` because the arrays starts in an exported symbol that goes by the name cpuidBitInfo

and each entry will be used to determine if a feature is not present, and lastly the final value will be negated to obtain the crypto features present, value which will be saved in `g_SymCryptCpuFeaturesPresentCheck`. The following algorithm is used to test if a feature is present or not:

![alt image](/images/mssecflt/CryptoFeatures.png "Crypto features present")

The tested features are the following (https://en.wikipedia.org/wiki/CPUID)
- rdrnd  
- pclmulqdq
- aes   
- sse   
- sse2  
- sse3  
- ssse3  
- avx   
- avx2  
- rdseed 
- sha   
- adx   
- bmi2  
         

finally a last global is set (`CPU_INFO g_SymCryptCpuid1`) with the values returned from `CPUID` with `EAX=1`.

> At this point the flag is set like this: `SecData.FilterSetFlag |= 0x1`

Once the crypto variables have been set, the driver will proceed to initialize the driver default configuration variables (`SecInitializeDriverConfiguration`). I won't get into all of them now but I will remark them whenever they are going to be used inside a function. Also inside this function a read/write telemetry policy will be applied to a list of processes that are saved inside the array pointed by `c_defaultReadOnlyNamesArray` (Hardcoded inside this array there is only one process `lsass.exe`, but as we'll see in following posts this config can be modified)

> Flag set: `SecData.FilterSetFlag |= 0x2`

Getting back into `SecInitalization`, the next job of this function is to initalize a process table, this is done inside `SecInitializeProcessTable`. This function will initialize a structure that will look something like this:

```C
typedef struct _SEC_PROCESS_TABLE
{
  _INT64 MagicAndSize;
  EX_PUSH_LOCK ProcessTablePushLock;
  __int64 field_10;
  __int64 field_18;
  __int64 field_20;
  __int64 field_28;
  __int64 field_30;
  __int64 field_38;
  _PAGED_LOOKASIDE_LIST PagedLookasideListProcessCtx;
  _PAGED_LOOKASIDE_LIST PagedLookasideListProcessCtxEntry;
  LIST_ENTRY (* ProcessesContextListEntry)[0x80];
  KEVENT ProcessTableEvent;
  DWORD dword160;
  int field_164;
  PVOID SecureSystemProcessId;
  __int64 field_170;
  __int64 field_178;
} SEC_PROCESS_TABLE, *PSEC_PROCESS_TABLE;
```

This structure is used mainly to manage the processes contexts, this will make more sense in a couple of posts when we start looking into different ways the driver has to track process/thread creation/loading. The field `ProcessesContextListEntry` is actually a shifted pointer into a `LIST_ENTRY` inside another structure that will have all the process context, something like `LIST_ENTRY *__shifted(PROCESS_CTX, 0x10)`. Another curious thing is that in case `Secure System` is running on the system (Credential Guard active), then the **UniqueProcessId** of this process will be saved into the struct.

> Flag set: `SecData.FilterSetFlag |= 0x4`

Next step in the initialization of MsSecFlt, is to register the event provider. This is done using the function `EtwRegister`, the provider 


the registration handle in `Microsoft_Windows_SECHandle`. Also, a callback is going to be set `SecEtwEnableCallback`


> Flag set: `SecData.FilterSetFlag |= 0x8`


SecInitializeSystemModuleTable
SecDetInitialize

> Flag set: `SecData.FilterSetFlag |= 0x10`


FltRegisterFilter

> Flag set: `SecData.FilterSetFlag |= 0x20`

SecCreateCommPorts

> Flag set: `SecData.FilterSetFlag |= 0x40`

SecPsCalloutInitialize

> Flag set: `SecData.FilterSetFlag |= 0x80`

SecObAddCallback

> Flag set: `SecData.FilterSetFlag |= 0x200`

SecRegInitialize

> Flag set: `SecData.FilterSetFlag |= 0x400`

SecTimerInitialize

> Flag set: `SecData.FilterSetFlag |= 0x800`
