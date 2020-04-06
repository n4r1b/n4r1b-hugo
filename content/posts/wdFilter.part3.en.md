+++
categories = ["WdFilter", "MiniFilter", "Windows Defender", "Microsoft Security"]
tags = ["WdFilter", "MiniFilter", "Windows Defender", "Microsoft Security"]
date = "2020-03-23"
description = "In this series of posts I'll be explaining how the Windows Defender main Driver works, in this third post we will look into the callback routine for process/desktop handle operations and also into everything related to drivers information and verification"
images = ["https://n4r1b.netlify.com/images/wdELAM/wdElam.png"]
featured = ["https://n4r1b.netlify.com/images/wdELAM/wdElam.png"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "Dissecting the Windows Defender Driver - WdFilter (Part 3)"
slug =  "Dissecting the Windows Defender Driver - WdFilter (Part 3)"
type = "posts"
+++

Welcome back to Dissecting the Windows Defender Driver, in the previous part we saw how **WdFilter** handles the loading of images in memory through an ImageLoad callback routine, we also saw how new threads are checked in two different Thread-creation callback routines and lastly we saw how messages are sent to **MsMpEng** both synchronously and asynchronously. And now for this part, we will focus on the following things:

- Process and Desktop handle operations callback
- Drivers information and verification

So without further ado let's get into it.

### Process & Desktop handle callbacks

First things first, how the initialization of the Object callbacks is done. This process starts inside `MpObInitialize`, this function will obtain dynamically the address of two functions:

- [ObRegisterCallbacks](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks) (Pointer saved in `MpData->pObRegisterCallbacks`)
- [ObUnRegisterCallbacks](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obunregistercallbacks) (Pointer saved in `MpData->pObUnRegisterCallbacks`)

If both function pointers were retrieved then it will proceed to call `MpObAddCallback`. The main job of  `MpObAddCallback` is to actually register the callback and return, in an out parameter, the registration handle which is then saved in `MpData->ObRegistrationHandle`. 

In order to register an Object callback a `OB_CALLBACK_REGISTRATION` structure must be provided to `ObRegisterCallbacks`. Among other things this structure contains an array of `OB_OPERATION_REGISTRATION` which will be initialized in this way:

{{< more C >}}
OB_CALLBACK_REGISTRATION    ObCbRegistration = {}     
OB_OPERATION_REGISTRATION   OperationRegistration[2] = {}

OperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
OperationRegistration[0].ObjectType = PsProcessType;
OperationRegistration[0].PreOperation = MpObPreOperationCallback;

if (MpData->OsVersionMask & OsVersionWin10) {
    OperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    OperationRegistration[0].ObjectType = ExDesktopObjectType;
    OperationRegistration[0].PreOperation = MpObPreOperationCallback;
    ObCbRegistration.OperationRegistrationCount = 2;
} else {
    ObCbRegistration.OperationRegistrationCount = 1;
}

ObCbRegistration.OperationRegistration = OperationRegistration;
{{< /more >}}

In the previous pseudocode we can see how two entries (In case of Windows 10) are being added into the array, both of the operations register the same *PreOperation* and no *PostOperation*, also both register to handle creation and duplication. Now we are going to focus on the *PreOperation* function `MpObPreOperationCallback`

> To learn much more than what I explained about all this structure and other cool stuff I strongly recommend this post https://rayanfam.com/topics/reversing-windows-internals-part1/ from [Sinaei](https://twitter.com/Intel80x86).

#### MpObPreOperationCallback

As we saw before this callback is registered for both **PsProcessType** and **ExDesktopObjectType**, so obviously the routine needs a way to distinguish which object is the one triggering the callback. Since this is a *PreOperation* routine it's prototype must be defined as a [POB_PRE_OPERATION_CALLBACK](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-pob_pre_operation_callback) which means the second parameter of it will be an [OB_PRE_OPERATION_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_operation_information) structure that contains a field with the *ObjectType*, this value can be used to know what type of object triggered the callback. So this function's only job will be to redirect the *OperationInformation* into the correct function for each object type.

#### MpObHandleOpenDesktopCallback

This is the function that handles operation regarding the Desktop Object, it's function will mainly be to act as a notifier. It will receive the `OB_PRE_OPERATION_INFORMATION` as a parameter and first thing it will do is to obtain the **ProcessCtx** from the current process. The `ProcessCtx->ProcessRules` will be checked to see if the value, I coined, **DoNotNotifyDesktopHandlesOp** (`0x8`) is not set. If the value is not set then the target *Object* will be retrieved from `OB_PRE_OPERATION_INFORMATION`. With this *Object* the code will proceed to obtain it's name throughout the function [ObQueryNameString](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obquerynamestring). Then a `AsyncMessageData` structure will be allocated -- Taking into account the length of the object name -- and populated accordingly. The union *TypeOfMessage* will contain the following structure:

```C
typedef struct _ObDesktopHandleMessage
{
  AuxPidCreationTime Process;
  INT ThreadId;
  INT SessionId;
  BYTE Operation;
  BYTE KernelHandleFlag;
  INT DesiredAccess; // https://docs.microsoft.com/en-us/windows/win32/winstation/desktop-security-and-access-rights
  WCHAR *ObjectName;
} ObDesktopHandleMessage, *PObDesktopHandleMessage;
```

Once the whole `AsyncMessageData` is filled, the notification is sent using `MpAsyncSendNotification`. And that's pretty much all for this callback, as I said in the beginning of the section it mainly works as a notifier.

![alt image](/images/wdFilter/part3/ObDesktopHandle.png "Async Message Desktop Handle")

#### MpObHandleOpenProcessCallback

This function will handle operations regarding Process handles. In order for this callback to start it's operation the flag `MpData->UnsetObAndRegCallback` must not be set, the current process must be other than **MsMpEng** and the handle must not be a **KernelHandle**. If these conditions are met, then the code will proceed to obtain the **ProcessCtx** for both, the current process and the target process -- The current process is the one trying to obtain a handle to the target process -- From now on different rules will be applied depending on which type of access the process is requesting. If the process is requesting any of the following accesses:

- PROCESS_VM_WRITE - Write to the address space of the target process 
- PROCESS_VM_OPERATION - Modify the address space of the target process
- PROCESS_CREATE_THREAD - Create a new thread in the context of the target process

Then the callback will proceed to check if code injection from the current process to the target process is allowed, in order to do this it uses two functions. `BOOLEAN MpAllowCodeInjection(PProcessCtx CurrentProcess, PProcessCtx TargetProcess)` this function will check if the *ProcessFlags* of the *CurrentProcess* match any of the following values:

- ExcludedProcess - 0x1
- MpServiceSidProcess - 0x10
- FriendlyProcess  - 0x20
- SvchostProcess - 0x100

if none flag is matched then it will obtain the value `ProcessCtx->CodeInjectionTargetMask` from the *TargetProcess* and the value `ProcessCtx->CodeInjectionRequestMask` from the *CurrentProcess* and it will proceed to AND the two values to determine if the injection is allowed. The following pseudo-code shows the behavior of this function

```C
processFlags = CurrentProcess->ProcessFlags;
 
if (processFlags & ExcludedProcess || processFlags & MpServiceSidProcess ||
    processFlags & FriendlyProcess || processFlags & SvchostProcess) {
      return TRUE;
}
targetMask = TargetProcess->CodeInjectionTargetMask;
requestMask = CurrentProcess->CodeInjectionRequestMask;

if (!targetMask || requestMask == -1 || targetMask & requestMask) {
  return TRUE
} 
MpLogPrintfW(L"[Mini-filter] Injection into process %u from process %u is BLOCKED.",
    TargetProcess->ProcessId,
    CurrentProcess->ProcessId);
return FALSE;
```
in case this function returns `FALSE` the *DesiredAccess* will be modified in order to remove the permission that trigger this check.

In case we are running `Windows 10 build 16000` or higher another check will be done, based on Windows Defender host intrusion and prevention system (HIPS) rules

> To be honest, I don't know much about Windows Defender HIPS, and I couldn't find much information about it on the internet. So I don't know if there's a way to add or check which HIPS rules are running on the system. If someone has more insight about it, please reach out to me as I would love to learn more about this.

The HIPS rules for handles creation are checked inside `MpAllowAccessBasedOnHipsRule`. Among other things this function accept the following parameters:

- HipsRule - `@r8`
- ProcessRule - `@r9`
- TargetRule - `@rsp+20`

and the function will basically check the rules provided as arguments against the corresponding **ProcessRules** -- The HipsRule is checked against the current process rules -- the actual behavior can be seen in the following pseudo-code:

```C
allowedFlag = FALSE;
allowedOrBlocked = L"BLOCKED";
targetRules = TargetProcess->ProcessRules; 
processRules = CurrentProcess->ProcessRules;

if (!(processRules & HipsRule) || targetRules & TargetHipsRule || processRules & ProcessRule) {
      allowedOrBlocked = L"ALLOWED";
      status = TRUE;
}

MpLogPrintfW(
    L"[Mini-filter] Applying HipsRule 0x%x: Access from process %u to target %u is '%ls'",
    HipsRule,
    CurrentProcess->ProcessId,
    TargetProcess->ProcessId,
    allowedOrBlocked);

return allowedFlag;
```
for *PROCESS_VM_WRITE*, *PROCESS_VM_OPERATION* and *PROCESS_CREATE_THREAD* the following values are passed as arguments to this function:

- HipsRule => AllowCodeInjectionHIPSRule - 0x8000 
- ProcessRule => AllowedToInjectCode - 0x10000
- TargetRule => AllowIncomingCodeInjection - 0x80000

Getting into the callback again, there's another set of access rights that will trigger checks, they can be seen in the following list:

- SYNCHRONIZE - Required to wait for the process to terminate using the wait functions
- PROCESS_TERMINATE - Required to terminate a process using TerminateProcess
- PROCESS_SUSPEND_RESUME - Required to suspend or resume a process
- PROCESS_QUERY_LIMITED_INFORMATION - Required to retrieve certain information about a process

in this case the callback will check the value `ProcessCtx->ProcessProtection` from the current process in order to check if the *Type* is **PsProtectedTypeNone** and the *Signer* less than **PsProtectedSignerAntimalware**. Also as in the previous case, there's a HIPS rule for this case too, in this case the parameters passed to function `MpAllowAccessBasedOnHipsRule` are the following:

- HipsRule => QuerySuspendResumeHIPSRule - 0x800000 
- ProcessRule => AllowedToQuerySuspendResume - 0x1000000
- TargetRule => AllowQuerySuspendResume - 0x2000000

if any of these checks fail then the *DesiredAccess* will be adjusted accordingly.

Lastly, this callback will proceed to send an async notification. This notification will be created and send inside `MpObSendOpenProcessBMNotification`, we've already seen a couple of functions similar to this one in behavior, it will basically create a `AsyncMessageData` where the *TypeOfMessage* will be `ObProcessHandleMessage`, which is a structure that has the following definition:

{{< more C >}}
typedef struct _ObProcessHandleMessage
{
  AuxPidCreationTime Process;
  AuxPidCreationTime TargetProcess;
  INT SessionId;
  INT FinalDesiredAccess;
  INT FileNameLen;
  INT FileNameOffset;
  INT TargeFileNameLen;
  INT TargeFileNameOffset;
  BYTE CodeInjectionHIPS[16];           // Needs investigation
  BYTE QuerySuspendResumeHIPSRule[16];  // Needs investigation
  INT Unk;
  MP_OB_NOTIFICATION_REASON NotificationReason;
} ObProcessHandleMessage, * PObProcessHandleMessage;

typedef enum MP_OB_NOTIFICATION_REASON
{
  // Default notification set to 0x0
  DesiredAccessModified = 0x1,
  AllowCodeInjectionHIPSTrigger = 0x2,
  QuerySuspendResumeHIPSTrigger = 0x4,
  SameDesiredAccesAndAllowCodeInjectionHIPSTrigger = 0x8,
  SameDesiredAccessAndQuerySuspendResumeHIPSTrigger = 0x10,
}
{{</ more >}}

Once this structure is allocated and populated the notification will be added to the `AsyncNotificationsList` for it to be processed by the worker thread.

![alt image](/images/wdFilter/part3/ObProcessHandle.png "Async Message Process Handle")

Getting back into the main function, after sending the notification there is one last check before finishing the function, in case the target process is a **MpServiceSidProcess** and the current process is neither a **MpServiceSidProcess** nor a **FriendlyProcess**, then the following access rights will be removed

```C
if (!(TargetProcess->ProcessFlags & MpServiceSidProcess)) {

  if (!(CurrentProcess->ProcessFlags & MpServiceSidProcess) && 
      !(CurrentProcess->ProcessFlags & FriendlyProcess)) {

    ObOpParameters->CreateHandleInformation.DesiredAccess &= 
        ~(PROCESS_VM_WRITE|PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD|PROCESS_TERMINATE);
  }

  goto ReleaseProcessCtx;
}
```

> More info about [Process security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)

### Drivers information and verification 

First function involved in this process is `MpInitializeDriverInfo` which is being called from within the `DriverEntry`. We already mentioned this function in the first post, now we will see more details about it and about other functions related to Drivers info and verification. Getting into the actual function, mainly it will allocate the following structure:

{{< more C >}}
typedef struct _MP_DRIVERS_INFO
{
  INT Status;
  BYTE Reserved[8];
  INT ElamSignaturesMajorVer;
  INT ElamSignatureMinorVer;
  LIST_ENTRY LoadedDriversList;
  PSLIST_ENTRY ElamRegistryEntries;
  LIST_ENTRY BootProcessList;
  PCALLBACK_OBJECT CallbackObject;
  PVOID BootDriverCallbackRegistration;
  FAST_MUTEX DriversInfoFastMutex;
  INT TotalDriverEntriesLenght;
  NTSTATUS (__fastcall *pSeRegisterImageVerificationCallback)(SE_IMAGE_TYPE, SE_IMAGE_VERIFICATION_CALLBACK_TYPE, PSE_IMAGE_VERIFICATION_CALLBACK_FUNCTION, PVOID, SE_IMAGE_VERIFICATION_CALLBACK_TOKEN, PVOID *);
  VOID (__fastcall *pSeUnregisterImageVerificationCallback)(PVOID);
  PVOID ImageVerificationCbHandle;
  INT RuntimeDriversCount;
  INT RuntimeDriversArrayLenght;
  PVOID RuntimeDriversArray;
  LIST_ENTRY RuntimeDriversList;
  INT64 field_C8;
} MP_DRIVERS_INFO, *PMP_DRIVERS_INFO
{{</ more >}}

after initializing some fields of the structure the function will obtain a handle to the callback object `\Callback\WdEbNotificationCallback` and then it will proceed to register `MpBootDriverCallback` as the callback function, saving the registration handle in the structure member *BootDriverCallbackRegistration*.

#### MpAddDriverInfo & MpAddBootProcessEntry

Before getting into the boot driver callback I want to explain how list entries `LoadedDriversList` and `BootProcessList` are filled. In the former data is going to be chained in `MpAddDriverInfo` which is executed in the Image-Load callback, while the latter is filled inside `MpAddBootProcessEntry` which is called from within the Process-Creation callback.

Digging into `MpAddDriverInfo`, as I just said, is going to be called from within the Image-Load callback whenever the loaded image is a **SystemModeImage**. This function will receive the `IMAGE_INFO` and the full image name as parameters, and mainly it will allocate memory for the structure `MP_DRIVER_INFO`

{{< more C >}}
typedef struct _MP_DRIVER_INFO
{
  LIST_ENTRY DriverInfoList;
  UNICODE_STRING ImageName;
  UNICODE_STRING DriverRegistryPath;
  UNICODE_STRING CertPublisher;
  UNICODE_STRING CertIssuer;
  PVOID ImageHash;
  INT ImageHashAlgorithm;
  INT ImageHashLength;
  PVOID CertThumbprint;
  INT ThumbprintHashAlgorithm;
  INT CertificateThumbprintLength;
  PVOID ImageBase;
  INT64 ImageSize;
  INT ImageFlags;
  INT DriverClassification;
  INT ModuleEntryEnd;
} MP_DRIVER_INFO, *PMP_DRIVER_INFO;
{{</ more >}}

where it will just fill the *ImageSize*, *ImageBase* and the *ImageName* to then chain this new entry into `MP_DRIVERS_INFO->LoadedDriversList`.

![alt image](/images/wdFilter/part3/AddDriverInfo.png "Add Driver Info")

For the case of `MpAddBootProcessEntry` this function is called from within the process creation, and it executes for the first 50 loaded processes (Counter kept in global variable **BootProcessCounter**). The function prototype looks like this:

```C
VOID
MpAddBootProcessEntry(
  HANDLE  ProcessId,
  HANDLE  ParentProcessId,
  PCUNICODE_STRING  ImageFileName,
  PCUNICODE_STRING  CmdLine
)
```

and again as the previous case, this function main goal is to allocate and initialize an structure, in this case the structure is `MP_BOOT_PROCESS` and it's definition is as it follows:

```C
typedef struct _MP_BOOT_PROCESS
{
  LIST_ENTRY BootProcessList;
  HANDLE ProcessId;
  HANDLE ParentProcessId;
  UNICODE_STRING ImageFileName;
  UNICODE_STRING CommandLine;
  INT SomeFlag;   // Set to 3
} MP_BOOT_PROCESS, *PMP_BOOT_PROCESS;
```
once the entry is initialized is then chained into the list `MP_DRIVERS_INFO->BootProcessList`. 

![alt image](/images/wdFilter/part3/AddBootProcess.png "Add Boot Process")

#### MpBootDriverCallback

Now that we know how those two list entries are filled we will start looking into the callback function registered during the initialization. As I already explained on my post about the [Windows Defender ELAM](https://n4r1b.netlify.com/posts/2019/11/understanding-wdboot-windows-defender-elam/) this callback is notified when in the boot driver callback function of the ELAM driver the `BDCB_CALLBACK_TYPE` is set to **BdCbStatusUpdate** and the image information has the `BDCB_CLASSIFICATION` set to **BdCbClassificationKnownBadImage**. If this conditions are met then the callback will be notified with *Argument1* being a pointer to the main **WdBoot** structure, `MP_EB_GLOBALS`, and *Argument2* set to the constant `0x28`.

So getting into `MpBootDriverCallback`, first thing it will do is a sanity check on *Argument1* and *Argument2*, for the latter it will check if is equal to `0x28` while for the former it will check that the *Magic* of the structure is `0xEB01`. If both checks are fine, then it will proceed to iterate the over the list of drivers that was created by **WdBoot** and for every driver it will call `MpCopyDriverEntry`, which will mainly copy the driver entry data into a `MP_DRIVER_INFO` structure that will be then chained to `MP_DRIVERS_INFO->LoadedDriversList`. 


> Disclaimer! The following paragraph describes a path/use-case I haven't been able to trigger so there's gonna be some guessing, I apologize for this. I think this has to do with the fact that ELAM Drivers can use Registry Callbacks or Boot-Driver Callbacks to monitor and validate the configuration data, and at least on my research I've only seen the second case. [More info](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements#am-driver-callback-interface) 

Once every entry has been copied, then the `SLIST_ENTRY` *ElamRegistryEntries* will be walked and for each entry it will call `MpCopyElamRegistryEntry`. This function will basically copy the entry to a structure I named `MP_ELAM_REGISTRY_ENTRY` and this structure will be inserted in the singly linked list `MP_DRIVERS_INFO->ElamRegistryEntries` -- Probably this has something to do with the ELAM registry hive entries, `MP_ELAM_REGISTRY_ENTRY` sizeof is `0x40` and it contains two `UNICODE_STRINGS` but I can't provide much more info about this, if anyone knows more please reach out to me so I can update this whole paragraph (I'll try to research more thou). 

Lastly, two more values are copied from `MP_EB_GLOBALS` to `MP_DRIVERS_INFO`. These values are the *ElamSignaturesMajorVer* and the *ElamSignatureMinorVer*. And that's all this function will do, so to summarize, it mainly copy the information from `MP_EB_GLOBALS` -- Which is the information obtained by the ELAM driver -- to the structure `MP_DRIVERS_INFO`.

#### MpSetImageVerificationCallback

This is one of the last functions executed during the initialization, the goal from this function is mainly to register an Image Verification callback, for this purpose it will retrieve dynamically two function pointers

- SeRegisterImageVerificationCallback
- SeUnregisterImageVerificationCallback

Both functions reside in the kernel and they basically do what their name says. `SeRegisterImageVerificationCallback` has a couple of checks that can be seen on the following pseudo-code:

{{< more C >}}
NTSTATUS 
SeRegisterImageVerificationCallback(
  SE_IMAGE_TYPE ImageType, 
  SE_IMAGE_VERIFICATION_CALLBACK_TYPE CallbackType, 
  PSE_IMAGE_VERIFICATION_CALLBACK_FUNCTION CallbackFunction, 
  PVOID CallbackContext, 
  SE_IMAGE_VERIFICATION_CALLBACK_TOKEN CallbackToken, 
  PVOID * RegistrationHandle
)
{
  if (ImageType != SeImageTypeDriver || CallbackType || CallbackToken) {
    // CallbackType should be SeImageVerificationCallbackInformational which is 0
    return STATUS_INVALID_PARAMETER;
  }
  
  PVOID registrationHandle = 
        ExRegisterCallback(ExCbSeImageVerificationDriverInfo, 
                          CallbackFunction, 
                          CallbackContext);

  if (registrationHandle) {
    *RegistrationHandle = registrationHandle;
  }
}
{{</ more >}}

Returning to `MpSetImageVerificationCallback`, besides registering function `MpImageVerificationCallback` as the image verification callback routine it will also allocate a pool of size `0x800` where the **RuntimeDriversArray** will reside.


#### MpImageVerificationCallback

This callback will be notified from within `SepImageVerificationCallbackWorker` inside the kernel, the call stack when this callback executes looks something like the following:

![alt image](/images/wdFilter/part3/CallStackImageVerification.png "Call stack MpImageVerificationCallback")

> How and when the callback is notified, for now, I will leave it as an exercise for the reader

Once the callback is notified first thing will do is call `MpAllocateDriverInfoEx` that will allocate and initialize a `MP_DRIVER_INFO_EX`

{{< more C >}}
typedef struct _MP_DRIVER_INFO_EX
{
  USHORT Magic;   // Set to 0xDA18
  USHORT Size;    // Sizeof 0xB0
  _QWORD WdFilterFlag;
  PVOID SameIndexList;
  _QWORD IndexHash;
  MP_DRIVER_INFO DriverInfo;
} MP_DRIVER_INFO_EX, *PMP_DRIVER_INFO_EX;
{{</ more >}}

> If you remember the post I wrote about WdBoot, this is the same structure I named `MODULE_ENTRY` in that post. Also this structure seems to be the extended version of `MP_DRIVER_INFO`, this recalls `IMAGE_INFO_EX` and `IMAGE_INFO` -- In this case is not a pointer is the whole structure contained. 

From here on, the code will do pretty much the same as what I explained on the post about **WdBoot**. An *IndexHash* will be calculated using the same algorithm

```C
 WCHAR  upper;
 _QWORD IndexHash =  0x4CB2F;
 while(*DriverInfo.ImageName.Buffer) {
     upper = RtlUpcaseUnicodeChar(*DriverInfo.ImageName.Buffer);
     IndexHash = HIBYTE(upper) + 0x25 * (upper + 0x25 * IndexHash);
     DriverInfo.ImageName.Buffer++;
 }
```

to then using this *IndexHash* to obtain an index in the **RuntimeDriversArray** using the following algorithm:

```C
DWROD size = (MpDriversInfo.RuntimeDriversArray >> 5) - 1;
_QWORD tmp = IndexHash & (-1 << (MpDriversInfo.RuntimeDriversArray & 0x1F))
_QWORD idx = (0x25 * (BYTE6(tmp) + 0x25 * (BYTE5(tmp) + 
              0x25 * (BYTE4(tmp) + 0x25 * (BYTE3(tmp) + 
              0x25 * (BYTE2(tmp) + 0x25 * (BYTE1(tmp) + 
              0x25 * (BYTE(tmp) + 0xB15DCB))))))) + HIBYTE(tmp)) & size;
```

> Please refer to the WdBoot post in order to get a better understanding on how all this madness actually works.

Lastly, the driver will be chained into `MpDriversInfo.RuntimeDriversList`.

![alt image](/images/wdFilter/part3/ImageVerification.png "Image Verification callback")


Everything we've seen regarding the Drivers information comes into play in one function we will see in another post called `MpQueryLoadedDrivers`. This function can be triggered by **MsMpEng** in order to obtain a copy of `MP_DRIVERS_INFO` data.

### Conclusion
And that's all for this post! I'm sorry if the driver information part is a bit messy, couldn't find a better way to explain it, I hope at least the big picture is clear. We are not far away from starting to see the filtering part of the driver -- Which as a spoiler, is quite nice -- but we still have to see some cool things along the way, for example next post I will dedicate the whole post to how **WdFilter** handles registry operations and there's some neat stuff going on there 😄.

If there's any mistake or something not clear, please don't hesitate to reach out to me on twitter [@n4r1b](https://twitter.com/n4r1B)