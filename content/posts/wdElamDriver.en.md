+++
categories = ["WdBoot", "ELAM", "Windows Defender"]
tags = ["WdBoot", "ELAM", "Windows Defender"]
date = "2019-11-05"
description = "Explanation on how the Windows Defender ELAM Driver (WdBoot) works"
images = ["https://n4r1b.com/images/wdELAM/wdElam.png"]
featured = ["https://n4r1b.com/images/wdELAM/wdElam.png"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "Understanding WdBoot (Windows Defender ELAM)"
slug =  "Understanding WdBoot (Windows Defender ELAM)"
type = "posts"
+++

Finally I'm going to talk about the Windows Defender ELAM Driver! Ever since I worked in an AV vendor I've always been interested by the features Microsoft release to help fight malware, and the ELAM is one of this features. It was introduced on Windows 8 and as a big overview basically it gives a way for a specially signed driver to execute before the initalization of boot drivers and allow or not their execution [(Oficial Microsoft documentation)](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware).

> **\*DISCLAIMER\*** 
> 
> This investigation has been done on a system running Windows 10 Pro Version 1903 (OS Build 19013.1) and `WdBoot.sys` version `4.18.1910.4`

## WdBoot Init
First let's have in mind that `winload` already load all the boot-start drivers and their dependencies into memory but now these drivers must be initialized, here is where ELAM drivers come into play (There's a couple drivers initialized before the ELAM driver, for example `CNG.sys` which allow ELAM devs to take advantage of the CNG Cryptographic Primitive Functions). Of course, ELAM drivers also have their own initialization phase, so let's get into the initalization of `WdBoot`. If we set a breakpoint in the DriverEntry we would find the following call stack:
![alt image](/images/wdELAM/InitCallStack.png "Call Stack EntryPoint WdBoot")

> WdBoot, as the other WD drivers, rely on WPP for tracing and logging. This means the code is full of WPP variables and functions, I'm not going to describe how it works but you can get more info here https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/wpp-software-tracing

After initializing WPP, the code will proceed to try an delete the value `ElamInfo` from the `WdBoot` key in the Service registry tree , this value basically will hold all the data recolected by the ELAM driver but later I will explain how and when is set (This key is not always set). The next step is to initialize the structure `MpEbGlobals`, this is the main global structure of WdBoot. Microsoft provides the name but not the declaration of it, so I'm afraid this will be a spoiler but the declaration looks something like the following:

```c
// sizeof(MP_EP_GLOBALS) == 0xB0
typedef struct _MP_EP_GLOBALS
{
  UNICODE_STRING RegistryPath;
  PVOID pHandleRegistration;
  PVOID IoUnregisterBootDriverCallback;
  DWORD Magic; // Set to 0x28EB01
  DWORD SignaturesVersionMajor;
  DWORD SignaturesVersionMinor;
  LIST_ENTRY DriversListEntry;
  PSLIST_ENTRY ElamRegistryEntries;
  PCALLBACK_OBJECT pWdCallbackObject;
  LARGE_INTEGER Cookie;
  _QWORD Unk_Unused1;
  SLIST_HEADER SlistHeader;
  DWORD LoadedDriversCount;
  DWORD LoadedDriversArrayLen;
  PVOID LoadedDriversArray; 
  DWORD TotalModulesEntryLen;
  BYTE EntryPointWdFilter[32];
  BYTE FlagWdOrMp;
  BYTE FlagTestMode;
  BYTE FlagPersistElamInfo;
  _QWORD Unk_Unused2;
} MP_EP_GLOBALS, *PMP_EP_GLOBALS;
```

This structure will be first set to zero, then the Magic, DriversListEntry, SlistHeader, FlagWdOrMp, FlagTestMode and RegistryPath will be all init/set.  

![alt image](/images/wdELAM/InitMpGlobals.png "Init MP_EP_GLOBALS")

Next step is to create the callback, the name of the callback will be different depending on the FlagWdOrMp. This flag basically determines if the driver must look for Windows Defender or Microsoft Antimalware Platform. In this case I will focus on WD case, the callback will be created with the function `ExCreateCallback` and the callback name will be `\Callback\WdEbNotificationCallback` the callback object will be saved in the corresponding member of `MP_EP_GLOBALS`.

Then function `MpEbInitModuleInformation` will be called, this function will initialize the array that will contain the modules information, to do this a pool of size 0x200 will be allocated (Tag `Ebib`), the last byte of the first 0x40 members of the array will be set to 1 (This will be used later to check if the position of the array has been written or not). Finally, the variable `LoadedDriversArray` will be set to the address of the pool and the variable `LoadedDriversArrayLen` will be set to set to 0x800 (Actually it comes from `LoadedDriversArrayLen & 0x1f | 0x800` but I've always seen it being 0x800), when used this value will all the time be shifted right by 5 (0x40).

Once that's done the address of `IoRegisterBootDriverCallback` and `IoUnregisterBootDriverCallback` will be obtained dynamically using `MmGetSystemRoutineAddress` (In case any of those two functions is not supported `WdBoot` will finish with `STATUS_NOT_SUPPORTED`). After that the fun part begins, first the driver will load the signatures (`MpEbLoadSignatures`) 

> Microsoft provides a bit of info on where this signatures should be saved. Take into acount that the ELAM Hive is unloaded after it has been used so to update it first it need to mounted (It can be found in the following path `\Windows\System32\config\ELAM`). [More Info](https://docs.microsoft.com/en-gb/windows-hardware/drivers/install/elam-driver-requirements#malware-signatures)

This function is pretty straight-forward, it will obtain a handle to the ELAM Registry which contains the key `Windows Defender` and inside this key we can found the value `Measured` (This value is measured by Measured Boot)

![alt image](/images/wdELAM/RegHiveELAM.png "ELAM Hive")

This value contains the sigantures, so `MpEbLoadSignaturesEx` will open a handle to it and `MpEbGetSignatures` will query this value to obtain the data, also it will size of the data. Both the data and the size will be returned in out parameters from `MpEbLoadSignatures`. Next step is to load the signatures from that data, the function in charge of doing that is `EbLoadSignatureData` and is quite interesting so we will look into it a bit more in-depth.

#### EbLoadSignatureData

> First, I have to acknowledge that the Federal Office for Information Security (BSI) did an investigation on TPM where they analyse a bit of the ELAM and they did a great job in how the signatures loading work, make sure to check it out [here](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/SiSyPHus/Workpackage5_TPM-Nutzung.pdf?__blob=publicationFile&v=2)

This function accepts two arguments, first one is the data previously obtained and second is the size of this data. The function will first check if the data is valid, to do this it uses the four first bytes:

```
1: kd> db rcx L4
ffffab06`9329c00c  ac 00 01 00 
```

These bytes will be used in the following way, first one is used as a Magic and the rest are used to obtain the offset to the actual signatures 

```
tmp = BYTE1(Data) | (WORD2(Data) << 8)
OffsetToSignatures = Data + tmp + 4 // We add the first four bytes
```

Then it will authenticate the data to make sure it has not been tampered, to do this it uses the function `EbAuthenticateSignatureData`. 

```
NTSTATUS __fastcall EbAuthenticateSignatureData(
    PUCHAR SignaturesData,
    ULONG SignaturesDataSize,
    _BCRYPT_RSAKEY_BLOB *MpPublicKeyRaw, 
    DWORD PublicKeySize, 
    PVOID EncryptedSignature, 
    DWORD EncryptedSignatureSize
)
```
To authenticate the data it first will obtain request the algorithm `SHA1` to the `Microsoft Primitive Provider`. This will be used to hash the data containing the signatures, then it will request the algorithm `RSA` to import a public key (This public key is embeded in the driver, and is stored in the variable `g_MpPublicKeyRaw`) which will be used to decrypt the encrypted signature and verify if it matches the previous calculated hash (`BCryptVerifySignature`) if it does then the signatures will be loaded. In order to load the signatures, the driver will parse the SignaturesData in the following way (This is a pseudocode of the real implementation, it does not include error checking and non initialized variables are):

```c
ULONG   i = 0;
ULONG   code = 0x80000000;

while(i <= SignaturesDataSize) {
    tag = BYTE(SignaturesData + i);
    EntrySize = BYTE1(SignaturesData + i) | 
              (BYTE2(SignaturesData + i) | 
              (BYTE3(SignaturesData + i) << 8) << 8);
    switch(tag) {
        case 0xA9:
            SigSize = *(DWORD *)(SignaturesData + i + 4)
            if ( BYTE(SignaturesData + SigSize + i + 8) == 9 ) {
                AddSignature((SignaturesData + i + 8), SigSize, code);
            }
            break;
        case 0x5C:
            code = *(DWORD *)(SignaturesData + i + 4);
            break;
        case 0x5D:
            code = 0x80000000;
            break;
    }
    i += 4 + EntrySize;
}
```

I hope this makes sense, here we can see a picture highlighting the different components taken into account by the parser:

![alt image](/images/wdELAM/Signtures.png "Signature Parser")

As you can see, the Signature per se is a 16 Bytes hash obtained when the tag byte is `0xA9`, also we can see tag `0x5C` contains some kind of strucute that has what it looks like the name of the signature I didn't look too much into this but in the Signatures Database values like `Trojan:Win64/Necurs.A` can be found.

Next we need to look into how the function `AddSignatures` saves the corresponding signature in a global array of signatures. First of all, the values will be added in the form of the following structure:

```
struct SIGNATURE_DATA
{
  DWORD Code;
  BYTE SignatureType;
  BYTE SignatureClassification;
  WORD SigantureSize;
  PVOID pSignature;
};
```
where the values `SignatureType` and `SignatureClassification` take some value of the following enums:

```
enum SIG_TYPE {
    THUMBPRINT_HASH = 1,
    CERTIFICATE_PUBLISHER = 2,
    ISSUER_NAME = 3,
    IMAGE_HASH = 4,
    REGISTRY = 6,
    VERSION_INFO = 7
}

enum SIG_CLASS {
    KnownGoodImage = 0,
    KnownBadImage = 1,
    KnownBadImageBootCritical = 3,
    UnknownImage = 4
}
```

The function won't do much more than allocate a pool to save the signature (Tag `EBeg`), increment the global variable that contains the size of the signatures array, and populate the structure I just mentioned. Once all the signatures have been loaded, the driver will sort this array (`MpQuickSort` based on the SignatureType) after this has been done it will iterate through the array looking for signatures with type `VERSION_INFO` or `REGISTRY`. In the first case, the pSignature will point to what it looks like a Major/Minor version (Probably the Signatures Database version) and the latter case will set two flags that will be aftewards check to see if a Registry Callback must be registered or not (In this investigation I didn't see this being used so I won't get much into it, I believe this must be something old since they are using `CmRegisterCallback` to register the callback and this function is obsolete since Windows Vista). That's pretty much how the signatures are loaded, after this has been done th driver will register a BootDriverCallback (`IoRegisterBootDriverCallback`) and proceed to enumerate the modules.

> Because I wanted to learn a bit more about Javascript Scripting in WinDBG, I though this was a great opportunity to get into it. So I wrote a little script that can displays all the signatures. It's not clean at all, just wanted to get my hands dirty with JS WinDBG scripting 😁
> 
> https://github.com/n4r1b/Windbg_WdBootScript

#### MpEbEnumerateModules

This function is the last executed in the initialization of `WdBoot`, as the name implies, it will enumerate the modules loaded by `winload` and save this data to use it when the BootDrivers callback routine gets executed. First thing this function will do is call `MpEbGetModuleInformation`, this function does the following:

![alt image](/images/wdELAM/FunFunction.png "MpEbGetModuleInformation")

returning from this function we will have an array with all the loaded modules and the size of each element from this array, as seen in the next image:

![alt image](/images/wdELAM/ModulesArray.png "Modules Array")

With this data, the function will iterate each entry of this array and for each value it will execute `MpEbAllocateDriverInfoEx` which will initialize a structure I coined `MODULE_ENTRY` which I observed that has the following declaration:

```
// sizeof(MODULE_ENTRY) == 0xB0
struct MODULE_ENTRY
{
  _QWORD Magic;         // Set to 0xB0EB01
  _QWORD WdFilterFlag;  // Set to 0xFBFBFBFBFAFAFAFA
  PVOID SameIndexSlist;
  _QWORD IndexHash;
  LIST_ENTRY DriversListEntry;
  UNICODE_STRING DriverImageName;
  UNICODE_STRING DriverRegistryPath;
  UNICODE_STRING CertPublisher;
  UNICODE_STRING CertIssuer;
  PVOID pImageHashPool;
  DWORD ImageHashAlgorithm;
  DWORD ImageHashLength;
  PVOID pCertThumbprintPool;
  DWORD ThumbprintHashAlgorithm;
  DWORD CertificateThumbprintLength;
  PVOID ImageBase;
  _QWORD ImageSize;
  DWORD ImageFlags;
  DWORD DriverClassification;
  _QWORD ModuleEntryEnd;
};
```
 `MpEbAllocateDriverInfoEx` will also set the ImageBase, ImageSize, DriverImageName and set the Flink and Blink of the DriverListEntry. Getting back to `MpEbEnumerateModules`, it will proceed to calculate the IndexHash value with the following algorithm

 ```C
 WCHAR  upper;
 _QWORD IndexHash =  0x4CB2F;
 while(*DriverImageName.Buffer) {
     upper = RtlUpcaseUnicodeChar(*DriverImageName.Buffer);
     IndexHash = HIBYTE(upper) + 0x25 * (upper + 0x25 * IndexHash);
     DriverImageName.Buffer++;
 }
 ```

 This value will then be used to calculate the index of this `MODULE_ENTRY` in the `LoadedDriversArray` using the following algorithm:

 ```C
 // Thanks Hex-Rays :)
DWROD size = (LoadedDriversArrayLen >> 5) - 1;
_QWORD tmp = IndexHash & (-1 << (LoadedDriversArrayLen & 0x1F))
_QWORD idx = (0x25 * (BYTE6(tmp) + 0x25 * (BYTE5(tmp) + 
              0x25 * (BYTE4(tmp) + 0x25 * (BYTE3(tmp) + 
              0x25 * (BYTE2(tmp) + 0x25 * (BYTE1(tmp) + 
              0x25 * (BYTE(tmp) + 0xB15DCB))))))) + HIBYTE(tmp)) & size;
 ```

> Try it yourself! (Using ASCII not Unicode) https://onlinegdb.com/BksOWHicH
>
> Please let me know if you recognize this algorithm, I couldn't find anything for the constants `0xB15DCB` and `0x4CB2F`

This non-sense will make more sense once when we see the BootDriver Callback routine. For now let's finish this function, since the size of the array may be shorter than the number of loaded modules there is chance to have collisions in the index value, that's when the member `SameIndexSlist` comes into play, this member will keep a single linked list (Is not really a SLIST_ENTRY because last entry doesn't point to NULL) for the Drivers which their computed index collide. And actually, the value saved in the `LoadedDriversArray` is a pointer to the `SameIndexSlist`. Then the function will check if the name of the module matches `WdFilter.sys` in the case it does it will set the WdFilterFlag and it will call `MpEbGetEntryPointSnapshot` which is the one that fills the member `EntryPointWdFilter` with the first 32 bytes from the `WdFilter` entrypoint. When it finishes doing this with every module, it will return from this function to the DriverEntry which will proceed to return STATUS_SUCCESS. That's pretty much how the initialization works, now let's get into the BootDriver Callback routine.

## MpEbBootDriverCallback

This is probably the main function of WdBoot, this function will determine the classification of the Driver and of course depending on this the driver will be able to initialize or not. This function was registered previously with the call to `IoRegisterBootDriverCallback`. The prototype of this callback is provided by Microsoft in the [WDK](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-boot_driver_callback_function).

```
void BootDriverCallbackFunction(
  PVOID CallbackContext,
  BDCB_CALLBACK_TYPE Classification,
  PBDCB_IMAGE_INFORMATION ImageInformation
)
```

Both `BDCB_CALLBACK_TYPE` and `_BDCB_IMAGE_INFORMATION` are also included in the WDK, so I won't get much into them. First thing this function will check if the `BDCB_CALLBACK_TYPE` is set to `BdCbStatusUpdate` (This is basically a status update provided by the system to a boot-start driver), if it is, then it will check if the driver is classified as `BdCbClassificationKnownBadImage`, in this case it will set the value `ptrSlistEntry` of the global variable `MpEbGlobals`, then it will proceed to notify all callbacks registered for [`WdEbNotificationCallback`](#WdEbNotificationCallback) and in case the flag `FlagPersistElamInfo` is set, as the name implies, it will proceed to save the colected data (`MpEbPersistElamInformation`). I will not go into much detail on how it does this, but it will basically pack all the data from each `MODULE_ENTRY` and save it along with the SignaturesVersionMajor and SignaturesVersionMinor in the key with value `ElamInfo` inside `HKLM\SYSTEM\CurrentControlSet\Services\WdBoot`.

In the case the Classification is set to `BdCbInitializeImage`, then it will proceed to try and determine the `BDCB_CLASSIFICATION`. To do this, first thing the code will do is set the Classification to `BdCbClassificationUnknownImage`, then it will try to obtain the appropriate `MODULE_ENTRY`, the function in charge of doing this is `MpEbGetModuleEntry` and this is where the previous non-sense code will make sense. Since inside the structure `_BDCB_IMAGE_INFORMATION` we have the ImageName, the driver can calculate the IndexHash with the name and then retreive the actual index (And of course, iterate the `SameIndexSlist` if necessary)

> I'm not an expert in optimization, but here is clear that this is much faster than iterating each memeber of the  `LoadedDriversArray` to compare the ImageName with the `DriverImageName` from each `MODULE_ENTRY`. And optimization is key in ELAM Drivers, Microsoft specifies some performance requirements that ELAM Drivers must meet.

In case the `MODULE_ENTRY` is not found, then `MpEbBootDriverCallback` will proceed to create this entry with the function `MpEbAllocateDriverInfoEx2` and it will also compute the `IndexHash` and it will save the newly create entry in the `LoadedDriversArray`. Then, the function `MpEbCopyImageInformation` will finish filling the `MODULE_ENTRY`, from the name of the function is pretty clear what it does, it copies all the info from `_BDCB_IMAGE_INFORMATION` into the appropiate member of `MODULE_ENTRY`. Then the function in charge of deciding the Driver classification will be called (`EbLookupProperty`), this function will pass-through the parameters to `EbLookupPropertyEx`.

#### EbLookupPropertyEx

This is **the** function, the returning result from this function will determine the classification of the driver. It is a recursive function, that has different behaviour when being called by `MpEbBootDriverCallback` than when is being called recursively (Even the arguments types change). It will be easier to understand this function by looking at the decompiler code:

![alt image](/images/wdELAM/LookupProperty.png "Lookup Property")

First of all, the Tag value corresponds to the following enum:

```c
enum LOOKUP_PROPERTY {
  CertThumbprintProperty = 1,
  CertPublisherProperty = 2,
  CertIssuerProperty = 3,
  ImageHashProperty = 4,
  EbBootDriverCallback = 5,
  EbRegistryCallback = 6
}
```

As seen on the code, this is a recursive call which will try to match one of the following driver properties with the previously loaded signatures:

- Certificate Issuer
- Certificate Publisher
- Certificate Thumbprint
- ImageHash

So, basically when this function comes from `MpEbBootDriverCallback`, it will be called in the following way `EbLookupProperty(5, &ModuleEntry->DriversListEntry, 0x90)`, which will lead to the first execution of the recursive lookup, since this execution Tag won't be `EbBootDriverCallback` and will be different from `EbRegistryCallback`, the function will prepare a `SIGNATURE_DATA` structure to call `MpBinarySearch`. As the name implies, this function will do a binary search to try and find a matching `SIGNATURE_DATA` in the array of signatures (Remember this array is kept in a global variable) in case it finds a match it will return the `SIGNATURE_DATA`. After this te recursive call returns with the signature classification, and here is where the collapsed if in the previous decompiled code does the magic:

```c
SigClass = 0; // KnownGoodImage
ImageHashClass = EbLookupPropertyEx(4,...);
if (ImageHashClass) {
    SigClass = ImageHashClass;
}
return SigClass;
```
So in the end, this function will return in `rax` one of the values from the `SIG_CLASS` enum. With this value we go back to `MpEbBootDriverCallback` where this value will be checked in the following way:

```c
SigClass = EbLookupProperty(5,...);
if (SigClass) 
{
    if (SigClass - 1) 
    {
        int tmp = SigClass - 2; 
        if (!tmp || tmp != 1) 
        {
            ImageInformation->Classification = 
                        BdCbClassificationUnknown;
            ModuleEntry->DriverClassification =
                        BdCbClassificationUnknown;
        } 
        else 
        {
            ImageInformation->Classification = 
                        BdCbClassificationKnownBadImageBootCritical;
            ModuleEntry->DriverClassification =
                        BdCbClassificationKnownBadImageBootCritical;            
        }
    } 
    else 
    {
        ImageInformation->Classification = 
                    BdCbClassificationKnownBadImage;
        ModuleEntry->DriverClassification =
                    BdCbClassificationKnownBadImage;
    }
} 
else 
{
    ImageInformation->Classification = 
                BdCbClassificationKnownGoodImage;
    ModuleEntry->DriverClassification = 
                BdCbClassificationKnownGoodImage;
}
```

If you check the `BDCB_CLASSIFICATION` you'll see that there's a bit of a mismatch between the returned value and the value assigned to Classification:

- LookupProperty return 0 == Assign BDCB_CLASSIFICATION 1 (KnownGoodImage)
- LookupProperty return 1 == Assign BDCB_CLASSIFICATION 2 (KnownBadImage)
- LookupProperty return 3 == Assign BDCB_CLASSIFICATION 3 (BadImageBootCritical)
- LookupProperty return 4 == Assign BDCB_CLASSIFICATION 0 (UnknownImage)

There's one last situation, when the driver that's going to be initialized is `WdFilter` in this case the callback will again get the first 32 bytes of `WdFilter` and compare them agains the ones obtained previously in the initialization of the `WdBoot`, in case there's a mismatch the entrypoint will be restored to it's original, the member `ModuleEntry->DriverClassification` will be set to 6 (Probably a classification that indicates that some driver tried to modify this Driver) and lastly the flag `FlagPersistElamInfo` will be set (Of course this will be logged through WPP).

![alt image](/images/wdELAM/CheckWdFilter.png "Check WdFilter")

Finally, this routine will link the `DriversListEntry` from the `MpEbGlobals` variable with the `DriversListEntry` from each `MODULE_ENTRY`. And it will add up the corresponding value to the `TotalModulesEntryLength`, this value is the sum of the lengths of various components of the `MODULE_ENTRY` and it will only be used in case the ELAM info is persisted, to know the size they must allocate for the data (Take into account that the info is only saved on BdCbStatusUpdate, and here we don't have the `MODULE_ENTRY` info so the code needs a way to know how much data it needs to allocate, that's why this value is saved as a global variable). 

![alt image](/images/wdELAM/LinkedList.png "Linked List")


## Conclusions
And that's more or less how the Windows Defender ELAM driver works. A couple more things regarding this technology. First of all, it doesn't provide security again bootkits (There are other things for that, but not ELAM), also ELAM drivers must be signed with the Early Launch EKU "1.3.6.1.4.1.311.61.4.1" and only Microsoft can sign certificates with this signature and only Anti-Malware vendors qualify for it so is not really something for general use. Finally the default policy is set to `PNP_INITIALIZE_BAD_CRITICAL_DRIVERS`, which means Unknown and BadButCritical drivers will be allowed to initialize this can be changed in the registry 

> `HKLM\System\CurrentControlSet\Control\EarlyLaunch\DriverLoadPolicy`

One last thing, Microsoft provides a sample ELAM code that can be found here https://github.com/Microsoft/Windows-driver-samples/tree/master/security/elam make sure to check it out! They use WDF which is quite cool (Even thou the WdBoot uses WDM 😅)

So, that's all folks. As always I really hope you learnt something and managed to get an overview on how Microsoft implemented their ELAM Driver. Feel free to contact me regarding any questions or any mistakes you may find. And thank you for reading this extra-long post! :)

### <a name="WdEbNotificationCallback"></a> Bonus: WdEbNotificationCallback

In this section I will explain a bit on what happens when the `WdEbNotificationCallback` is notified, which driver register for this callback and what parameters it receives.

> If you are interested in ExecutiveCallbackObjects and want to dig more into them, make sure to check the investigation [0xcpu](https://twitter.com/0xcpu) and me are doing on them (And feel free to contribute)
>
> https://github.com/0xcpu/ExecutiveCallbackObjects 

As we saw before, this callback is notified inside the `MpEbBootDriverCallback` when the `BDCB_CALLBACK_TYPE` is set to `BdCbStatusUpdate` and the `_BDCB_IMAGE_INFORMATION` specifies the driver as `BdCbClassificationKnownBadImage`. When this happens, then the function [`ExNotifyCallback`](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exnotifycallback) is executed

> This function notifies every registered routine for the callback object that is specified as the first parameter. Parameter two and three will be passed to the callback routine as Argument1 and Argument2.

If we search for occurrences of the string `\Callback\WdEbNotificationCallback` inside `Systemroot\System32`, we will see besides `WdBoot` we also find a match on `WdFilter`. So cross-referencing this string on `WdFilter` we can find that function `MpInitializeDriverInfo` is registering the function `MpBootDriverCallback` for this callback object ([`ExRegisterCallback`](https://docs.microsoft.com/en-gb/windows-hardware/drivers/ddi/wdm/nf-wdm-exregistercallback)). So let's take a quick look into the function `MpBootDriverCallback`:

![alt image](/images/wdELAM/MpBootDriverCallback.png "MpBootDriverCallback")

As we can see they are checking both Argument1 and Argument2, to make sure the notification comes from `WdBoot` and not from some other driver trying to impersonate this notification.

> ![alt image](/images/wdELAM/ExNotifyCallback.png "ExNotifyCallback")

Actually, Argument1 is a pointer to the `Magic` member of the `MP_EP_GLOBALS` structure. With this pointer, is pretty simple for `WdFilter` to use the `DriversListEntry` to iterate over the loaded drivers and get the information from the `MODULE_ENTRY` structure. And in fact, `MpCopyDriverEntry` does this and saves a local copy of the loaded drivers, creating another list entry that will be used afterwards in the function `MpQueryLoadedDrivers`. For now I'll leave it here because we have plans on doing a full research on `WdFilter` where we will explain this and much more.