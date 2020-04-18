+++
categories = ["WdFilter", "MiniFilter", "Windows Defender", "Microsoft Security"]
tags = ["WdFilter", "MiniFilter", "Windows Defender", "Microsoft Security"]
date = "2020-04-05"
description = "In this series of posts I'll be explaining how the Windows Defender main Driver works, in this fourth post we will be focusing on how WdFilter handles different registry operations"
images = ["https://n4r1b.netlify.com/images/wdELAM/wdElam.png"]
featured = ["https://n4r1b.netlify.com/images/wdELAM/wdElam.png"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "Dissecting the Windows Defender Driver - WdFilter (Part 4)"
slug =  "Dissecting the Windows Defender Driver - WdFilter (Part 4)"
type = "posts"
+++

Welcome back to Dissecting the Windows Defender Driver, in the previous part we saw how **WdFilter** manages the different handle operations for Process and Desktops Objects, also we saw everything regarding the harvest of drivers information and the verification of them. For this post we will just focus on one topic:

- Registry operations

Let's get into it!

## MpRegInitialize

This function is the one in charge of initializing the structure that will contain all the fields necessary to keep track of the registry operations. It's is called from the `DriverEntry` and first thing it will do is retrieve the following function pointers:

- [CmCallbackGetKeyObjectIDEx](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmcallbackgetkeyobjectidex)
- [CmCallbackReleaseKeyObjectIDEx](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmcallbackreleasekeyobjectidex)

Once it has those two pointer it will allocate a pool of size `0x500` with tag `MPrD` where it will proceed to initialize the structure `MP_REG_DATA` -- The pointer to the structure is saved in the global variable **MpRegData**.

{{< more C >}}
typedef struct _MP_REG_DATA
{
  USHORT Magic;     // Set to 0xDA09
  USHORT Size;      // Sizeof 0x500
  ULONG_PTR RegDataPushLock;
  PMP_REG_USER_DATA MonitoredKeys;
  ULONG MonitoredRegKeyRules;
  NTSTATUS (__fastcall *pCmCallbackGetKeyObjectIDEx)(PLARGE_INTEGER Cookie, PVOID Object, PULONG_PTR ObjectID, PCUNICODE_STRING *ObjectName, ULONG Flags);
  void (__fastcall *pCmCallbackReleaseKeyObjectIDEx)(PCUNICODE_STRING ObjectName);
  LARGE_INTEGER CmCallbackGetKeyCookie;
  INT64 field_38;
  PAGED_LOOKASIDE_LIST NotificationsLookaside;
  FAST_MUTEX CmUnregisterFastMutex;
  LARGE_INTEGER CmRegisterCallbackCookie;
  INT OpenConnectionPortsCount;
  UNICODE_STRING LoadAppInitString;
  LIST_ENTRY ServiceKeyHardeningList;
  FAST_MUTEX CallCtxFastMutex;
  LIST_ENTRY CallCtxList;
  INT64 Unk;
  INT64 Unk1;
  PAGED_LOOKASIDE_LIST CreateKeyCtxLookaside;
  PAGED_LOOKASIDE_LIST SetValueKeyCtxLookaside;
  PAGED_LOOKASIDE_LIST DeleteValueKeyCtxLookaside;
  PAGED_LOOKASIDE_LIST DeleteKeyCtxLookaside;
  PAGED_LOOKASIDE_LIST RegDataEntry;
  PAGED_LOOKASIDE_LIST KeyNamesLookaside;
  PAGED_LOOKASIDE_LIST RenameKeyCtxLookaside;
} MP_REG_DATA, *PMP_REG_DATA;
{{</ more >}}

After initializing the events and the lookaside lists, in case we are running either **MpFilter** or a Windows version older than Win8.1 the function will proceed to register a registry callback that's meant for hardening keys, shortly we will see the behavior of this callback (`MpRegHardeningCallback`).

Finally, the list of hardened keys will be created inside `MpRegCreateHardeningList`, this function will obtain a handle to the **CurrentControlSet** key, then it will iterate an array of hard-coded services keys -- Actually is an struct with the key name and a flag that determines if it's related to **MpFilter** or **WdFilter** -- and for those that match the criteria their full key name will be chained into `MpRegData->ServiceKeyHardeningList`. On a machine with **WdFilter** the following keys would match:

![alt image](/images/wdFilter/part4/HardenedKeys.png "Hardened Keys under WdFilter")


## MpRegHardeningCallback

As seen in the previous section, the initialization routine register a registry callback meant for hardening keys. As every registry callback routine the prototype of this function is [EX_CALLBACK_FUNCTION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-ex_callback_function), and in this case no context is going to be passed into this routine. 

This function will only focus on the case where *Argument1* is **RegNtQueryValueKey**, which implies that *Argument2* contains the structure [REG_QUERY_VALUE_KEY_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_reg_query_value_key_information). If *Argument1* is the expected then `MpRegPreQueryValueKey` will be called, this function is quite simple and it's pseudocode looks something like this:

```C
valueName = QueryValueKeyInfo->ValueName

if (!valueName || !RtlEqualUnicodeString(valueName, &MpRegData->LoadAppInitString, 1))
  return STATUS_NO_MATCH;

if (MpGetProcessContextByObject(IoGetCurrentProcess(), &processCtx)) {
  if (processCtx->processFlags & (MsSecesProcess|MpServiceSidProcess)) {
    return STATUS_ACCESS_DENIED;
   } else {
    MpReleaseProcessContext(processCtx);
    return STATUS_SUCCESS;
  }
}
```

I still don't have a clue why is the access being denied to process with the **MpServiceSid**. Even thou, being a callback that's only registered if running a version of Windows under NT 6.3 it may have to do something with that. In case someone can shed some light on this topic I would kindly appreciate it! :D

## MpRegCallback

Finally we get into the main routine for handling registry operations, this routine is registered inside `MpRegisterRegCallback`, which is the last function called in the `DriverEntry`. As with the previous registry routine, `MpRegCallback` function prototype is also `EX_CALLBACK_FUNCTION`. And again, no context will be registered for this function.

> This routine is registered using [CmRegisterCallback](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallback) instead of `CmRegisterCallbackEx`, may be legacy code not modified since this function is obsolete since Windows Vista.

Getting into the actual registry callback routine, the function will begin by checking if the *Argument1* -- which keeps a value from within the enum [REG_NOTIFY_CLASS](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_reg_notify_class) and identifies the type of registry operation -- contains one of the monitored *Pre* operations values from which it will retrieve some data from the structure contained in *Argument2* -- As stated on the msdn, *Argument2* has a pointer to a structure that contains information that is specific to the type of registry operation -- to determine this, the following bitmask is used `0x220000000017`. I will save you the time of determining which `REG_NOTIFY_CLASS` values match the bitmask:

- RegNtDeleteKey        = 0 
- RegNtSetValueKey      = 1
- RegNtDeleteValueKey   = 2 
- RegNtRenameKey        = 4
- RegNtPostRestoreKey   = 2Ah
- RegNtPreReplaceKey    = 2Dh

For pretty much all of these values, the function will retrieve the registry key *Object* that's inside the structure. The only one that differs is the case of `RegNtRenameKey` where the *NewName* will also be saved into a local.

> Even thou **RegNtPreCreateKeyEx** is not checked with the bitmask, actually the first check done in the function is to see if *Argument1* contains the value RegNtPreCreateKeyEx (0x1A), and in this case the pointer to the structure `REG_CREATE_KEY_INFORMATION_V1` is copied to a local.

Once the function has the necessary values, it will proceed to check if the process that trigger the callback is one of the following:

- System
- MsMpEng
- FriendlyProcess (`ProcessCtx->ProcessFlags & 0x20`)
- MpServicesSidProcess (`ProcessCtx->ProcessFlags & 0x10`)

If the process meets any of the previous checks then `MpRegHardeningIsMatch` won't be called for this operation, shortly we will visit that function but first we need to check some pre-processing that's done in case the previous check is not met. This pre-processing can take three paths: 

- First path is regarding the case of key creation, this path will mainly check if the key to be created already exists, in order to do this it calls `MpRegpCheckExistingKey` -- This function will basically try to get a handle to the object using the *RootObject* and then try to open this key, also the function will return a copy of the *CompleteName*. 

- Second case applies to **RegKeyNewName**, for this path the function will first obtain the *ObjectName* using function `MpRegpGetKeyName` -- This function will call [CmCallbackGetKeyObjectIDEx](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmcallbackgetkeyobjectidex) if running Windows 8 or above, in any other case it will pop an entry from `MpRegData->KeyNamesLookaside` and use [ObQueryNameString](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obquerynamestring) to obtain the object name -- using the function name and the *NewName* it will create a new unicode string which will be used afterwards to call `MpRegHardeningIsMatch`

- Last path applies to all the other registry operations we saw before, and is quite simple. It will call `MpRegpGetKeyName` to get the object name to then call `MpRegHardeningIsMatch`

> It's curious to see they use `ObQueryNameString` instead of `CmCallbackGetKeyObjectID`, the latter is available since Windows Vista. Which makes me wonder if this piece of code has been like this since Windows XP and maybe they updated it on Windows 8 to use `CmCallbackGetKeyObjectIDEx` which became available. Just a random thought 😁

Last step before starting with the actual processing of the operations is to check if the key involved matches one of the hardened keys. As already said this is done inside `MpRegHardeningIsMatch`, this function receives a unicode string as only parameter and it will iterate the list `MpRegData->ServiceKeyHardeningList` checking if the regkey passed as parameter match any of the list -- `RtlPrefixUnicodeString` -- if it does then it will return `TRUE`. If this function returns true, then no matter what type operation is being done the registry callback will return `STATUS_ACCESS_DENIED`

Finally we get into the actual processing of the different registry operations, first step in this process is to check two bitmasks. First one (`0x66000C0B8017`) contains all the registry operations that the callback will check, second one (`0x4400080B8000`) contains all the Post operations checked, and will be used in order to know if a **CallCtx** can be fetched -- Later we will see more about this **CallCtx** stuff.

As before I'll save you the time of checking these bitmasks (I'll omit the values checked before, but those are included in the bitmask that contains all operations):
       
- RegNtPostDeleteKey  = 0Fh       
- RegNtPostSetValueKey  = 10h     
- RegNtPostDeleteValueKey  = 11h  
- RegNtPostRenameKey  = 13h       
- RegNtPostCreateKeyEx  = 1Bh     
- RegNtPostRestoreKey  = 2Ah      
- RegNtPostReplaceKey  = 2Eh

After those two checks the code will go into a switch statement that will end up calling the specific subfunction that will handle the registry operation. I will divide these subfunctions in different sections that will contain the different pre-operations for each type of operation, then we will discuss all the post-operations in one section since they are pretty much the same.

> **Disclaimer:** These subfunctions don't differ much but we will at least see the function prototype and structures/enums involved in each one. Also, by the name of the function it can be implied to which type of operation they correspond.

### MpRegPreCreateKeyEx 

```C
NTSTATUS MpRegPreCreateKeyEx(
  PREG_CREATE_KEY_INFORMATION_V1 CreateKeyInfo, 
  ULONG MonitoredKeysRules, 
  PKeyCtx *CreateKeyCtx, 
  PBOOLEAN AccessDenied, 
  PUNICODE_STRING KeyName, 
  BOOLEAN KeyExist
);
```
The function will start by doing a sanity check on *CreateKeyInfo* and *CreateKeyCtx*, if everything is fine it will check that **CreateKeyOperation** (`0x1`) is active in *MonitoredKeysRules*, after that if no *KeyName* is provided then function `MpRegpCheckExistingKey` will be called in order to obtain the *KeyName* and to check if the *KeyExisy*. In case the key is found the function will return, in case it doesn't `MpRegMatchData` will be called 

> `MpRegMatchData` is probably the most important function regarding registry operations and we will discuss it in detail later in the post, for now let's imagine that this function will check the *KeyName* against a list of keys and if found it will return the rules that apply to it

if `MpRegMatchData` doesn't find a matching key then te function will return, on the other hand if a matching key is found then the code will check if **CreateDenied** (`0x10000`) is active for that key, if the value is active then it will proceed to check if the process trying to create the key match any of the following requirements:

- `ProcessCtx->ProcessRules` has **AllowAllRegistryOperations** (`0x400`) set.
- The process is a ExcludedProcess (`ProcessCtx->ProcessFlags & 0x1`)
- The process is a FriendlyProcess (`ProcessCtx->ProcessFlags & 0x20`)
- The process is a MpServiceSidProcess (`ProcessCtx->ProcessFlags & 0x10`)

if any of these requirements is met, then the access won't be denied, but if the process doesn't match the requirements then parameter *AccessDenied* will be set to `TRUE` and a notification throughout `MpRegpSendNotification` will be sent. 

There's another case where they key rules don't have the **CreateDenied** bit set, but it has the **CreateKeyOperation** bit set. In this case, a **CallCtx** will be created. This **CallCtx** has a union which differs depending which type of operation is representing, for the creation the **CallCtx** will look like this:

```C
typedef struct _CallCtx
{
  USHORT Magic;     // Set to 0xDA0B
  USHORT Size;      // Sizeof 0x38
  PVOID FreeKeyCtx; // Points to MpRegpFreeCreateKeyContext 
  LIST_ENTRY CallCtxList;
  PKTHREAD CurrentThread;
  PUNICODE_STRING KeyName;
  union TypeOfOperation {
      PMP_REG_MATCH_INFO MatchInfo;
  } CreateAndDeleteKey;
} CallCtx, *PCallCtx;
```

Finally this created **CallCtx** will be copied into the out-param *CreateKeyCtx*, so then it can be inserted into the `MpRegData->CallCtxList` by calling `MpRegpInsertCallContext`. 

![alt image](/images/wdFilter/part4/PreCreateKey.png "Pre-operation CreateKey CallCtx")

Since this was the first one I got into a bit more of detail, next ones are pretty similar so the explanation will be a bit more shallow.

### MpRegPreRestoreKey 

```C
NTSTATUS MpRegPreRestoreKey(
  PREG_RESTORE_KEY_INFORMATION PreRestoreKeyInfo, 
  ULONG MonitoredKeysRules, 
  PKeyCtx *RestoreKeyCtx,
  PBOOLEAN AccessDenied, 
  PUNICODE_STRING KeyName
);
```
Also we start with the sanity checks and checking if **RestoreKeyOperation** (`0x4000`) is active in the *MonitoredKeysRules*. If we don't have the *KeyName* then it will be obtained by calling `MpRegpGetKeyName`. Wit the *KeyName* `MpRegMatchData` will be called and as we saw previously there's three options. First no matching data is found so the function will return. Second matching data is found and bit **RestoreDenied** (`0x200000`) is set, in this case it will again check the process requirements and if they are not met it will set *AccessDenied* to `TRUE` and send a notification. Last option is that matching data is found but it only has the **RestoreKeyOperation** bit set in which case the following **CallCtx** will be created -- The **CallCtx** used by this operation is the one meant for the renaming of keys operation, is even allocated with function `MpRegpAllocRenameKeyContext`

```C
typedef struct _CallCtx
{
  USHORT Magic;     // Set to 0xDA19
  USHORT Size;      // Sizeof 0x40
  PVOID FreeKeyCtx; // Points to MpRegpFreeRenameKeyContext 
  LIST_ENTRY CallCtxList;
  PKTHREAD CurrentThread;
  PUNICODE_STRING KeyName;
  union TypeOfOperation {
      PUNICODE_STRING KeyNewName;
      PMP_REG_MATCH_INFO MatchInfo;
  } RenameKey;
} CallCtx, *PCallCtx;
```
And again this context is saved in the parameter *RestoreKeyCtx* to then be added to the **CallCtx** list.

### MpRegPreReplaceKey 

```C
NTSTATUS MpRegPreReplaceKey(
  PREG_REPLACE_KEY_INFORMATION ReplaceKeyInfo, 
  ULONG MonitoredKeysSig, 
  PCallCtx *RenameKeyCtx, 
  PBOOLEAN AccessDenied, 
  PUNICODE_STRING KeyName
);
```
Same behavior as before but, of course, the bits checked differ. Bits checked in this function are the following:

- ReplaceKeyOperation (`0x8000`)
- ReplaceDenied (`0x100000`)

This operation will also use the RenameKey **CallCtx**, so is the same one we just saw in the previous section. 

### MpRegPreSetValueKey
```C
NTSTATUS MpRegPreSetValueKey(
  PREG_SET_VALUE_KEY_INFORMATION SetValueKey, 
  ULONG MonitoredKeysRules, 
  PCallCtx *SetValueKeyCtx, 
  PBOOLEAN AccessDenied, 
  PUNICODE_STRING KeyName
);
```

This function also has the same behavior but when it calls `MpRegMatchData` it will also provide the *ValueName* that is going to be added, so the *KeyName* and the *ValueName* must match. Again if a match is found the function will check for the following two values:

- SetValueKeyOperation (`0x100`)
- SetValueDenied (`0x80000`)

There's one little detail in this operation, the rule that match may have the value **SetValueRetrieveKeyValueInfo** (`0x400`) set. If this is the case then `MpRegpQueryValueKeyByPointer` will be called in order to obtain the [key partial information](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_value_partial_information) of the value.

Finally, if the access was not denied but the bit **SetValueKeyOperation** is set then the following **CallCtx** will be created:

```C
typedef struct _CallCtx
{
  USHORT Magic;     // Set to 0xDA0C
  USHORT Size;      // Sizeof 0x48
  PVOID FreeKeyCtx; // Points to MpRegpFreeSetValueContext 
  LIST_ENTRY CallCtxList;
  PKTHREAD CurrentThread;
  PUNICODE_STRING KeyName;
  union TypeOfOperation {
      PKEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
      ULONG KeyType;
      PMP_REG_MATCH_INFO MatchInfo;
  } SetValueKeyCtx;
} CallCtx, *PCallCtx;
```

In the following image we can see an example of this **CallCtx**:

![alt image](/images/wdFilter/part4/PreSetValueKey.png "Pre-operation SetValueKey CallCtx")

### MpRegPreDeleteValueKey

```C
NTSTATUS MpRegPreDeleteValueKey(
  PREG_DELETE_VALUE_KEY_INFORMATION DeleteValueKeyInfo, 
  ULONG MonitoredKeysRules, 
  PCallCtx *DeleteValueKeyCtx, 
  PBOOLEAN AccessDenied, 
  PUNICODE_STRING KeyName
);
```

This function has the same behavior as `MpRegPreSetValueKey`. It also passes the *ValueName* to `MpRegMatchData` and the checks done in case there's a match are the following:

- DeleteValueKeyOperation (`0x800`)
- DeleteDenied (`0x40000`)

And again we have a value in case the key partial information must be retrieved, **DeleteValueRetrieveKeyValueInfo** (`0x2000`). Finally, in case a **CallCtx** is created it will look something like this:

```C
typedef struct _CallCtx
{
  USHORT Magic;     // Set to 0xDA0D
  USHORT Size;      // Sizeof 0x48
  PVOID FreeKeyCtx; // Points to MpRegpFreeDeleteValueContext 
  LIST_ENTRY CallCtxList;
  PKTHREAD CurrentThread;
  PUNICODE_STRING KeyName;
  union TypeOfOperation {
      PUNICODE_STRING ValueName;
      PKEY_VALUE_PARTIAL_INFORMATION KeyValueInfo;
      PMP_REG_MATCH_INFO MatchInfo;
  } SetValueKeyCtx;
} CallCtx, *PCallCtx;
```
### MpRegPreRenameKey

```C
NTSTATUS MpRegPreRenameKey(
  PREG_RENAME_KEY_INFORMATION RenameKeyInfo, 
  ULONG MonitoredKeysRules, 
  PCallCtx *RenameKeyCtx, 
  PBOOLEAN AccessDenied, 
  PUNICODE_STRING KeyName
);
```
In this function behavior differs a bit from the other cases since there's two *KeyName's* to match, one for the key before it's renamed and a second one for the renamed key. So `MpRegMatchData` is called two times with both *KeyNames* and if both match then the rules are OR'ed. Everything else works in the same fashion as previously explained. The checked values are the following:

- RenameKeyOperation (`0x4`)
- RenameDenied (`0x20000`)

In case a **CallCtx** is created, the type of the context is the one we saw previously in `MpRegPreRestoreKey`

![alt image](/images/wdFilter/part4/PreRenameKey.png "Pre-operation rename key")

### MpRegPreDeleteKey
```C
NTSTATUS MpRegPreDeleteKey(
  PREG_DELETE_KEY_INFORMATION DeleteKeyInfo,
  ULONG MonitoredKeysRules, 
  PCallCtx *DeleteKeyCtx, 
  PBOOLEAN AccessDenied, 
  PUNICODE_STRING KeyName
);
```
Behavior for this pre-operation is exactly the same as the one we saw for the Create key pre-operation, the values checked are the following:

- DeleteKeyOperation (`0x10`)
- DeleteDenied (`0x40000`)

and in case a **CallCtx** is created, the type of the context is the same as for the create key operation, it only differs in the `CallCtx->Magic` which in this case is set to `0xDA11`


> One detail I forgot to mention is that there is a special value that can be set in the rules of the RegKey which I called **TamperProtectionActive** (`0x400000`), if this value is set the access will be denied no matter which process is trying to perform the operation on that key. 

### Post-operations

First things first, as we saw before in the post there is a bitmask for the post-operations and when the *RegNotifyClass* matches any of these values then function `MpRegpFetchCallContext` will be called. This function, as the name says, fetches a **CallCtx**. A pseudocode of this function would be something like this:

{{< more C >}}

PCallCtx MpRegpFetchCallContext() 
{
  CurrentThread = KeGetCurrentThread();
  CallCtx = (PCallCtx) CONTAINING_RECORD(MpRegData->CallCtxList.Flink, CallCtx, "CallCtxList");
  if (CallCtx != &MpRegData->CallCtxList) {
    while (1) {
      nextCallCtx = CallCtx->CallCtxList.Flink;
      if (CallCtx->CurrentThread == CurrentThread)
        break;
      CallCtx = nextCallCtx;
      if (nextCallCtx == &MpRegData->CallCtxList) 
        goto End;
    }
    // Sanity checks and unchaining
  }
End:
  return CallCtx;
}
{{</ more >}}

As you can see basically it will walk the **CallCtx** list entry and try to find one context that matches the same *CurrentThread* that was set when the context was created in the pre-operation.

> This is safe since, as stated in the MSDN: "A RegistryCallback executes at IRQL = PASSIVE_LEVEL and in the context of the thread that is performing the registry operation." Basically we can assume pre and post will execute in the same thread. The following image shows the post-operation from the Create pre-operation shown in the section "MpRegPreCreateKeyEx", thread object is the same for both operations.
>
> ![alt image](/images/wdFilter/part4/PostOperation.png "Post-operation thread safe")


So after we have the expected **CallCtx** the code will go again into the switch statement to enter into the corresponding post-operation function. All of this post-operation functions will do the same, first do a sanity check checking if a **CallCtx** is passed as an argument and then checking if the `CallCtx->Magic` matches the one expected from that type of operation. If sanity checks are correct, then the function will proceed to create a `RegNotification` and send it throughout `MpRegpSendNotification` -- We'll see both the notification structure and the function later in the post.

## MpRegMatchData

```C
NTSTATUS MpRegMatchData(
  PUNICODE_STRING KeyName, 
  PUNICODE_STRING ValueName, 
  ULONG Flags, 
  PMP_REG_MATCH_INFO *MatchingInfo
);
```
Finally we get into the function that actually checks if certain type of operation on a Key is allowed. First thing this function will do is obtain a pointer to the data that keeps the keys that will be monitored, this pointer can be obtained from `MpRegData->MonitoredKeys`. 

> In case you are curios this data comes from user space -- Parsed in the function MpRegUpdateData -- more specifically it comes from **MpRtp.dll**, which is the Real-time protection module of the Windows Defender. Since I'm just focusing on the kernel I didn't check how this data is obtained. But is a nice project to look into it (Even thou is C++... maybe in the future 🤔) 

Going back to `MpRegData->MonitoredKeys`, this member contains a pointer to a `MP_REG_USER_DATA` structure, which looks like this:

```C
typedef struct _MP_REG_USER_DATA
{
  int DataSize;
  int NumberOfEntries;
  PMP_KEY_ENTRY MonitoredKeysTree;
  ULONG MonitoredKeysRules;
} MP_REG_USER_DATA, *PMP_REG_USER_DATA;
```

With this data the function can start to search if the *KeyName* is included in the monitored keys, in order understand how this is done we first need to understand how the data is layout. First we need to know the definition of the structure I coined `MP_KEY_ENTRY`:

```C
typedef struct _MP_KEY_ENTRY
{
  PMP_KEY_ENTRY SubKey;
  PMP_KEY_ENTRY NextKey;
  PWSTR KeyName;
  USHORT KeysToSkip;
  PMP_CLIENT_VALUE ClientList;
  PMP_KEY_VALUE ValuesList;
} MP_KEY_ENTRY, *PMP_KEY_ENTRY;
```

as you can see the structure keeps a pointer to a *SubKey*, a *NextKey* (Both of type `MP_KEY_ENTRY`) and a *KeyName*. So as you may have already guess the data is laid out in a kind of binary tree. So the pseudocode of how this data will be walked looks something like this (It's super simplified):

{{< more C >}}
keyEntry = MpRegData->MonitoredKeys->MonitoredKeysTree; // Root KeyName => Registry

while (1) {
  FsRtlDissectName(&keyNameToMatch, &firstName, &remainingName);

  if (keyEntry->KeyName) {
    partialMatch = MpRegpMatchName(keyEntry->KeyName, &FirstName);
  } else {
    if (keyEntry->KeysToSkip == 0xFFFF) {
      partialMatch = TRUE;
    } else {
      // Used to skip key paths that have KeyNames that differ on each PC (Like User's SID)    
      do {
        FsRtlDissectName(&keyNameToMatch, &tmp, &remainingName)
      }
      while(keyEntry->KeysToSkip)
      partialMatch = tmp.Length != 0;
    }
  }

  if (!partialMatch) {
    keyEntry = keyEntry->NextKey;
    continue; 
  } 

  MpRegpMatchEntry(....);
  if (keyEntry->NextKey) {
    // The function keeps a stack of non-visited nextKeys, in order to come back later
    MpRegpPushEntryToStack(....);
  }
  keyEntry = keyEntry->SubKey;

  if (!keyEntry) {
    // I'm leaving out some checks here that would check if there's 
    // entries in the stack, if there are no entries it means we reached
    // the end so we would break 
    MpRegpPopEntryFromStack(....);
  }

  keyNameToMatch = remainingName;
}
{{</ more >}}

So as you can see, the algorithm is not that hard. The whole KeyName will be dissect and the first name will be compared against the actual entry, if it matches then we go to the *SubKey* and we save the *NextKey* in the non-visited stack. In case the entry *KeyName* didn't match then the algorithm will go to the *NextKey* if there is, if there is no *NextKey* then an entry will be poped from the stack and the same will be repeated -- I hope this is more or less clear :).

So now the last step, you may have noticed an strange function in the middle of the algorithm, `MpRegpMatchEntry`. This function is the one that fills the structure `MP_REG_MATCH_INFO` which is then returned to the pre-operation functions and contains the rules that apply to the Key being manipulated. 

This function will only execute if the key path to check has matched fully. If this is the case then there's two possible paths. First path is for every operation other than **SetValueKeyOperation** and **DeleteValueKeyOperation**, in this case the `MP_KEY_ENTRY->ClientList` will be obtained, this member contains the following structure:

```C
typedef struct _MP_CLIENT_VALUE
{
  PMP_CLIENT_VALUE NextClientValue;
  BYTE ValueHash[16];
  ULONG KeyRules;
} MP_CLIENT_VALUE, *PMP_CLIENT_VALUE;
```

second path is for the case of *SetValueKey* and *DeleteValueKey*, in this case `MP_KEY_ENTRY->ValuesList` will be obtained, and this member contains the following structure:

```C
typedef struct _MP_KEY_VALUE
{
  PMP_KEY_VALUE NextKeyValue;
  PWSTR KeyValueName;
  PMP_CLIENT_VALUE ClientValue;
} MP_KEY_VALUE, *PMP_KEY_VALUE;
```
in order for the function to obtain the `MP_KEY_VALUE->ClientValue`, the *ValueName* that the operation wants to set or delete must match the one from the structure.

An mainly how the function will work is by comparing the `MP_CLIENT_VALUE->KeyRules` with the *Flag* passed as an argument when calling `MpRegMatchData`

> This flag is build in every pre-operation function, and keeps both values we saw in each pre-operation. For instance for a key creation this flag would be: `CreateDenied | CreateKeyOperation (0x100001)`

if the comparison of the flag with the *KeyRules* returns true then a `MP_REG_MATCH_INFO` structure will be allocated and the *KeyRules* and *ValueHash* will be copied

```C
typedef struct _MP_REG_MATCH_INFO
{
  INT HashesCount;
  ULONG HashesArrayLen;
  _OWORD (*HashesArray)[];
  BYTE KeyValueInfoFlag;
  ULONG KeyRules;
} MP_REG_MATCH_INFO, *PMP_REG_MATCH_INFO;
```

> The *ValueHash* is not used in the WdFilter, but since this is sent to the **MsMpEng** I guess it's probably used there. Also, I'm not sure what the hash represents, since this hash comes from **MpRtp** I don't know which data is being hashed.

Lastly, since this is super painful to debug I decided to practice my JavaScript debugger scripting and wrote the following [**script**](https://gist.github.com/n4r1b/2d913f50e9de4767df96bf0fc01b757b) that has two options:

- Create an instance of an MP_KEY_ENTRY, MP_KEY_VALUE or MP_CLIENT_VALUE

```C
> dx Debugger.Utility.Analysis.WdFilterExtension.RegUserData()
```

- List all the monitored keys

```C
> !mpRegData
> dx Debugger.Utility.Analysis.WdFilterExtension.RegUserData()
```

The script is not bulletproof, just wrote it to make the debugging easier for me, but it has many flaws (For example, not showing the whole key path to get to a specific `MP_KEY_ENTRY`) thou it comes in handy if we use it with [LINQ](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/using-linq-with-the-debugger-objects) syntax to search for a specific *KeyName* or *ValueName*. For example we could run the following query to search for an entry that has the *KeyName* **MsMpEng.exe**, and then check which rules apply to this key.

```js
> dx -r1 @$mpRegUserData().MpRegUserData.MonitoredKeysTree.Select(p => new { 
    Name = p.KeyName, 
    Client = p.ClientList.Select(n => new { Hash = n.ValueHash, KeyRules = n.KeyRules })
  }).Where(p => p.Name != 0x0 && p.Name.ToDisplayString("su").ToLower().Contains("msmpeng.exe"))
```

The following picture shows this query and one looking for the monitored values inside the *Windows Defender* key.

![alt image](/images/wdFilter/part4/WindbgScript.png "Example WinDbg script")

## MpRegpSendNotification

As seen during the post there's two possible ways for the Registry Callback to send a notification. First, one in case the operation is denied. And Second, in case a pre-operation creates a **CallCtx** so the post-operation will retrieve this context and send a notification. The function in charge of preparing the notification is `MpRegpSendNotification`. This function is quite simple, and since the post is already super long I won't get into all the little details. Mainly this function will receive a pointer to a structure I named `RegNotification` which looks like this:

{{< more C >}}
typedef struct _RegNotification
{
  PVOID KeyObject;
  PUNICODE_STRING KeyName;
  PUNICODE_STRING ValueName;
  PUNICODE_STRING NewKeyName;
  PUNICODE_STRING OldFileName;
  PUNICODE_STRING NewFileName;
  ULONG ValueType;
  ULONG ValueDataSize;
  PVOID ValueData;
  ULONG NewValueType;
  ULONG NewValueDataSize;
  ULONG RegRestoreFlags;
  PVOID NewValueData;
  ULONG FinalKeyRules;
  PMP_REG_MATCH_INFO MatchInfo;
} RegNotification, *PRegNotification;
{{</ more >}}

As you may notice, this structure contains fields for every possible operation this means they use the same structure for every registry operation, and just populate the fields that apply in each operation. 

With this information `MpRegpSendNotification` will calculate the necessary size of the buffer to allocate for the notification, and then proceed to allocate it by calling `MpAsyncCreateNotification`. This `AsyncMessageData` buffer will contain the following data type in the union *TypeOfMessage*:

{{< more C >}}
typedef struct _RegOperationMessage
{
  INT64 OffsetKeyName;
  INT64 OffsetValueName;
  INT64 OffsetNewKeyName;
  INT64 OffsetOldFileName;
  INT64 OffsetNewFileName;
  AuxPidCreationTime Process;
  HANDLE ThreadId;
  DWORD SessionId;
  ULONG FinalKeyRules;
  ULONG NewValueType;
  ULONG BufferNewValueDataLen;
  INT64 OffsetNewValueData;
  ULONG ValueType;
  ULONG BufferValueDataLen;
  INT64 OffsetValueData;
  ULONG RegRestoreFlags;
  GUID TransactionId;
  INT HashesCount;
  INT64 OffsetHashesArray;
} RegOperationMessage, *PRegOperationMessage;
{{</ more >}}

> There's a helper function that is the one in charge of copying the data from the `RegNotification` to the `RegOperationMessage`. In case you'd like to look at it, this function is `MpRegpCopyVariableNotificationData`

Finally, the message will be sent either synchronously in case the `ProcessCtx->ProcessRules` have the bit **NotifyRegistryOperationSync** (`0x200000`) active or asynchronously in any other case -- For the sync message the type of operation will be set to **RegistryEventSync** (`0x2`).

![alt image](/images/wdFilter/part4/SendNotification.png "Send notification")

## Conclusion

And that's all for this part folks! Again sorry for the long post but I believe this is one of the coolest parts of the driver so I wanted to get a bit in depth with some things. The next post we will end up code non-related to the minifilter capabilities of the driver!! We will see the different messages **MsMpEng** can send to **WdFilter** in order to trigger different operations like adding a process to the excluded list or creating a section for a data scan! If this sounds cool, see ya in the next post! :)

As always if there's any mistake or something not clear, please don't hesitate to reach out to me on twitter [@n4r1b](https://twitter.com/n4r1B)