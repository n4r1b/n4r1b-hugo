+++
categories = ["Kernel"]
tags = ["Kernel", "LoadLibrary"]
date = "2019-03-16"
description = "Looking into the roots of how the kernel handle the LoadLibrary function"
images = ["https://n4r1b.netlify.com/images/loadLibrary/loadLibrary.jpg"]
featured = ["https://n4r1b.netlify.com/images/loadLibrary/loadLibrary.jpg"]
featuredalt = ""
featuredpath = "date"
linktitle = ""
title = "Part 1: Digging deep into LoadLibrary"
slug = "Part 1: Digging deep into LoadLibrary"
type = "posts"
+++

Welcome back! Here we are again with the Kernel, today we are going to talk about one of the most, if not the most, famous functions from the Windows API, LoadLibrary. The motivation to do this research comes from a project I was wroking on a couple of weeks ago, where I was writing a reflective loader of a DLL and I wasn't able to make it work (Finally it had to do with some reloc stuff), so yeah, I thought the best way to find my error was to look how Windows handle the load library process.

## Disclaimer!
I will focus on the Kernel code that gets executed when LoadLibrary is executed. Everything that goes on Userland I will just skim through it. On the other hand, I won't go into every call/instruction inside the Kernel, believe, there is **A LOT** of code there. I will focus on what I believe are the most important functions and structures.


## LoadLibrary!
For the investigation I will use this little snippet:

```cpp
int WinMain(...) {
    HMODULE hHandle = LoadLibraryW(L"kerberos.dll");
    return 0;
}
```

I use the Unicode function because the kernel only works with these kind of Strings, and so I save some time will doing the research 😁

The first thing that happen when LoadLibraryW gets executed is that execution gets redirected into the DLL **KernelBase.dll** (These has to do with the new MinWin Kernel that Windows adopted since Windows 7. [More info](https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html)), inside KernelBase the first function that will be called is **RtlInitUnicodeStringEx** to obtain a UNICODE_STRING with the parameter passed to LoadLibrary (This is a Struct not a String!!) next, we get into the function **LdrLoadDLL** (Prefix Ldr == Loader) where the parameter in ```r9``` is an out param which will have the handle of the loaded module. After this we get into the private version of this function **LdrpLoadDll**, these two functions is where all the interesting code of Userland will get executed. After some sanity checks and getting inside some more functions we finally get into the first jump into kernel code. The kernel function to execute is **NtOpenSection** and is the one that Im going to be focusing on this post. Here we can see the call stack just before going into the kernel.

![alt img](/images/loadLibrary/call_stack_userland.jpg "UserLand CallStack")

## NtOpenSection

First thing we need to know is what does "Section" stands for, going into the Windows Drivers doc in the Memory Managment chapter there is a section called ["Section Objects and Views"](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views) where it can be read that a "Section Object" represents a memory region that can be shared and that this object provides a mechanism for a process to map a file into its memory address space (That's pretty much quoting the doc)

> Bear in mind that Windows Kernel, even thought is written almost entirely in C, it's kinda Object Oriented (It's no 100% Object Oriented, Inherit principles are not followed strictly) that's why we usually speak about Object whitin the kernel. In this case "Section Object"

So, with that definition of a section in mind, it makes complete sense that **NtOpenSection** is the first Kernel function that gets sexecuted when loading a library.

Let's get the party started, first let's see the arguments this function will receive. As you can see, there will be 3 arguments (We are on x64 so following __fastcall calling convention the first 4 params go into registers)

-  ```rcx``` -> PHANDLE pointer that receives the handle to the Object
-  ```rdx``` -> ACCESS_MASK requested access to the Object
-  ```r8```  -> POBJECT_ATTRIBUTES pointer to the OBJECT_ATTRIBUTES of the DLL

This 3 arguments can be seen in the next Image:

![alt img](/images/loadLibrary/params_opensection.jpg "Params NtOpenSection")

the ACCESS_MASK is a combination of the following values, which can be obtained in the [winnt.h](https://www.codemachine.com/downloads/win10/winnt.h) header
```cpp
#define SECTION_QUERY                0x0001
#define SECTION_MAP_WRITE            0x0002
#define SECTION_MAP_READ             0x0004
#define SECTION_MAP_EXECUTE          0x0008
```
First thing this function will do, as almost every other Executive Kernel function, is to obtain the PreviousMode](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/previousmode) and after that there will be another check, also pretty normal to see it in Kernel functions, which will check if PHANDLE value is over the MmUserProbeAddress, if this second check goes wrong error 998 will pop-up ("Invalid Access to memory location").

> Some days ago [@benhawkes](https://twitter.com/benhawkes) from Project Zero, disclosed a Windows Kernel vulnerability that has something to do with the PreviousMode check, make sure to read his article it's very dope (as always with Project Zero articles) https://googleprojectzero.blogspot.com/2019/03/windows-kernel-logic-bug-class-access.html

If both checks are passed, code will go into **"ObOpenObjectByName"**, this function will receive, among other things, an Object of type Section in ```rdx```, this Object is retrieved from the MmSectionObjectType address. 

![alt img](/images/loadLibrary/section_object.jpg "Section Object")

From now on we get into "real" Kernel code 😆😆, first thing is to check if we received an OBJECT_ATTRIBUTES in ```rcx``` and an OBJECT_TYPE in  ```rdx```, if everything goes well the kernel will get a Pool from the LookAside List 8 (KTHREAD->PPLookAsideList[8].P), I won't go to much into what a LookAside list is, but see them as some sorta of cache. (You can read more [here](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-lookaside-lists)) next the function **ObpCaptureObjectCreateInformation** will get called, after some sanity check, the code will store a OBJECT_CREATE_INFORMATION struct with the data from the OBJECT_ATTRIBUTES in the Pool retreived before. If the Object attributes have an ObjectName (UNICODE_STRING), the name will be copied into the address pointed in the ```r9``` param but with a slight modification, the MaximumLength will be changed to ```F8h```

![alt img](/images/loadLibrary/object_create_info.jpg "Create Information")

after returning from that function, fun with structures begins! 🤣🤣. First we get a pointer to the KTHREAD (```gs:188h```) from here we obtain a pointer to the KPROCESS (KTHREAD+```98h```->ApcState+```20h```->Process), and as you may known, KPROCESS is the first element of EPROCESS (Kinda like the PEB from the kernel processes, don't kill me for this 🤣). So basically, if you get a pointer to the KPROCESS you also have a pointer to the EPROCESS

![alt img](/images/loadLibrary/eprocess_kprocess.jpg "Executive Process, Kernel Process")

this way the Kernel gets the UniqueProcessId (EPROCESS+```2E0h```), along with these the code also gets a pointer to the member GenericMapping, which is the offset ```0xc``` inside the structure OBJ_TYPE_INITIALIZER that resides inside the structure OBJECT_TYPE in offset ```40h```. Following this, the function **SepCreateAccessStateFromSubjectContext** will get called, as the name implies we recieve an [ACCESS_STATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_access_state) Object after calling this function (Pointer passed as an argument in ```rdx```) this function belong to the component ["Security Reference Monitor"](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-security-reference-monitor) this component mainly provides function to check access and rights, you can identify these functions by the prefix **Se**

Next step, probably one of the most important during this process, is to execute the function **ObpLookupObjectName**. Again the name give us a little info on the functionality of the method, here the code will look for an Object based on a Name (In this case the DLL name). Just by lookign at the function Graph we can tell it's an important function 🤣

<img src="/images/loadLibrary/graph.jpg" alt="ObpLookupObjectName Graph" style="margin:auto; width:50%"/>

A pretty valuable aspect to understand these functions is to know which are the arguments the function expect, a lot of the Kernel functions are not documented on the WDK so we get have two options, first one is to reverse the Kernel and try to understand which params are being passed to the function and the second option which is much faster is to search for the function on Google and you'll probably land into [ReactOS](https://reactos.org/) which is a Super Awesome project (kinda an Open-Source Windows) and there are a lot of functions on this project that match the Windows Kernel almost exactly so it's a great way to understand a lot of things inside the kernel, so make sure to visit that project! An idea of how this function arguments look, check the next picture:

<a name="params_obp">
<img src="/images/loadLibrary/params_obplookupobjectname.jpg" alt="Params ObpLookupObjectName" style="margin:auto;"/>
</a>

Inside this function, first thing is to initialize the structure [OBP_LOOKUP_CONTEXT](https://doxygen.reactos.org/dd/d94/struct__OBP__LOOKUP__CONTEXT.html), next we get a reference to the "KnownDlls" Directory Object with the call to **ObReferenceObjectByHandle**, this object contains a list of Section Objects already loaded into memory, and each of them corresponds to one DLL from the "KnownDlls" Register key

> **Spoiler:** As you may see in the Userland Call stack, the function before **NtOpenSection** is called **LdrpFindKnownDll**, these means that if the DLL we are trying to load is not in the list of "KnownDlls" we will get an error

![alt img](/images/loadLibrary/known_dlls.jpg "Known DLLs")

next, the code wil calcualate a Hash with the name of the DLL and it will check if this Hash matches one of the Hashes from the "KnownDlls", if there are no matches then the function will return the error "c0000034: Object Name not found.". From here on, the flow is mainly to clean everything before returning into Userland. 

![alt img](/images/loadLibrary/error_name.jpg "Error c0000034")


> **Another Spoiler:** On part 2 we will see how Userland reacts when it receives the error "c0000034". Quick preview, the DLL will be seeked and the function NtOpenFile will be called

### KnownDll

Now let's imagine the DLL we are looking for is inside the KnownDlls list, For this, 'cause I'm too lazy to compile the code again we will add "kerberos.dll" to this list. We can found this list in the following Register key: ```*HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\KnownDLLs*```

> **NOTE!** We need elevated privileges to do this, in my case I just set myself as the owner of that key and added the DLL

In the following image you can see how the Kerberos DLL has been loaded as part of the KnownDlls (Haven't checked too much, but I belive the name must be Uppercase because the hash is calculated with the Uppercase name of the DLL, but there are cases like "kernel32.dll" which are in Lowercase so I gotta investigate more on this)

<a name="kerberos">![alt img](/images/loadLibrary/kerberos_knowndll.jpg "Kerberos KnownDll")</a>

Doing a Fast-Forward we can see how the function **ObpLookupObjectName** this time returned 0 instead of "c0000034" as the NTSTATUS

![alt img](/images/loadLibrary/return_knowndll.jpg "Sucessfull ObpLookupObjectName")

For this case we will start directly from the function **ObpLookupObjectName**, specifically from the point where the hash is computed (The code flow is the same until this point for both cases). This time we will look how the hash is calculated by looking at the following pseudocode:


> **NOTE!** This function is undocumented, so is very possible that the implementation changes from one version of Windows to another, even from one SP to the next one. In my particular Im studying the kernel of this version: **Windows 8.1 Kernel Version 9600 MP (2 procs) Free x64**

```cpp
// Credit to Hex-Ray xD
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
        /* This code is really executed in the else statement, the if
        statement is a while that goes element by element substracting 
        20h from every element between 61h and 7Ah, of course that's 
        much slower than this */
        size -= 4;
        dll_buffer += 4;
        res = acc + (res >> 1) + 3 * res;
    } while (size >= 4)
    hash = (DWORD) res + (res >> 20h)
    /* If size is not a multiple of 4 the last iteration
    would be done using the while explained before */
}

obpLookupCtx.HashValue = hash;
obpLookupCtx.HashIndex = hash % 25;
```

If you do this operation with the DLL name "kerberos.dll", hopefully, you will get the HashIndex ```20h``` which corresponds to the value 32 in decimal, if you double check the image where I showed that "kerberos.dll" was loaded as part of the [KnownDlls](#kerberos) and check in the column Hash, you can see that the values is 32. Next, the function checks if the calculated hash, which is written to the ```OBP_LOOKUP_CONTEXT``` structure, matches the hash of the section with the, also, calculated index

![alt img](/images/loadLibrary/directory_entry.jpg "Hashes Match")

If this first check goes well, the code then obtains the ```OBJECT_HEADER_NAME_INFO``` using the formula ```ObjectHeader - ObpInfoMaskToOffset - ObpInfoMaskToOffset[InfoMask & 3]```, and summarizing the name of the Object is checked agains the name we passed as a parameter to the function LoadLibrary. If this goes well too, the members Object and EntryLink of ```OBP_LOOKUP_CONTEX``` will be filled consequently, after a couple more checks this structure will be copied into the out parameter pointer and we will return from this function. This function has two out arguments, upon return the first one will have the pointer to the object and the second one will have the pointer to the filled ```OBP_LOOKUP_CONTEX``` structure.

![alt img](/images/loadLibrary/return_obplookupobjectname.jpg "return ObpLookupObjectName")

If you check the arguments the function receives ([here](#params_obp)) the value FoundObject will be on ```rsp+68h``` while the structure ```OBP_LOOKUP_CONTEX``` will be on ```rsp+48h```. Also look how the Object doesnt' have any Handle opened still, this will happen in the last function we are going to study today **ObpCreateHandle**, this function will be in cahrge of getting the handle from the Object.

This function also has A LOT of code, and since this is already quite long I won't go into much detail (Maybe in other Post I could go into more detail, because is a pretty interesting function)

The most importante arguments that **ObpCreateHandle** will receive are on ```rcx```, where it will receive a value from the ``OB_OPEN_REASON`` enum. One of the following: 
```cpp
ObCreateHandle      =   0
ObOpenHandle        =   1
ObDuplicateHandle   =   2
ObInheritHandle     =   3
ObMaxOpenReason     =   4
```
then in ```rdx``` the function expects a reference to the Object (The DLL Section Object), and in ```r9``` the function will receive an ACCESS_STATE structure, with the ACCESS_MASK among other interesting things.

We this in mind, and knowing in this case the value from the ``OB_OPEN_REASON`` enum will be ObOpenHandle, let's roll. The first thing the function will do is check if the handler we are trying to obtain is for a Kernel Object (With other words, we are trying to get a [Kernel Handle](https://docs.microsoft.com/en-us/windows/desktop/sysinfo/kernel-objects)). If this is not the case, then the function will retreive the ObjectTable (```KTHREAD->ApcState->Process->(EPROCESS) ObjectTable```) which corresponds to a ``HANDLE_TABLE`` structure, after some checks the function [**ExAcquireResourceSharedLite**](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-exacquireresourcesharedlite) will get called in order to get the resources of the PrimaryToken (When I say resource Im speaking about the structure ```ERESOURCES``` which is some sort of mutex, you can read more about resources [here](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-eresource-routines))

If the resource has been acquired the the function [**SeAccessCheck**](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-seaccesscheck) will be called, these function checks if the requested access right to the specific object can be granted. If these rights are granted we get inot the function **ObpIncrementHandleCountEx** which is in charge of incrementing the Handle count from both this Section Object we are trying to get the handle of and the general Section Object Type count (This function only increment the counter, but this doesn't mean the handle is open. This can be check by running ```!object [object]``` and you'll notice the HandleCount has been incremented, but checking the handles of the process ```!handle``` you won't see any reference to this handle)

Lastly, the handle will be open. To save some time I will show some pseudocode of how this is done and I will add comments in the code. (Again pseudocode sponsored by Hex-Rays 🤣)

```cpp
// Im goint to simplify, there will be no check nor casts
HANDLE_TABLE * HandleTable = {};
HANDLE_TABLE_ENTRY * NewHandle = {};
HANDLE_TABLE_FREE_LIST * HandlesFreeList = {};

// Get reference to the Object and his attributes (rsp+28h), to get
// the object we use the Object Header (OBJECT_HEADER) which is 
// obtained from the Object-30h (OBJECT_HEADER+30h->Body) 
QWORD LowValue = 
    (((DWORD) Attributes & 7 << 11) | (Dll_object - 30h << 10) | 1)
// Get the type, Object-18h (OBJECT_HEADER+18h->TypeIndex)
HIDWORD(HighValue) = Dll_Object - 18h
// Get the requested access 
LODWORD(HighValue) = ptrAccessState.PrevGrantedAccess & 0xFDFFFFFF;
// Get the HANDLE_TABLE from the process
HandleTable = KeGetCurrentThread()->ApcState.Process->ObjectTable;
// Calculate index based on Processor number 
indexTable = Pcrb.Number % nt!ExpUuidSequenceNumberValid+0x1;

// Get the List of Free Handles
HandlesFreeList = HandleTable->FreeLists[indexTable];
if(HandlesFreeList) {
    Lock(HandlesFreeList); // This is more complex than this
    // Get the First Free Handle
    NewHandle = HandlesFreeList->FirstFreeHandleEntry;
    if (NewHandle) {
        // Make the Free handles list point to the next free handle
        tmp = NewHandle->NextFreeHandleEntry;
        HandlesFreeList->FirstFreeHandleEntry = tmp;
        // Increment Handle count
        ++HandlesFreeList->HandleCount;
    }
    UnLock(HandlesFreeList);
}

if (NewHandle) {
    // Obtain the HandleValue, just to return it
    tmp = *((NewHandle & 0xFFFFFFFFFFFFF000) + 8)
    tmp1 = NewHandle - (NewHandle & 0xFFFFFFFFFFFFF000) >> 4;
    HandleValue = tmp + tmp1*4;
    // Assign pre-computed values to the handle so it
    // knows to which object points, whick type of object it
    // is and which permissions where granted
    NewHandle->LowValue = LowValue;
    NewHandle->HighValue = HighValue;
}
```

Finally, the function will return the Handle value in ```rsp+48```. From now until returning to Userland, everything is related to cleaning the machine state (Structures, Single Lists, Access States, etc...) and when we finally reach Userland (**LdrpFindKnowDll**) we will have the handle and the STATUS will be 0.

![alt img](/images/loadLibrary/handle.jpg "Created Handle")

> This handle has nothing to do with the HANDLE of the module that LoadLibrary will return when everything is done executing, this is just a handle to a Section Object that will be used "internally". Even more, right at this point the DLL is not even loaded in the address space of the process, how that happens is what we are going to see in Part 2

## Conclusions

As you can see, there is a lot of code inside the Kernel, and not everything is straight forward, I would dare to say that things are pretty complex. Have in mind that this is something quite simple, we will get into more sophisticated stuff 😀😀. On the other hand, I left **A LOOT** of code, structures, lists, etc... without commenting nor mentioning so please don't kill me for this, I tried to summarize into what I thoutgh was the most important. Of course, as always if you have any doubts, questions or if there's something wrong and you want to bash me don't hesitate to contact me (it's free!!).
And that's all folks, I hope you enjoyed it and see you in Part 2!! I'm off!! 🤪🤪

[@n4r1b](https://www.twitter.com/n4r1b)
