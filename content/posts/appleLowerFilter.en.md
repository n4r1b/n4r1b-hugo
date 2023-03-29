+++
categories = ["Apple", "USB", "AppleLowerFilter", "Windows Internals"]
tags = ["Apple", "USB", "AppleLowerFilter", "Windows Internals"]
date = "2023-03-04"
description = "How Apple's USB lower filter on Windows devices helps control device configurations"
images = ["https://n4r1b.com/images/smartAppControl/SmartAppControl.jpg"]
featured = ["https://n4r1b.com/images/smartAppControl/SmartAppControl.jpg"]
featuredalt = ""
featuredpath = "date"
linktitle = "The Intersection of Apple's USB Lower Filter and iPhone-WPD Integration"
title = "The Intersection of Apple's USB Lower Filter and iPhone-WPD Integration"
slug =  "The Intersection of Apple's USB Lower Filter and iPhone-WPD Integration"
type = "posts"
+++

If you've ever connected an iPhone, iPad, or iPod to a Windows PC, you might have noticed that the device appears as a different type of device depending on what you're doing with it. For example, if you're charging your iPhone, it might show up as a "USB Composite Device," but if you're syncing music with iTunes, it might show up as an "Apple Mobile Device USB Driver.". Have you ever wondered how this works? It turns out that Apple has a USB lower filter on Windows machines that helps them control which USB configurations is used by the OS.

This blog post will be divide in two parts: first, we'll explore how Apple's USB lower filter works, what it does, and how it can provide a different experience whether Apple software is installed or not, and second, we'll investigate why file operations out-of-the-box with iPhones are so limited when the WPD property `WPD_DEVICE_PROTOCOL` for the device indicate that device is using the protocol Media Transfer Protocol (MTP). We'll delve into topics such as Windows Portable Device (WPD), USB descriptors, and User-Mode Driver Framework (UMDF), among others.

> **Remark:** The research for this post was conducted using Windows 11 22H2, the AppleLowerFilter version 486.0.0.0 and an iPhone SE 2nd generation.

## Motivation
The motivation behind this blog post was a curiosity that arose from the limited options presented when connecting an iPhone to a Windows machine. Surprisingly, looking into the WPD properties of the iPhone the WPD device protocol is defined as `MTP: 15.20`, this is something weird since the class defined by the Interface descriptor is Image. This mismatch and the the limited options to interact with the device without using Apple software was bugging me so I decided to investigate to try an shed some light on these observations.

## Initializing Apple's USB Lower Filter

Apple devices present themselves as composite devices with multiple interfaces to ensure that their devices are properly recognized and that all necessary drivers are loaded. This is because Apple devices typically have multiple interfaces, which provide different functionality, such as audio, video, and control. When we plug an Apple device into a Windows machine, the bus adapter identifies the device and provides its HardwareIDs and CompatibleIDs to the operating system. These IDs are used to search for the best driver in the Driver Store based on the match quality of the IDs. For the bus driver to consider this device a composite device, certain [requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/enumeration-of-the-composite-parent-device) must be met. If these requirements cannot be met, the OS will not load the USB Composite Device class driver (usbccgp) automatically. In this case, we need to provide an INF that will load the generic parent driver, which for apple is the file *AppleUSB.inf*

> In the case of the iPhone the requirement not met is that the device has multiple configurations (`bNumConfigurations == 4`).

This single INF file contains various setup configurations for different devices (e.g. AppleUSB, AppleUsbHomePod, and AppleUsbWatch). For the case of iOS devices the HardwareId will match exactly so the OS will apply the AppleUSB setup configuration, this will copy the `AppleLowerFilter.sys` and will add the following values under the device specific registry key:

```inf
[AppleUSB_CCGPDriverInstall_AddReg.HW]
HKR,,"OriginalConfigurationValue",0x00010001,2
HKR,,"UsbccgpCapabilities",0x00010001,0x10      ; Selective suspend for USB devices attached to the USB Composite Parent Driver
HKR,,FriendlyName,,%iPhone.AppleUSB.DeviceDesc% ;"Apple Mobile Device USB Composite Device"
HKR,,LowerFilters,0x00010000,AppleLowerFilter
```

> The `OriginalConfigurationValue` is a value that can be set for the Usbccgp.sys driver in a device's hardware registry key. It determines which configuration of the composite device should be used as the default. When a composite device is first plugged in, the system reads the OriginalConfigurationValue and loads the specified configuration. This can be useful for composite devices with multiple configurations, where one configuration may be preferred as the default. [More Info](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/selecting-the-configuration-for-a-multiple-interface--composite--usb-d).

The following steps detailed by Microsoft will happen after the driver package is installed -- [How Windows Install Device: Step 3](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/step-3--the-driver-for-the-device-is-installed)
- The device will be restarted.
- After restarting, the PnP manager identifies the device's function driver and any optional filter drivers, builds the device stack -- In our case the FDO is Usbccgp & the LowerFiDO is AppleLowerFilter -- and starts the device by calling the DriverEntry routine for any required driver that is not yet loaded. The AddDevice routine is then called for each driver, starting with lower-filter drivers, then the function driver. Resources are assigned if required, and the PnP manager sends an IRP_MN_START_DEVICE to the device's drivers

## Digging into Apple's USB Lower Filter
After covering the theory behind the enumeration and installation of the AppleLowerFilter in the previous section, we will now take a closer look at how the driver works and the role it plays in enabling the functionality of Apple devices on Windows machines.

Being a WDF driver, the first steps when the PnP calls the DriverEntry is to initialize the framework and bind the WDF version (In this case WDF 1.15). Once this is done the framework will call our DriverEntry function, in the case of the AppleLowerFilter they driver entry will simply create a driver object and setting only an AddDevice routine in the `WDF_DRIVER_CONFIG`. The AddDevice routine for the AppleLowerFilter will do the following:

- Identify itself as a FiDO by calling [WdfFdoInitSetFilter](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdffdo/nf-wdffdo-wdffdoinitsetfilter)
- Register a [PnP and power management callback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfdevice/nf-wdfdevice-wdfdeviceinitsetpnppowereventcallbacks) for events: 
    - EvtDevicePrepareHardware
    - EvtDeviceReleaseHardware
    - EvtDeviceD0Entry
    - EvtDeviceD0Exit
- Set two [IRP pre-process callbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfdevice/nf-wdfdevice-wdfdeviceinitassignwdmirppreprocesscallback) for IRPs:
    - IRP_MJ_PNP
    - IRP_MJ_INTERNAL_DEVICE_CONTROL
- Finally, [create a DO](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfdevice/nf-wdfdevice-wdfdevicecreate) with a Context Type Info named `FILTER_EXTENSION (sizeof == 0x50)`

> **Note:** I won't get into all the details of the WDF framework, but I encourage everyone to delve into the [source code on Github](https://github.com/Microsoft/Windows-driver-frameworks). It's a well-designed piece of software that makes writing drivers much easier and intuitive, so looking into the code is a great exercise 🙂.

Next step that we are interested in during the [power-up sequence](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/power-up-sequence-for-a-function-or-filter-driver) is to prepare the hardware for power-up, this means calling the EvtDevicePrepareHardware callback registered by the filter. This is probably the most interesting step in the AppleLowerFilter so let's look at it closely.

First step in the Callback is to retrieve the USB descriptor, this is done by means of a function I called `GetUsbDeviceDescriptor`. This function is used to retrieve the USB device descriptor for the USB device. This is done by allocating memory for a URB (USB Request Block) and using the `URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE` type, which is a request to retrieve a descriptor from a USB device. The descriptor being requested is `USB_DEVICE_DESCRIPTOR_TYPE`, which provides information about the USB device such as its vendor and product IDs, device class, and protocol. The function submits the URB synchronously to retrieve the descriptor.

> For most of the USB related operations Apple is using the usbdlib, this is a bit surprising given that this is a WDF driver they could have used the wdfusb header which I personally think it would have simplified things 🙂.

Then, the driver will store the `bNumConfigurations` into the `FILTER_EXTENSION` context and will proceed to call what I consider the main function of this driver: `GetPreferredConfig`. Let's take a look at a simple pseudocode of this function before describing the internals:

```c
int PreferredConfig;
if (FilterCtx->bNumConfigurations == 1) {
    PreferredConfig = 1;
} else {
    if( !NT_SUCCESS( GetDeviceConfigUrb(WdfDevice, &PreferredConfig) ) {
        PreferredConfig = 3;
    }
}

FilterCtx->DeviceConfig = PreferredConfig;
if( !QueryAppleSoftwarePresent() ){
    PreferredConfig = 1;
}

if ( PreferredConfig >= FilterCtx->bNumConfigurations)  {
    PreferredConfig = FilterCtx->bNumConfigurations;
}

if ( PreferredConfig >= 5 ) {
    return 5;
}

return PreferredConfig;
```
This function will first check if the number of configurations of the device is 1. If it is, the preferred configuration is set to 1. If not, the code sends a URB to retrieve the preferred configuration. If the URB request fails, the preferred configuration is set to 3. The code then sets the `DeviceConfig` field in the FilterCtx structure. Then, it checks if the `QueryAppleSoftwarePresent` function returns false (indicating that Apple Software is not installed), and sets the preferred configuration to 1 if so. The code then checks if the preferred configuration is greater than or equal to the number of configurations specified in the device descriptor. If it is, the preferred configuration is set to the maximum number of configurations. Finally, if the preferred configuration is greater than or equal to 5, the code returns 5.

There's a few a key points in this function that we will look into deeper. The first thing that stand-out is the function `GetDeviceConfigUrb`, this function will allocate memory for a URB, sets the URB to make a vendor-specific control request, and then submits the URB synchronously to the USB driver stack. The specific vendor request being made is a control transfer with a request type of 69 and a transfer buffer containing one byte of data.

```c
Urb->UrbHeader.Function = URB_FUNCTION_VENDOR_DEVICE;
Urb->UrbHeader.Length = sizeof(_URB_CONTROL_VENDOR_OR_CLASS_REQUEST);
Urb->UrbControlVendorClassRequest.TransferBufferLength = 1;
Urb->UrbControlVendorClassRequest.TransferBuffer = preferredConfig;
Urb->UrbControlVendorClassRequest.Request = 69; // Curious number choice by the Apple guys :D
Urb->UrbControlVendorClassRequest.Value = 0;
Urb->UrbControlVendorClassRequest.Index = 0;
Urb->UrbControlVendorClassRequest.TransferFlags = USBD_TRANSFER_DIRECTION_OUT | USBD_SHORT_TRANSFER_OK;
Status = SubmitUrbSync(wdfDevice, UsbdHandle, Urb);
```

The next key point into choosing the preferred config is the function `QueryAppleSoftwarePresent`, this function plays a big role since it's return value will determine if we are always constrained to just one preferred config. This function will do the following:

```cpp
// Check if we have already found the Apple Mobile Device Service
if (gAppleMobileServiceFound) {
    return 1;
}

// pseudocode just for simplicity 
auto EventString{"\\BaseNamedObjects\\com.apple.MobileDeviceProcess.QueryMuxReady"};
// Try to open the MuxReady event
if ( NT_SUCCESS( ZwOpenEvent(&eventHandle, STANDARD_RIGHTS_REQUIRED, &EventString) ) ) {
    ZwClose(eventHandle)
    return 1;
} 

// I believe this is old behavior. At least with the latest version of iTunes from the
// Microsoft Store, these keys are not created.
auto serviceFound = QueryRegistry(
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Apple Mobile Device Service",
    L"ImagePath");
auto appFound = QueryRegistry(
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Apple Mobile Device App",
    0); 

if (serviceFound || appFound) {
    // Apple Mobile Device Service and app were found, so set the global flag    
    gAppleMobileServiceFound = true;
    return 1;
}

// Apple NT event, Apple Mobile Device Service and app not found, so return 0
return  0;
```
Getting back to function `GetPreferredConfig`, this value plays a big role because the number returned by this function will be used to overwrite the `OriginalConfigurationValue` in the registry key of the device.

> **Note:** The value returned by `GetPreferredConfig` will be subtracted by one since Registry values described by the `OriginalConfigurationValue` correspond to the USB-defined configuration index, indicated by the `bConfigurationValue` member of the configuration descriptor (`USB_CONFIGURATION_DESCRIPTOR`) and not by the bConfigurationNum values reported in the device's configuration descriptor.

What we've just seen is why even thou the INF writes the value `2` in the `OriginalConfigurationValue` if you insert an iPhone into a PC without iTunes installed you'll see the following in the registry:

![alt img](/images/appleLowerFilter/OriginalConfigurationValue.jpg "OriginalConfigurationValue")

After setting the `OriginalConfigurationValue` in the registry, the EvtDevicePrepareHardware function will call [WdfUsbTargetDeviceCreate](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfusb/nf-wdfusb-wdfusbtargetdevicecreate) to create the USB target device object. The USB target device object represents the underlying USB device and provides a way for the driver to communicate with the device.

To periodically check the preferred configuration, the function sets up a `WDFTIMER`. The timer's callback function will be called periodically to check if the preferred configuration has changed. If the preferred configuration has changed, the function will call [WdfUsbTargetDeviceCyclePortSynchronously](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfusb/nf-wdfusb-wdfusbtargetdevicecycleportsynchronously) for the device to be surprise-removed and re-enumerated, so it loads with the new configuration.

> The timer is set with a period of `0` so the framework will not call the timer. On the other hand, the filter will call `WdfTimerStart` with a DueTime of 5s (Relative to the current system time) from within the timer's callback function and also in the D0Entry callback.

Let's now look into both IRP pre-process callbacks to get the full picture of the driver workflow. The pre-processing of IRPs allows the driver to modify or redirect the IRP before it is sent to the default handler or another driver in the stack. Let's first look at the handler for the Internal Device Control request. This function will check the IRP is an IOCTL_INTERNAL_USB_SUBMIT_URB request to select the USB configuration. If it is, the function obtains a handle to the device, forwards the IRP and then retrieves pipe handles for the USB interface has class Image. The pipe handles for Interrupt, BulkIn and BulkOut will be stored in the device context.

Now lets take a look at the handler for the PnP IRPs pre-processing. In this case the handle will handle two cases:
- `IRP_MN_QUERY_DEVICE_RELATIONS`
- `IRP_MN_QUERY_ID`

The case of the QueryID IRP is pretty simple, the function will check if `FilterCtx->DeviceConfig` -- Remember this value was obtained by means of the vendor-specific URB -- is set to 1,  If it is, the function appends the string `&RESTORE_MODE` to the information returned for `BusQueryHardwareIDs` and `BusQueryDeviceID` requests.

In the other hand, the QueryDeviceRelation is a bit more interesting. First of all, this handler will only execute if certain timer has not run (More on this shortly) and if Apple Software is installed on the machine. It will only handle the BusRelations IRP, it will forward the request synchronously and checks if the status is successful. If there is any information returned, it looks in the returned device object list for a device whose CompatibleId contains `USB\Class_06`. If found, it dereference this DO, then removes it from the list and updates the device count -- This will make so that even usbccgp created the PDO for the WPD device, the PnP will not see the DO just yet since the returned list won't have it. Shortly we will see how the lower filter handles this.

If the device of class 6 was found then the function will set up another WDF timer, based on the DbgPrints we will call it the PtpTimer, which triggers after 5 seconds.
When triggered the callback will set a flag in the deviceContext so the QueryDeviceRelations handler doesn't process requests anymore, will check if iTunes is present and if it is, it will send the following set of PTP/MTP operation request packets to the USB device.

- OpenSession - OperationCode: 0x1002
- VendorExtension - OperationCode: 0x9008
- CloseSession - OperationCode: 0x1003

The USB packet capture below illustrates the execution of these operations, notice how they take place approximately 5 seconds into the capture on that port.

![alt img](/images/appleLowerFilter/CapturePtpTimer.jpg "Capture PTP timer packets")

> I've tried by all means to get more information on operation 0x9008 but there seems to not be any information about it for Apple devices. The best I could get was ChatGPT saying that "Operation command 0x9008 in a PTP/MTP packet typically corresponds to the "Apple Device Info" command". Unfortunately, I asked for documents/quotes proving this and every link the chat gave me was either invalid or was unavailable/deprecated Apple documentation. Given the name "Apple Device Info" I thought it would be similar to the PTP/MTP command "GetDeviceInfo", but every test I tried on my machine command 0x9008 doesn't seem to have a Data Phase, so my best guess it's that is either not a "Device Info" command or Apple devices don't respond to that command anymore. However, if somebody has more info about this command please reach out, I'd love to hear more about it 🙂!!

For reference, the quotes/links from ChatGPT:

![alt img](/images/appleLowerFilter/ApplePtpChatGpt.jpg "Operation Command 0x9008 ChatGPT info")
 
Lastly, after sending the PTP/MTP requests, the PtpTimer will call `IoInvalidateDeviceRelations` with relation type `BusRelation` which will trigger a new IRP QueryDeviceRelations, but since this time the timer already executed the handler won't remove the WPD device from the Devices list. So this time the PnP manager we will actually see the PDO for the WPD device and will start building the stack for it. The following image shows this behavior captured by adding our own LowerFilter to the stack and just tracing Pre and Post the IRP is handled by the AppleLowerFilter.

![alt img](/images/appleLowerFilter/PrePostDeviceRelations.jpg "Pre & Post DeviceRelations")

> I have no clue why Apple is doing this, my guess is that the PTP packet with operationCode 0x9008 somehow notifies the device that iTunes is present on the host or something around those lines. I didn't notice any different behavior on the WPD device with or without iTunes installed, other than the WPD device taking 5 seconds to actually show up. Removing the AppleLowerFilter from the list of LowerFilters for the device doesn't seems to have any major impact on the behavior of the WPD device. Again, if anybody knows more on why Apple might be doing these I'd love to hear it!

That's pretty much how the AppleLowerFilter behaves, as can be seen it will mainly work during initialization of the device, other than that the timer to check the active config will be running in the background every 5 seconds to see if the port has to be re-enumerated.

## PTP or MTP, that is the question
In this section, we'll focus on why iPhones don't offer a whole set of operations on their storage as the ones we would expect from a device using the MTP protocol. We'll also investigate why the mismatch between the USB Interface Class/Subclass and the `WPD_DEVICE_PROTOCOL` property. To answer those questions, we'll take a look at how the a WPD device is created, how the storage is "mounted" and how WPD properties are set.

First let see the differences in the WPD device protocol property between and Android device connected using PTP and an iPhone:

![alt img](/images/appleLowerFilter/WpdInfo.jpg "WpdInfo Android vs iPhone")

given the WPD Protocol property in the iPhone we would expect to have a much richer set of options to interact with the device. We can quickly answer why the iPhone behaves as a PTP device just by looking into the Interface descriptor of the device. See the following descriptors for an iPhone and a Xiaomi in both PTP & MTP mode -- The iPhone has multiple configurations, but no matter which one we choose the interface that will create the WPD PDO will always contain the Interface with Class 6 and SubClass 1.

{{< more yaml >}} 
        ---------------- iPhone Interface Descriptor -----------------
bLength                  : 0x09 (9 bytes)
bDescriptorType          : 0x04 (Interface Descriptor)
bInterfaceNumber         : 0x00 (Interface 0)
bAlternateSetting        : 0x00
bNumEndpoints            : 0x03 (3 Endpoints)
bInterfaceClass          : 0x06 (Image)
bInterfaceSubClass       : 0x01 (Still Imaging device)
bInterfaceProtocol       : 0x01
iInterface               : 0x0E (String Descriptor 14)
 Language 0x0409         : "PTP"

        ---------------- Xiaomi MTP Interface Descriptor -----------------
bLength                  : 0x09 (9 bytes)
bDescriptorType          : 0x04 (Interface Descriptor)
bInterfaceNumber         : 0x00 (Interface 0)
bAlternateSetting        : 0x00
bNumEndpoints            : 0x03 (3 Endpoints)
bInterfaceClass          : 0xFF (Vendor Specific)
bInterfaceSubClass       : 0xFF
bInterfaceProtocol       : 0x00
iInterface               : 0x05 (String Descriptor 5)
 Language 0x0409         : "MTP"

        ---------------- Xiaomi PTP Interface Descriptor -----------------
bLength                  : 0x09 (9 bytes)
bDescriptorType          : 0x04 (Interface Descriptor)
bInterfaceNumber         : 0x00 (Interface 0)
bAlternateSetting        : 0x00
bNumEndpoints            : 0x03 (3 Endpoints)
bInterfaceClass          : 0x06 (Image)
bInterfaceSubClass       : 0x01 (Still Imaging device)
bInterfaceProtocol       : 0x01
iInterface               : 0x00 (No String Descriptor)
{{< /more >}}

Even though this answers the big question, there's still details such as why the iPhone won't allow to create nor copy anything into it while on the other hand the Xioami even when using PTP would allow creation of objects so as someone who enjoys getting to the bottom of things, simply glancing at the Interface descriptor wasn't enough to satisfy my curiosity. 

Since this descriptor will generate the CompatibleId `USB\Class_06&SubClass_01&Prot_01`, looking for the INF that matches this ID we find the `wpdmtp.inf`. Within this INF we can get the following components for the UMDF part of WPD devices:

- `WpdMtp.dll`: MTP core protocol component
- `WpdMtpUS.dll`: Usbscan transport layer for MTP driver
- `WpdMtpDr.dll`: Windows Portable Device Media Transfer Protocol Driver

> Just for completion, as part of the kernel side of things, the INF will add `WinUSB.sys` as a LowerFilter and the reflector `WUDFRd.sys` as function driver.

From the three binaries mentioned above `WpdMtpDr` is the main WPD MTP driver that will run in the `WUDFHost`, so we will start from there. This being a UMDFv1 driver it will be strongly based on COM and written in C++, on the bright side we have the [WpdWudfSampleDriver](https://github.com/microsoft/Windows-driver-samples/tree/win11-22h2/wpd/WpdWudfSampleDriver) which will leave us with very little reversing to be done -- It surprises me that the driver has not been updated to use UMDFv2, given that UMDFv1 has pretty much been deprecated and having little to no support for new features, I guess if ain't broken don't fix it 😅.

![alt img](/images/appleLowerFilter/AddDeviceUMDFv1.jpg "Add Device UMDFv1")

As can be seen above, our entrypoint will be the [OnDeviceAdd](https://github.com/microsoft/Windows-driver-samples/blob/win11-22h2/wpd/WpdWudfSampleDriver/Driver.cpp#L18) routine.  In this function, the `CDevice` object is created, which takes us to the [CDevice::OnPrepareHardware](https://github.com/microsoft/Windows-driver-samples/blob/win11-22h2/wpd/WpdWudfSampleDriver/Device.cpp#L80) routine where the WpdBaseDriver is initialized by calling [WpdBaseDriver::Initialize](https://github.com/microsoft/Windows-driver-samples/blob/win11-22h2/wpd/WpdWudfSampleDriver/WpdBaseDriver.cpp#L152). Unfortunately, this is the part where the Sample code and `WpdMtpDr` will start to differ. The sample code has no real device to communicate with, but in our case, we do. This is where `WpdMtp.dll` comes in, to act as the glue between the `WpdMtpDr` and the real device. The MTP core library contains the `CMtpDevice` class, which represents the real device. During the WpdBaseDriver initialization, the MTP core library is loaded and a session is opened with the device as can be seen in the following simplified code snippet.

```cpp
// No error handling
HANDLE hEvent{};
CMtpDevice * MtpCore{};
MTP_RESPONSECODE mtpRes = OK; // 0x2001

CoCreateInstance(&CLSID_WindowsMtp, NULL, CLSCTX_INPROC_SERVER, &IID_IMtp2, (LPVOID *)&MtpCore);
//
// wpdEvent represents a class that implements IMtpEventCallback, to get notifications from MTP events
// 
MtpCore->Open(pszPortName, wpdEvents, NULL);  
MtpCore->InitAsyncCancelEventHandle(hEvent);

CWpdDriverBase->m_mtpCore = MtpCore // Let's assume this will be wrapped in a ComPtr

MtpCore->OpenSession( 1, &mtpRes );
if( mtpRes == SessionAlreadyOpened || mtpRes == InvalidTransactionId ) { // 0x201E & 0x2004 respectively
    MtpCore->ResetDevice( &mtpRes );
    MtpCore->OpenSession( 1, &mtpRes );
}

MtpCore->Close();
```

After loading the MTP core module, the initialization routine is triggered to retrieve the MTP DeviceInfo Dataset. This is one of the initial MTP requests sent to the device, and the DeviceInfo structure is populated upon its return. Notably, the structure contains critical information such as the Model, Manufacturer, and various MTP version identifiers, as detailed in section 5.1.1 of the MTPforUSB-IFv1.1 specification. Such information plays a crucial role in setting up the WPD properties later on.

> The MTP core sends the request and parses the response into a `CDeviceInfo` structure, whereas the `WpdMtpDr` leverages a caching system that stores COM pointers to the classes returned by `WpdMtp`. This approach prevents frequent re-issuance of PTP/MTP requests to the device, thereby optimizing I/O operations. Please note that this caching mechanism is beyond the scope of this post.

The following stack shows the first time this function is called:
```
0:008> k
 # Child-SP          RetAddr               Call Site
00 000000b5`6027f3d8 00007ffb`db67dc66     wpdmtp!CMtpDevice::GetDeviceInfo
01 000000b5`6027f3e0 00007ffb`db6850fd     wpdmtpdr!CMtpWrapper::GetDeviceInfo+0x10a
02 000000b5`6027f450 00007ffb`db65f058     wpdmtpdr!CMtpWrapper::IsDevicePropertySupported+0xf5
03 000000b5`6027f4f0 00007ffb`db65f3c6     wpdmtpdr!WpdBaseDriver::Initialize+0x58
04 000000b5`6027f570 00007ffb`db6494a9     wpdmtpdr!WpdBaseDriver::Initialize+0xbe
05 000000b5`6027f5a0 00007ffb`db64b9f6     wpdmtpdr!CDevice::InitializeBaseDriver+0x71d
06 000000b5`6027f660 00007ffb`db64acf9     wpdmtpdr!CDevice::_PrepareHardwareThread+0x4e
07 000000b5`6027f7b0 00007ffc`1f3626bd     wpdmtpdr!CDevice::PrepareHardwareThread+0x9
08 000000b5`6027f7e0 00007ffc`2034a9f8     KERNEL32!BaseThreadInitThunk+0x1d
09 000000b5`6027f810 00000000`00000000     ntdll!RtlUserThreadStart+0x28
```

> **Note:** I won't get into all the details of how the WPD protocol works since that could be a post in itself. But, mainly there's two IOCTLs (For Read-Only and Read-Write commands) which pack the WPD payload inside. In UM a WPD application will build a WPD command usually using the WPD API, which will serialize this WPD command and pack it into an IOCTL request, this will reach the Driver which will deserialize the command and act accordingly. For an example on how a WPD driver handles this, see: [CQueue::ProcessWpdMessage](https://github.com/microsoft/Windows-driver-samples/blob/win11-22h2/wpd/WpdWudfSampleDriver/Queue.cpp#L33).

Once the device is ready to receive I/O operations, the OS will try to retrieve the WPD DEVICE properties, this information lives within the `DEVICE` objectID (This ObjectID is pre-defined and always represents the DEVICE object). This request will reach the WPD driver which will fill in the WPD Device properties with the information of the `CDeviceInfo`. For the case of the `WPD_DEVICE_PROTOCOL` this is how the value will be set:

```cpp
// No error handling
ULONG extId;
CString protocol;
USHORT extVersion;
IMtpDeviceInfo deviceInfo;
IPortableDeviceValues portableDeviceValues;

if( property == WPD_DEVICE_PROTOCOL) {
    deviceInfo->GetVendorExtId( &extId );
    deviceInfo->GetVendorExtVersion( &extVersion );
    
    if( extId == MICROSOFT_VENDOR_EXT_ID ) { // MICROSOFT_VENDOR_EXT_ID == 6
        protocol.Format(_T("MTP: %.2f"), extVersion / 100.0 );
    } else {
        protocol.Format(_T("PTP: %.2f"), extVersion / 100.0 );
    }
    portableDeviceValues->SetStringValue( &WPD_DEVICE_PROTOCOL, protocol);
}
```

So now if we take a look at the DeviceInfo Dataset that is returned by an iPhone, we can look the `VendorExtId` and `VendorExtVersion` and finally answer why the `WPD_DEVICE_PROTOCOL` is set to `MTP 15.20`. If anyone is curious, the `MICROSOFT_VENDOR_EXT_ID` is defined by MS as part of their WMDRM protocol. This is one of the values that the MTP responder needs to set in the DeviceInfo Dataset to tell the MTP initiator that it supports AAVT, surprisingly the iPhone only adds this required value but not the others. For more info see: [MTP Vendor Extension Identification Message](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drmnd/2995527e-53fb-4612-8615-bd1c3c444832) & [Media Transfer Protocol Enhanced specification by MS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drmnd/37ad5858-ae05-45ae-bdfa-97538c190576)

![alt img](/images/appleLowerFilter/GetDeviceInfoApple.jpg "Apple Device Info")

One quick detail from the WPD DEVICE properties, there's a property called `WPD_DEVICE_TYPE` that is used for representation purposes only. But since we are here I think is interesting to discuss it fast. This property will be retrieved on the function `CDevicePropContext::GetDeviceType`, the function will get the CompatibleIds using the SetupAPI and will determine the DeviceType using an algorithm roughly like this:

1. If `MS_SUBCOMP_XXX`, extract the device type from the "XXX" part of the ID using `wcstol`.
2. If `MS_COMP_MTP`, try to get PTP/MPT property "Perceived Device Type (0xD407)" if not found set DeviceType to WPD_DEVICE_TYPE_GENERIC.
3. If neither `CLASS_06&SUBCLASS_01&PROT_01` nor `URN:MICROSOFT-COM:DEVICE:MTP:1` set DeviceType to WPD_DEVICE_TYPE_MEDIA_TYPE.
4. Get the `DeviceInfo`. If VendorExtId is not 6, set DeviceType to WPD_DEVICE_TYPE_CAMERA. Otherwise try to get "Perceived Device Type" if not found set DeviceType to WPD_DEVICE_TYPE_GENERIC, if found, set DeviceType to value returned by device.

In the case of an iPhone we would reach step 4, and since VendorExtId is equal to 6 and Property "Perceived Device Type" is not present, the DeviceType will be set to WPD_DEVICE_TYPE_GENERIC.

Now that we understand how the `WPD_DEVICE_PROTOCOL` property is set, let's explore why the Apple device's file operations are so limited. To anybody familiar with the PTP/MTP protocol they probably already know this, but regardless of the protocol PTP or MTP, each storage object (represented by `StorageIDs` starting with `s`) in the device has its own properties. Again, when I/O operations start on the device the OS retrieves information from the storage objects using two key operations: `GetStorageIDs (0x1004)` (to retrieve the list of `StorageIDs`) and `GetStorageInfo (0x1005)` (to define how the storage object behaves). We'll focus on the latter, as it returns a StorageInfo dataset that contains the following three key fields (see section 5.2.2 of the MTPforUSB-IFv1.1 specification for more information).

- Storage Type
- FileSystem Type
- Access Capability

When the WPD driver first tries to obtain the StorageInfo for the device, the request goes through the MTP core module. This module sends a PTP/MTP operation request to the device and returns the resulting StorageInfo dataset back to the driver.

```
0:008> k
 # Child-SP          RetAddr               Call Site
00 000000b5`6027de48 00007ffb`db68387f     wpdmtp!CMtpDevice::GetStorageInfo
01 000000b5`6027de50 00007ffb`db695d05     wpdmtpdr!CMtpWrapper::GetStorageInfo+0x117
02 000000b5`6027def0 00007ffb`db6cc52f     wpdmtpdr!CStoragePropContext::CacheStorageUniqueId+0xed
03 000000b5`6027df40 00007ffb`db6cb7e9     wpdmtpdr!CHierarchyHandler::QueryStorages+0x1bb
04 000000b5`6027dfe0 00007ffb`db6c9c7e     wpdmtpdr!CHierarchyHandler::QueryDeviceChildren+0x65
05 000000b5`6027e0c0 00007ffb`db68f589     wpdmtpdr!CHierarchyHandler::GetChildren+0x2ae
06 000000b5`6027e140 00007ffb`db672608     wpdmtpdr!CEnumContext::BeginFunctionalObjectsEnumeration+0xa9
07 000000b5`6027e230 00007ffb`db66f5a7     wpdmtpdr!WpdCapabilities::OnGetFunctionalObjects+0x118
08 000000b5`6027e2f0 00007ffb`db65e497     wpdmtpdr!WpdCapabilities::DispatchWpdMessage+0x18f
09 000000b5`6027e3e0 00007ffb`db65036d     wpdmtpdr!WpdBaseDriver::DispatchWpdMessage+0x5e7
0a 000000b5`6027e6a0 00007ffb`db64f82d     wpdmtpdr!CSessionQueue::ProcessWpdMessage+0x411
0b 000000b5`6027e720 00007ffc`14858eba     wpdmtpdr!CSessionQueue::OnDeviceIoControl+0x22d
```

So if we take a look into how the iPhone is answering this request we will be able to determine how the Storage object will behave, based on the three fields we mentioned above

![alt img](/images/appleLowerFilter/GetStorageInfoApple.jpg "Apple StorageInfo")

From above image we get the following information:
- **Storage Type == Fixed RAM**, this is pretty standard with mobile devices.
- **FileSystem Type == DCF**, DCF stands for Design Rules for Camera FS, many of you would recognize this from the famous `DCIM` root directory. The DCF standard defines the option to set the read-only attribute on directories and files.
- **Access Capability == Read-only without object deletion**, this is the nail in the coffin. This will define the access restrictions on the Storage object, and the OS will honour them. For example, this will affect the options displayed in the Context Menu within the iPhone.

So here we have it, this is why the file options on an iPhone are so limited. Just for comparison, the following image shows the StorageInfo Dataset for the Xiaomi device when plugged in using PTP

![alt img](/images/appleLowerFilter/GetStorageInfoXiaomi.jpg "Xiaomi StorageInfo")

As it turns out, this is the reason why I was able to create objects on the Xiaomi device even when connected using the PTP protocol. However, it's worth noting that Xiaomi seems to have an issue with their MTP responder. Regardless of whether PTP or MTP is selected on the device, the same Dataset is returned in response to the `GetStorageInfo` request, at least on the Redmi Note 8 model.

With that, we've addressed the questions we raised earlier in this section, providing a clearer understanding of why Apple devices behave the way they do, as well as how the WPD properties are configured for the device.

## The Impact of Apple Software on the Apple device stack
Before wrapping up this post, let's briefly discuss what happens when we install iTunes on our host machine and how it enables operations such as copying files to/from the device. As mentioned earlier, the WPD API will only provide a limited subset of operations on the iPhone due to the restrictions in the Storage object. However, when iTunes is installed, it adds a different layer that enables more comprehensive access to the device.

As we saw in the AppleLowerFilter, once iTunes is installed this will allow the device to select a different USB Configuration Descriptor. Without iTunes we are limited to the configuration 1, on the other hand once iTunes is installed by default the chosen configuration will be 3. Let's take a quick look at both configurations and their interfaces:

{{< more yaml >}} 
    ------------------ Configuration Descriptor -------------------
bLength                  : 0x09 (9 bytes)
bDescriptorType          : 0x02 (Configuration Descriptor)
wTotalLength             : 0x0027 (39 bytes)
bNumInterfaces           : 0x01 (1 Interface)
bConfigurationValue      : 0x01 (Configuration 1)
iConfiguration           : 0x05 (String Descriptor 5)
 Language 0x0409         : "PTP"
bmAttributes             : 0xC0
 D7: Reserved, set 1     : 0x01
 D6: Self Powered        : 0x01 (yes)
 D5: Remote Wakeup       : 0x00 (no)
 D4..0: Reserved, set 0  : 0x00
MaxPower                 : 0xFA (500 mA)

        ---------------- Interface Descriptor -----------------
bLength                  : 0x09 (9 bytes)
bDescriptorType          : 0x04 (Interface Descriptor)
bInterfaceNumber         : 0x00 (Interface 0)
bAlternateSetting        : 0x00
bNumEndpoints            : 0x03 (3 Endpoints)
bInterfaceClass          : 0x06 (Image)
bInterfaceSubClass       : 0x01 (Still Imaging device)
bInterfaceProtocol       : 0x01
iInterface               : 0x0E (String Descriptor 14)
 Language 0x0409         : "PTP"

// Endpoint descriptors -> Bulk IN, Bulk OUT & Interrupt IN

    ------------------ Configuration Descriptor -------------------
bLength                  : 0x09 (9 bytes)
bDescriptorType          : 0x02 (Configuration Descriptor)
wTotalLength             : 0x003E (62 bytes)
bNumInterfaces           : 0x02 (2 Interfaces)
bConfigurationValue      : 0x03 (Configuration 3)
iConfiguration           : 0x07 (String Descriptor 7)
 Language 0x0409         : "PTP + Apple Mobile Device"
bmAttributes             : 0xC0
 D7: Reserved, set 1     : 0x01
 D6: Self Powered        : 0x01 (yes)
 D5: Remote Wakeup       : 0x00 (no)
 D4..0: Reserved, set 0  : 0x00
MaxPower                 : 0xFA (500 mA)

        ---------------- Interface Descriptor -----------------
bLength                  : 0x09 (9 bytes)
bDescriptorType          : 0x04 (Interface Descriptor)
bInterfaceNumber         : 0x00 (Interface 0)
bAlternateSetting        : 0x00
bNumEndpoints            : 0x03 (3 Endpoints)
bInterfaceClass          : 0x06 (Image)
bInterfaceSubClass       : 0x01 (Still Imaging device)
bInterfaceProtocol       : 0x01
iInterface               : 0x0E (String Descriptor 14)
 Language 0x0409         : "PTP"

// Endpoint descriptors -> Bulk IN, Bulk OUT & Interrupt IN

        ---------------- Interface Descriptor -----------------
bLength                  : 0x09 (9 bytes)
bDescriptorType          : 0x04 (Interface Descriptor)
bInterfaceNumber         : 0x01 (Interface 1)
bAlternateSetting        : 0x00
bNumEndpoints            : 0x02 (2 Endpoints)
bInterfaceClass          : 0xFF (Vendor Specific)
bInterfaceSubClass       : 0xFE
bInterfaceProtocol       : 0x02
iInterface               : 0x17 (String Descriptor 23)
 Language 0x0409         : "Apple USB Multiplexor"

// Endpoint descriptors -> Bulk IN & Bulk OUT
{{< /more >}}

Selecting configuration 3, will make usbccgp generate the deviceID `USB\VID_xxxx&PID_yyyy&MI_01` (01 extracted from the bInterfaceNumber). And these deviceIDs are actually defined in the `appleusb.inf`, which define the copy of the following files:

```inf
[AppleUsbMux_Install]
Include=winusb.inf
Needs=WINUSB.NT
CopyFiles=AppleUsbFilter_CopyFiles
CopyFiles=AppleKmdfFilter_CopyFiles
FeatureScore=0x7F

[AppleUsbFilter_CopyFiles]
AppleUsbFilter.dll

[AppleKmdfFilter_CopyFiles]
AppleKmdfFilter.sys
```

These two drivers will be part of the device Apple calls "Apple Mobile Device USB Device", which communicates with the iPhone using a proprietary protocol rather than MTP or PTP. Yoy can learn more about this protocol by looking at the source code of the awesome [libimobiledevice](https://libimobiledevice.org/). Once the drivers are installed and running, iTunes itself communicates with the iPhone using a combination of standard WPD API calls and custom Apple-specific commands. This allows iTunes to offer features like copying files to/from the device, managing apps and backups, and updating the device firmware.

The following diagram provides a simplified overview of the entire device stack for an iPhone, including this scenario in which iTunes is installed and the AppleUsbMux device is created.

![alt img](/images/appleLowerFilter/AppleDeviceStack.jpg "Apple Device Stack")

## Conclusion
In this post, we explored how Apple's USB lower filter works on Windows machines and it's role in providing a different experience depending on whether Apple software is installed or not. We also delved into topics such as Windows Portable Device (WPD) and User-Mode Driver Framework (UMDF) to better understand the inner workings of the Apple device stack. We touched on how WPD devices are initialized and set up and this helped us learned why there's a mismatch between the WPD device protocol property and the class defined by the interface descriptor in Apple devices. We also looked into how the Storage object for a WPD device is set up and how this plays a role in the limitations that we have to operate with an iPhone without using third party software. Lastly, we briefly discussed how having iTunes installed make a difference in the Apple Mobile Device Stack and how this allows iTunes a way to properly manage the device content. 

It's understandable that Apple wants to protect certain information and limit out-of-the-box options for interacting with iPhone storage, but it would have been nice to have a more hybrid solution where users could have more flexibility within certain limits. While iTunes provides a robust solution for managing iPhone content, sometimes installing third-party software may not be an option. However, I recognize that with the recent release of iTunes as a Microsoft Store application, this limitation may be reduced. Overall, while I understand Apple's approach to limiting access to certain information, a bit more flexibility would have been welcome. Maybe a Mac is the solution for a better integration with Apple devices 😄.

Thank you for reading this post and I hope you found it informative! As always, if there's any mistake or something not clear, please don't hesitate to reach out to me on twitter [@n4r1b](https://twitter.com/n4r1B).
