#include "driver.h"
#include "Callout.h"

// Global handle to the WFP Base Filter Engine
HANDLE g_filter_engine_handle = NULL;

#define EXAMPLE_DEVICE_STRING L"\\Device\\WFPExample"
#define EXAMPLE_DOS_DEVICE_STRING L"\\DosDevices\\WFPExample"

// Data and constants for the example Callout
#define EXAMPLE_CALLOUT_NAME		L"ExampleCallout"
#define EXAMPLE_CALLOUT_DESCRIPTION	L"A callout used for demonstration purposes"

// {6812FC83-7D3E-499a-A012-55E0D85F348B}
DEFINE_GUID(MY_WALL_EST,
	0x6812fc83,
	0x7d3e,
	0x499a,
	0xa0, 0x12, 0x55, 0xe0, 0xd8, 0x5f, 0x34, 0x8b
);

// {B438CEAE-FF2A-484f-9CB8-F425A288594C}
DEFINE_GUID(MY_WALL_STREAM,
	0xb438ceae,
	0xff2a,
	0x484f,
	0x9c, 0xb8, 0xf4, 0x25, 0xa2, 0x88, 0x59, 0x4c);


// Data and constants for the example Filter
#define EXAMPLE_FILTER_NAME L"ExampleFilter"
#define EXAMPLE_FILTER_DESCRIPTION L"A filter that uses the example callout"

// filter ID
UINT64 g_filter_est = 0;
UINT64 g_filter_stream = 0;

// callout ID
UINT32 g_callout_est = 0;
UINT32 g_callout_stream = 0;

PDEVICE_OBJECT g_WFP = NULL;

// 状态
UINT64 g_flag = 0;
PEDlist g_data = NULL;

// Driver entry and exit points
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD evt_unload;

// block 开关
VOID EnableBlock(BOOLEAN bEnable);

// Initializes required WDFDriver and WDFDevice objects
NTSTATUS init_driver_objects(DRIVER_OBJECT * driver_obj, UNICODE_STRING * registry_path,
	WDFDRIVER * driver, WDFDEVICE * device);

// 注册callout
NTSTATUS register_callout(IN DEVICE_OBJECT * wdm_device,
	IN const GUID* layerKey,
	IN const GUID* calloutKey,
	IN FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	IN FWPS_CALLOUT_NOTIFY_FN notifyFn,
	IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn,
	IN UINT32 flag,
	OUT UINT32* calloutId,
	OUT UINT64* filterId);

/************************************
			Functions
************************************/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT driver_obj, IN PUNICODE_STRING registry_path)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDFDRIVER driver = { 0 };
	WDFDEVICE device = { 0 };

	FWPM_SESSION wdf_session = { 0 };
	BOOLEAN in_transaction = FALSE;

	// Define this driver's unload function
	//driver_obj->DriverUnload = DriverUnload;
	status = init_driver_objects(driver_obj, registry_path, &driver, &device);
	if (!NT_SUCCESS(status)) goto Exit;

	// 初始化链表
	g_data = ExAllocatePoolWithTag(NonPagedPool, sizeof(EDlist), TAG_MEM_NOPAGE);
	if (g_data == NULL) goto Exit;
	RtlZeroMemory(g_data, sizeof(EDlist));

	InitializeListHead(&g_data->hips_list);
	KeInitializeSpinLock(&g_data->lock);
	EnableBlock(TRUE);

	// Begin a transaction to the FilterEngine. You must register objects (filter, callouts, sublayers)
	//to the filter engine in the context of a 'transaction'
	wdf_session.flags = FWPM_SESSION_FLAG_DYNAMIC;	// <-- Automatically destroys all filters and callouts after this wdf_session ends
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &wdf_session, &g_filter_engine_handle);
	if (!NT_SUCCESS(status)) goto Exit;
	status = FwpmTransactionBegin(g_filter_engine_handle, 0);
	if (!NT_SUCCESS(status)) goto Exit;
	in_transaction = TRUE;

	// Register the example Callout to the filter engine
	g_WFP = WdfDeviceWdmGetDeviceObject(device);

	if (g_WFP == NULL)
	{
		DbgPrint("wdm_device error, status 0x%08x\n", status);
		goto Exit;
	}
	status = register_callout(g_WFP,
		&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
		&MY_WALL_EST,	// callout key
		est_callout,// classfn
		example_notify,		// notify
		NULL,	// 不需要
		0,
		&g_callout_est,
		&g_filter_est);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("register_callout MY_WALL_EST error, status 0x%08x\n", status);
		goto Exit;
	}
	
	status = register_callout(g_WFP,
		&FWPM_LAYER_STREAM_V4,
		&MY_WALL_STREAM, 
		stream_callout, 
		example_notify, 
		example_flow_delete, 
		0,
		&g_callout_stream,
		&g_filter_stream);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("register_callout MY_WALL_STREAM error, status 0x%08x\n", status);
		goto Exit;
	}

	// Commit transaction to the Filter Engine
	status = FwpmTransactionCommit(g_filter_engine_handle);
	if (!NT_SUCCESS(status)) goto Exit;

	in_transaction = FALSE;

	// Cleanup and handle any errors
Exit:
	if (!NT_SUCCESS(status)){
		DbgPrint("WFPDriver example driver failed to load, status 0x%08x\n", status);
		if (in_transaction == TRUE){
			FwpmTransactionAbort(g_filter_engine_handle);
			_Analysis_assume_lock_not_held_(g_filter_engine_handle); // Potential leak if "FwpmTransactionAbort" fails
		}
		status = STATUS_FAILED_DRIVER_ENTRY;
	}
	
	else{
		DbgPrint("--- WFPDriver example driver loaded successfully ---\n");
	}

	return status;
}

NTSTATUS init_driver_objects(DRIVER_OBJECT * driver_obj, UNICODE_STRING * registry_path,
	WDFDRIVER * driver, WDFDEVICE * device)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDF_DRIVER_CONFIG config = { 0 };
	UNICODE_STRING device_name = { 0 };
	UNICODE_STRING device_symlink = { 0 };
	PWDFDEVICE_INIT device_init = NULL;

	RtlInitUnicodeString(&device_name, EXAMPLE_DEVICE_STRING);
	RtlInitUnicodeString(&device_symlink, EXAMPLE_DOS_DEVICE_STRING);

	// Create a WDFDRIVER for this driver
	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
	config.DriverInitFlags = WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = evt_unload; // <-- Necessary for this driver to unload correctly
	status = WdfDriverCreate(driver_obj, registry_path, WDF_NO_OBJECT_ATTRIBUTES, &config, driver);
	if (!NT_SUCCESS(status)) goto Exit;
	
	// WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE
	// 设置 IOCTL

	// Create a WDFDEVICE for this driver
	device_init = WdfControlDeviceInitAllocate(*driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);	// only admins and kernel can access device
	if (!device_init){
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto Exit;
	}

	// Configure the WDFDEVICE_INIT with a name to allow for access from user mode
	WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_NETWORK);
	WdfDeviceInitSetCharacteristics(device_init, FILE_DEVICE_SECURE_OPEN, FALSE);
	WdfDeviceInitAssignName(device_init, &device_name);
	WdfPdoInitAssignRawDevice(device_init, &GUID_DEVCLASS_NET);
	WdfDeviceInitSetDeviceClass(device_init, &GUID_DEVCLASS_NET);



	status = WdfDeviceCreate(&device_init, WDF_NO_OBJECT_ATTRIBUTES, device);
	if (!NT_SUCCESS(status)){
		WdfDeviceInitFree(device_init);
		goto Exit;
	}
	
	WdfControlFinishInitializing(*device);

Exit:
	return status;
}

NTSTATUS register_callout(IN DEVICE_OBJECT * wdm_device,
	IN const GUID* layerKey,
	IN const GUID* calloutKey,
	IN FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	IN FWPS_CALLOUT_NOTIFY_FN notifyFn,
	IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn,
	IN UINT32 flag,
	OUT UINT32* calloutId,
	OUT UINT64* filterId)
{
	NTSTATUS status = STATUS_SUCCESS;
	FWPS_CALLOUT s_callout = { 0 };
	FWPM_CALLOUT m_callout = { 0 };
	FWPM_DISPLAY_DATA display_data = { 0 };
	FWPM_FILTER     filter = { 0 };

	BOOLEAN regOK = FALSE;

	// 注册callout
	s_callout.calloutKey = *calloutKey;
	s_callout.classifyFn = classifyFn;
	s_callout.notifyFn = notifyFn;
	s_callout.flowDeleteFn = flowDeleteNotifyFn;
	s_callout.flags = flag;

	// STATUS_FWP_NULL_POINTER
	status = FwpsCalloutRegister((void *)wdm_device, &s_callout, calloutId);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to register callout functions for example callout, status 0x%08x", status);
		goto Exit;
	}
	regOK = TRUE;

	g_flag++;

	display_data.name = EXAMPLE_CALLOUT_NAME;
	display_data.description = EXAMPLE_CALLOUT_DESCRIPTION;

	// 关联filter
	m_callout.calloutKey = *calloutKey;
	m_callout.displayData = display_data;
	m_callout.applicableLayer = *layerKey;
	m_callout.flags = 0;

	status = FwpmCalloutAdd(g_filter_engine_handle, &m_callout, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to register example callout, status 0x%08x", status);
		goto Exit;
	}
	else {
		DbgPrint("Example Callout Registered");
	}
	// 创建filter
	filter.displayData.name = EXAMPLE_FILTER_NAME;
	filter.displayData.description = EXAMPLE_FILTER_DESCRIPTION;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;	// 必须给出决策
															// Says this filter's callout MUST make a block/permit decission
	//filter.subLayerKey = EXAMPLE_SUBLAYER_GUID;
	filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	//filter.weight.type = FWP_UINT8;
	filter.weight.type = FWP_EMPTY;
	//filter.weight.uint8 = 0xf;		// The weight of this filter within its sublayer
	filter.numFilterConditions = 0;	// If you specify 0, this filter invokes its callout for all traffic in its layer
	filter.layerKey = *layerKey;	// This layer must match the layer that ExampleCallout is registered to
	filter.action.calloutKey = *calloutKey;

	status = FwpmFilterAdd(g_filter_engine_handle, &filter, NULL, filterId);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to register example filter, status 0x%08x", status);
		goto Exit;
	}
	else {
		DbgPrint("Example filter registered");
		return status;
	}

Exit:
	if (regOK)
		FwpsCalloutUnregisterById(*calloutId);

	return status;
}

VOID evt_unload(WDFDRIVER Driver)
{

	DbgPrint("Unload !!!");
	NTSTATUS status;
	EnableBlock(FALSE);
	status = FwpmFilterDeleteById(g_filter_engine_handle, g_filter_est);
	if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister filters, status: 0x%08x", status);
	status = FwpmFilterDeleteById(g_filter_engine_handle, g_filter_stream);
	if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister filters, status: 0x%08x", status);
	status = FwpsCalloutUnregisterById(g_callout_est);
	if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister callout, status: 0x%08x", status);
	status = FwpsCalloutUnregisterById(g_callout_stream);
	if (!NT_SUCCESS(status)) DbgPrint("Failed to unregister callout, status: 0x%08x", status);

	// Close handle to the WFP Filter Engine
	if (g_filter_engine_handle) {
		FwpmEngineClose(g_filter_engine_handle);
		g_filter_engine_handle = NULL;
	}

	// 删除hips数据
	KIRQL irql;
	KeAcquireSpinLock(&g_data->lock, &irql);
	while (!IsListEmpty(&g_data->hips_list))
	{
		LIST_ENTRY* p;
		Hips_RDP* phr;
		p = RemoveHeadList(&g_data->hips_list);
		phr = CONTAINING_RECORD(p, Hips_RDP, listEntry);
		ExFreePoolWithTag(phr, TAG_MEM_NOPAGE);

	}
	KeReleaseSpinLock(&g_data->lock, irql);

	DbgPrint("--- WFPDriver example driver unloaded ---");
	return;
}


VOID EnableBlock(BOOLEAN bEnable)
{
	KIRQL irql;
	KeAcquireSpinLock(&g_data->lock, &irql);
	g_data->bEnable = bEnable;
	KeReleaseSpinLock(&g_data->lock, irql);
}