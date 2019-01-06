/** ExampleCallout.c

Implementation of an example Callout that inspects
outbound TCP traffic at the FWPM_OUTBOUND_TRANSPORT_V4
layer. This callout's ClassifyFn function prints the packets
TCP 4-tuple, and blocks the packet if it is bound for remote
port 1234. This Callout's NotifyFn function prints a message.

Author: Jared Wright - 2015
*/

#include "Callout.h"
#include "misc.h"

#define FORMAT_ADDR(x) (x>>24)&0xFF, (x>>16)&0xFF, (x>>8)&0xFF, x&0xFF
#define XFORMAT_ADDR(x) x&0xFF,(x>>8)&0xFF,(x>>16)&0xFF,(x>>24)&0xFF


UINT64 BuildFlowContext(const FWPS_INCOMING_VALUES * inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
	OUT UINT64* flowHandle);

// 工具
NTSTATUS InsertHipsData(Hips_RDP* pED);
void RemoveHipsData(Hips_RDP* pED);


/*************************
	ClassifyFn Function
**************************/
void example_classify(
	const FWPS_INCOMING_VALUES * inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
	void * layerData,
	const void * classifyContext,
	const FWPS_FILTER * filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT * classifyOut)
{
	UINT32 local_address = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT32 remote_address = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 local_port = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 remote_port = inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;

	UNREFERENCED_PARAMETER(inMetaValues);
	UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(filter);


	// If the packet is destined for remote port 1234, block the packet
	if (remote_port == 1234){
		DbgPrint("Blocking Packet to port 1234");
		classifyOut->actionType = FWP_ACTION_BLOCK;
		return;
	}
	// Otherwise, print its TCP 4-tuple
	else{
		DbgPrint("Example Classify found a packet: %d.%d.%d.%d:%hu --> %d.%d.%d.%d:%hu\n",
			FORMAT_ADDR(local_address), local_port, FORMAT_ADDR(remote_address), remote_port);
	}

	classifyOut->actionType = FWP_ACTION_PERMIT;
	return;
}

/*************************
	NotifyFn Function
**************************/
NTSTATUS example_notify(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID * filterKey,
	const FWPS_FILTER * filter)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	switch (notifyType){
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
		DbgPrint("A new filter has registered Example Callout as its action");
		break;
	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
		DbgPrint("A filter that uses Example Callout has just been deleted");
		break;
	}
	return status;
}


// 在该层收集信息
void est_callout(
	const FWPS_INCOMING_VALUES * inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
	void * layerData,
	const void * classifyContext,
	const FWPS_FILTER * filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT * classifyOut)

/*
Routine Description

   Our stream layer callout for traffic to/from the application we're
   interested in. Since we specified the filter that matches this callout
   as conditional on flow, we only get called if we've associated a flow with
   the traffic.

Arguments
   [IN] const FWPS_INCOMING_VALUES* inFixedValues -  The fixed values passed in
													  based on the traffic.
   [IN] const FWPS_INCOMING_METADATA_VALUES* inMetaValues - Metadata the
															 provides additional
															 information about the
															 connection.
   [IN] VOID* packet - Depending on the layer and protocol this can be NULL or a
					   layer specific type.
   [IN] const FWPS_FILTER* filter - The filter that has specified this callout.

   [IN] UINT64 flowContext - Flow context associated with a flow
   [OUT] FWPS_CLASSIFY_OUT* classifyOut - Out parameter that is used to inform
										   the filter engine of our decision

Return values

	STATUS_SUCCESS or a specific error code.

Notes


*/

{
	NTSTATUS status;
	UINT64 FlowHandle = 0;
	UINT64 FlowContext = 0;
	
	classifyOut->actionType = FWP_ACTION_PERMIT;

	// 开关
	if (g_data->bEnable == FALSE) return;

	// 生成我们的自有数据，这数据是传给上层 stream
	FlowContext = BuildFlowContext(inFixedValues, inMetaValues, &FlowHandle);

	if (!FlowContext)
	{
		DbgPrint("BuildFlowContext FlowContext err\n");
		//classifyOut->actionType = FWP_ACTION_PERMIT;
		return;
	}

	DbgPrint("BuildFlowContext FlowContext = %I64x g_callout_stream = %d FlowContext = %I64x\n", FlowHandle, g_callout_stream, FlowContext);
	
	// 绑定一个 Context 到 FWPS_LAYER_STREAM_V4 层的 g_callout_stream
	status = FwpsFlowAssociateContext(FlowHandle, 
		FWPS_LAYER_STREAM_V4,
		g_callout_stream,
		FlowContext);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("FwpsFlowAssociateContext err 0x%x\n",status);
		//classifyOut->actionType = FWP_ACTION_PERMIT;
		return;
	}
}

// 在该层判断
void stream_callout(
	const FWPS_INCOMING_VALUES * inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
	void * layerData,
	const void * classifyContext,
	const FWPS_FILTER * filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT * classifyOut)
	/*
Routine Description

   Our stream layer callout for traffic to/from the application we're
   interested in. Since we specified the filter that matches this callout
   as conditional on flow, we only get called if we've associated a flow with
   the traffic.

Arguments
   [IN] const FWPS_INCOMING_VALUES* inFixedValues -  The fixed values passed in
													  based on the traffic.
   [IN] const FWPS_INCOMING_METADATA_VALUES* inMetaValues - Metadata the
															 provides additional
															 information about the
															 connection.
   [IN] VOID* packet - Depending on the layer and protocol this can be NULL or a
					   layer specific type.
   [IN] const FWPS_FILTER* filter - The filter that has specified this callout.

   [IN] UINT64 flowContext - Flow context associated with a flow
   [OUT] FWPS_CLASSIFY_OUT* classifyOut - Out parameter that is used to inform
										   the filter engine of our decision

Return values
	STATUS_SUCCESS or a specific error code.
Notes

*/
{
	DbgPrint("FWPM_LAYER_STREAM_V4\n");
	FWPS_STREAM_CALLOUT_IO_PACKET* streamPacket;
	PCHAR byDataStream = NULL;
	Hips_RDP* pHR = NULL;
	//FLOW_DATA* flowData;

	// 默认放行
	UINT32 flag = FWP_ACTION_PERMIT; // ( 我们的驱动必须给出决断，放行 or 阻止) 
	//UINT32 flag = FWP_ACTION_CONTINUE; // 如果是 监听类型的，返回 FWP_ACTION_CONTINUE
	UINT32 uI32 = 0;
	BOOLEAN inbound = FALSE;

	// 开关
	if (g_data->bEnable == FALSE) return;

	// 取出我们在 establish 层存的数据 ( 在 delete 回调中需要删除 )
	PEventData pED = NULL;
	streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;
	
	byDataStream = ExAllocatePoolWithTag(NonPagedPool, 
		streamPacket->streamData->dataLength, 
		TAG_MEM_NOPAGE);

	if (byDataStream == NULL)
	{
		DbgPrint("stream_callout ExAllocatePoolWithTag err\n");
		goto Exit;
	}

	FwpsCopyStreamDataToBuffer0(
		streamPacket->streamData,
		byDataStream,
		streamPacket->streamData->dataLength,
		&uI32);

	ASSERT(uI32 == streamPacket->streamData->dataLength);

	// 接收 or 发送
	inbound = (BOOLEAN)((streamPacket->streamData->flags & FWPS_STREAM_FLAG_RECEIVE) == FWPS_STREAM_FLAG_RECEIVE);

	if (streamPacket->streamData->dataLength > 0)
	{
		if (flowContext)
		{
			pED = (PEventData)flowContext;
			DbgPrint("inbound:%d \n lengh:%d  Local Port: %d remote = %d.%d.%d.%d:%hu data=%I64x\n  process : %ws \n",
				inbound,
				streamPacket->streamData->dataLength,
				pED->ud.localPort,
				FORMAT_ADDR(pED->ud.remoteAddressV4),
				pED->ud.remotePort,
				byDataStream,
				pED->ud.processPath);

			
			// 简单check 是系统进程
			if (pED->ud.processID <= 4 && pED->ud.localPort == RDP_PORT && inbound == TRUE)
			{
				//DbgBreakPoint();
				// 检查是否RDP 会话认证包
				if (IsLikeRDPPacket(byDataStream, uI32))
				{
					DbgPrint("IsLikeRDPPacket\n");
					pHR = FindHipsDataByIp(pED->ud.remoteAddressV4);
					//pED->ud.ctConn++;
					// 首次出现
					if (pHR == NULL)
					{
						pHR = ExAllocatePoolWithTag(NonPagedPool,
							sizeof(Hips_RDP),
							TAG_MEM_NOPAGE);
						if (pHR != NULL)
						{
							RtlZeroMemory(pHR, sizeof(Hips_RDP));
							GetLocalTimeStamp(&(pHR->time));
							pHR->remoteAddressV4 = pED->ud.remoteAddressV4;
							pHR->op = FWP_ACTION_PERMIT;
							InsertHipsData(pHR);
							DbgPrint("new RDP !!! \n");
						}
						else
						{
							DbgPrint("Hips_RDP No Memory!!!\n");
							goto Exit;
						}
					}

					DbgPrint("Check RDP !!! \n");

					// 连接计数
					pHR->ctConn++;
					// 毫秒
					LARGE_INTEGER nowtime = { 0 };
					GetLocalTimeStamp(&nowtime);
					
					// 规则check
					// 规则1 尝试次数总计超过 RDP_TRY_COUNT
					if (pHR->ctConn >= RDP_TRY_COUNT)
					{
						pHR->op = FWP_ACTION_BLOCK;
						DbgPrint("Hips_RDP BLOCK remote = %d.%d.%d.%d:%hu !!!\n",
							FORMAT_ADDR(pED->ud.remoteAddressV4),
							pED->ud.remotePort);
					}
					
					UINT64 time_spend = (nowtime.QuadPart - pHR->time.QuadPart) / 1000;

					// 规则2 尝试的频率太快了
					if (time_spend > 0 && (pHR->ctConn / time_spend) >= RDP_TRY_PERTIMES )
					{
						pHR->op = FWP_ACTION_BLOCK;
						DbgPrint("Hips_RDP BLOCK remote = %d.%d.%d.%d:%hu !!!\n",
							FORMAT_ADDR(pED->ud.remoteAddressV4),
							pED->ud.remotePort);
					}

					// 修改规则
					flag = pHR->op;
				}
			}
		}
	}
	// 看下数据
	//DbgBreakPoint();

Exit:
	if (byDataStream)
		ExFreePoolWithTag(byDataStream, TAG_MEM_NOPAGE);

	classifyOut->actionType = flag;
}

/***************************
	FlowDeleteFn Function
****************************/
NTSTATUS example_flow_delete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
	// 删除我们est->stream的Context数据
	if (layerId == FWPS_LAYER_STREAM_V4 && 
		calloutId == g_callout_stream && 
		flowContext)
	{
		PEventData pED = (PEventData)flowContext;
		ClearEventData(pED);
	}
	return STATUS_SUCCESS;
}

// establish 阶段回调
UINT64 BuildFlowContext(const FWPS_INCOMING_VALUES * inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues, 
	OUT UINT64* flowHandle)
{
	FWP_BYTE_BLOB* processPath;
	PEventData pED = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_PATH))
	{
		DbgPrint("Not Find FWPS_METADATA_FIELD_PROCESS_PATH");
		goto Exit;
	}

	processPath = inMetaValues->processPath;
	//UINT64 FlowHandle;
	UINT32 local_address = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32;
	UINT32 remote_address = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;
	UINT16 local_port = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;
	UINT16 remote_port = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;

	DbgPrint("FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4: %d.%d.%d.%d:%hu --> %d.%d.%d.%d:%hu\n",
		FORMAT_ADDR(local_address), local_port, FORMAT_ADDR(remote_address), remote_port);

	pED = ExAllocatePoolWithTag(NonPagedPool, sizeof(EventData), TAG_MEM_NOPAGE);
	if (!pED)
	{
		DbgPrint("PEventData err\n");
		goto Exit;
	}
	RtlZeroMemory(pED, sizeof(EventData));

	pED->flowHandle = inMetaValues->flowHandle;
	*flowHandle = pED->flowHandle;
	pED->ud.localAddressV4 = local_address;
	pED->ud.localPort = local_port;
	pED->ud.remoteAddressV4 = remote_address;
	pED->ud.remotePort = remote_port;
	pED->ud.processID = inMetaValues->processId;

	pED->ud.processPath = ExAllocatePoolWithTag(NonPagedPool,
		processPath->size,
		TAG_MEM_NOPAGE);
	if (! pED->ud.processPath)
	{
		DbgPrint("processPath no Memory!!!\n");
		goto Exit;
	}
	// 拷贝进程路径
	memcpy(pED->ud.processPath, processPath->data, processPath->size);

	status = STATUS_SUCCESS;

Exit:

	if ((status != STATUS_SUCCESS) && pED)
	{
		ClearEventData(pED);
		pED = NULL;
	}

	return (UINT64)pED;
}

void ClearEventData(EventData* pED)
{
	if (pED->ud.processPath)
	{
		ExFreePoolWithTag(pED->ud.processPath, TAG_MEM_NOPAGE);
	}
	ExFreePoolWithTag(pED, TAG_MEM_NOPAGE);
}

NTSTATUS InsertHipsData(Hips_RDP* pED)
{
	//ExInterlockedInsertTailList(&g_data->list, &pED->listEntry, &g_data->lock);
	KIRQL irql;
	KeAcquireSpinLock(&g_data->lock, &irql);
	if (g_data->bEnable)
	{
		InsertTailList(&g_data->hips_list, &pED->listEntry);
		g_data->hips_count++;
	}
	KeReleaseSpinLock(&g_data->lock, irql);

	return STATUS_SUCCESS;
}
void RemoveHipsData(Hips_RDP* pED)
{
	//ExInterlockedRemoveHeadList(&g_list->list, &g_list->lock);
	KIRQL irql;
	KeAcquireSpinLock(&g_data->lock, &irql);
	if (g_data->bEnable)
	{
		RemoveEntryList(&pED->listEntry);
		g_data->hips_count--;
	}
	KeReleaseSpinLock(&g_data->lock, irql);
}

Hips_RDP* FindHipsDataByIp(UINT32 ip)
{
	KIRQL irql;
	Hips_RDP* pED = NULL;
	PLIST_ENTRY p = NULL;

	KeAcquireSpinLock(&g_data->lock, &irql);
	if(g_data->bEnable)
	{
		for (p = g_data->hips_list.Blink; p != &(g_data->hips_list); p = p->Blink)
		{
			pED = CONTAINING_RECORD(p, Hips_RDP, listEntry);
			if (pED->remoteAddressV4 == ip)
				break;
		}
	}

	KeReleaseSpinLock(&g_data->lock, irql);

	return pED;
}
