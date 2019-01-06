/** ExampleCallout.h

Public functions for the ExampleCallout.

Author: Jared Wright - 2015
*/

#ifndef ExampelCallout_H
#define ExampelCallout_H

#include "driver.h"

/*	The "classifyFn" callout function for this Callout.
For more information about a Callout's classifyFn, see:
http://msdn.microsoft.com/en-us/library/windows/hardware/ff544893(v=vs.85).aspx
*/
/*
void example_classify(
	const FWPS_INCOMING_VALUES * inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
	void * layerData,
	const void * classifyContext,
	const FWPS_FILTER * filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT * classifyOut);
*/
// kill
void est_callout(
	const FWPS_INCOMING_VALUES * inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
	void * layerData,
	const void * classifyContext,
	const FWPS_FILTER * filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT * classifyOut);

void stream_callout(
	const FWPS_INCOMING_VALUES * inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES * inMetaValues,
	void * layerData,
	const void * classifyContext,
	const FWPS_FILTER * filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT * classifyOut);

/*	The "notifyFn" callout function for this Callout.
This function manages setting up global resources and a worker thread
managed by this Callout. For more information about a Callout's notifyFn, see:
http://msdn.microsoft.com/en-us/library/windows/hardware/ff568804(v=vs.85).aspx
*/
NTSTATUS example_notify(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID * filterKey,
	const FWPS_FILTER * filter);

void ClearEventData(EventData* pED);
Hips_RDP* FindHipsDataByIp(UINT32 ip);

/*	The "flowDeleteFn" callout function for this Callout.
This function doesn't do anything.
http://msdn.microsoft.com/en-us/library/windows/hardware/ff550025(v=vs.85).aspx
*/
NTSTATUS example_flow_delete(
	UINT16 layerId,
	UINT32 calloutId,
	UINT64 flowContext);


extern PEDlist g_data;

// filter ID
extern UINT64 g_filter_est;
extern UINT64 g_filter_stream;
// callout ID
extern UINT32 g_callout_est;
extern UINT32 g_callout_stream;




#endif	// include guard