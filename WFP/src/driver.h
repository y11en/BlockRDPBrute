/** WFPDriver.h

Imports needed for the Windows Filtering Platform

Author: Jared Wright - 2015
*/

#ifndef WFPDriver_H
#define WFPDriver_H


#define NDIS61 1				// Need to declare this to compile WFP stuff on Win7, I'm not sure why

#include "Ntifs.h"
#include <ntddk.h>				// Windows Driver Development Kit
#include <wdf.h>				// Windows Driver Foundation


#pragma warning(push)
#pragma warning(disable: 4201)	// Disable "Nameless struct/union" compiler warning for fwpsk.h only!
#include <fwpsk.h>				// Functions and enumerated types used to implement callouts in kernel mode
#pragma warning(pop)			// Re-enable "Nameless struct/union" compiler warning

#include <fwpmk.h>				// Functions used for managing IKE and AuthIP main mode (MM) policy and security associations
#include <fwpvi.h>				// Mappings of OS specific function versions (i.e. fn's that end in 0 or 1)
#include <guiddef.h>			// Used to define GUID's
#include <initguid.h>			// Used to define GUID's
#include "devguid.h"

#define TAG_MEM_NOPAGE   'gdaq'

NTSTATUS
GetLocalTime(OUT PTIME_FIELDS  timeFields);
VOID
GetLocalTimeStamp(OUT PLARGE_INTEGER locTime);

typedef enum 
{
	TP_SEND = 0,
	TP_RECV
}ENUM_SOCKET_TYPE;

typedef struct
{
	ULONG   localAddressV4;
	USHORT  localPort;
	USHORT  ipProto;
	ULONG   remoteAddressV4;
	USHORT  remotePort;
	WCHAR*  processPath;
	UINT64	processID;
}userData;

typedef struct
{
	LIST_ENTRY  listEntry;
	ULONG   remoteAddressV4;
	USHORT  remotePort;
	UINT32  ctConn;			// 连接次数	
	LARGE_INTEGER  time;	// 首次连接时间戳
	UINT32 op;				// 操作标志
	ENUM_SOCKET_TYPE type;	// 标识，是入站还是出站规则（暂时没用）
}Hips_RDP, PHIPS_RDP;

// 上下文
typedef struct
{
	LIST_ENTRY  listEntry;
	UINT64      flowHandle;
	UINT64      flowContext;
	UINT64      calloutId;
	userData	ud;
}EventData,*PEventData;

typedef struct
{
	LIST_ENTRY hips_list;
	KSPIN_LOCK lock;
	UINT64 hips_count;
	BOOLEAN bEnable;
}EDlist, *PEDlist;


#endif // include guard