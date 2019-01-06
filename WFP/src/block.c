#include "driver.h"
#include "misc.h"

// 协议特征
UINT32 RDP_MAGIC[RDP_MAGIC_SZ] = { 0x43000000,0x696b6f6f,0x6d203a65,0x68737473};
NTSTATUS
GetLocalTime(OUT PTIME_FIELDS  timeFields)
/*++
--*/
{
	NTSTATUS        status = STATUS_SUCCESS;
	LARGE_INTEGER   sysTime, locTime;
	KeQuerySystemTime(&sysTime);
	ExSystemTimeToLocalTime(&sysTime, &locTime);
	RtlTimeToTimeFields(&locTime, timeFields);
	return status;
}

// 返回当前时间毫秒数
VOID
GetLocalTimeStamp(OUT PLARGE_INTEGER locTime)
/*++
--*/
{
	LARGE_INTEGER   sysTime;
	KeQuerySystemTime(&sysTime);
	ExSystemTimeToLocalTime(&sysTime, locTime);
}


// 检查是不是RDP数据包
BOOLEAN IsLikeRDPPacket(PVOID pbuf, size_t size)
{
	BOOLEAN bIs = FALSE;
	
	// 大小check
	if (size >= MIN_SZ_RDPPACKET)
	{
		UINT32* p = (UINT32*)((PBYTE)(pbuf)+MAGIC_OFFSET);
		int i = 0;
		for (; i < RDP_MAGIC_SZ; ++i)
		{
			if (p[i] != RDP_MAGIC[i])
				break;
		}

		bIs = ((i >= RDP_MAGIC_SZ) ? TRUE : FALSE);
	}
	
	return bIs;
}

/*
特征码Cookie: mstshash=

 lengh:46  Local Port: 3389 remote = 192.168.206.1:14377 data=fffffa8002fa2650
  process : System
Break instruction exception - code 80000003 (first chance)
fffff880`033cbd41 cc              int     3
0: kd> dc fffffa8002fa2650
fffffa80`02fa2650  2e000003 0000e029 43000000 696b6f6f  ....)......Cooki
fffffa80`02fa2660  6d203a65 68737473 3d687361 65675567  e: mstshash=gUge
fffffa80`02fa2670  79616f78 00010a0d 00000008 00000000  xoay............
fffffa80`02fa2680  02090004 20646156 00000000 00000000  ....Vad ........
fffffa80`02fa2690  03804ab1 fffffa80 02c871e0 fffffa80  .J.......q......
fffffa80`02fa26a0  0395f630 fffffa80 00000180 00000000  0...............
fffffa80`02fa26b0  00000180 00000000 00000000 01000000  ................
fffffa80`02fa26c0  00000000 00000000 00000000 00000000  ................

*/