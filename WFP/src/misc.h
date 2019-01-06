#pragma once
#include "driver.h"

#define  RDP_MAGIC_SZ		0x4
#define  MAGIC_OFFSET		0x8
#define  MIN_SZ_RDPPACKET	RDP_MAGIC_SZ * 4 + MAGIC_OFFSET
#define  RDP_PORT 3389
#define  RDP_TRY_COUNT		20
#define  RDP_TRY_PERTIMES	2		// 平均1s内连接2次
BOOLEAN IsLikeRDPPacket(PVOID pbuf, size_t size);
extern UINT32 RDP_MAGIC[RDP_MAGIC_SZ];