#pragma once

#include <iostream>
#include <Windows.h>
#include <thread>
#include <unordered_map>
#include <strsafe.h>

#define NOTIFY_LOG_COME_ON L"Notify_NEW_LOG"
#define SECURITY_LOG	L"Security"
#define PROVIDER_NAME	L"Microsoft-Windows-Security-Auditing"
#define MAX_TIMESTAMP_LEN   23 + 1   // mm/dd/yyyy hh:mm:ss.mmm


// 登陆状态码
#define EVENT_TYPE_LOGON_SUCCESS		4624
#define EVENT_TYPE_LOGON_UNSUCCESSFUL	4625

// 错误状态码
#define EVENT_STATUES_NOT_FOUND_USERNAME	L"0xc0000064"
#define EVENT_STATUES_PASSWORD_WRONG		L"0xc000006a"

// 登陆方式
#define EVENT_LOGON_NET	L"3"
#define EVENT_LOGON_RDP L"10"


CONST wchar_t* pEventTypeNames[] = { L"Error", L"Warning", L"Informational", L"Audit Success", L"Audit Failure" };

// EVENT_TYPE_LOGON_UNSUCCESSFUL 的键值
CONST wchar_t* KEYs[] = { L"SubjectUserSid",L"SubjectUserName",L"SubjectDomainName",L"SubjectLogonId",L"TargetUserSid",
L"TargetUserName",L"TargetDomainName",L"Status",L"FailureReason",L"SubStatus",L"LogonType",
L"LogonProcessName",L"AuthenticationPackageName",L"WorkstationName",L"TransmittedServices",
L"LmPackageName",L"KeyLength",L"ProcessId",L"ProcessName",L"IpAddress",L"IpPort" };


#define MIN(a,b) (a>b?b:a)

class EventData
{
public:
	EventData() {}
	~EventData() {}
	DWORD time;
	DWORD eventID;
	DWORD eventType;
	std::unordered_map <std::wstring, std::wstring> eventData;
};


// 错误计数器
class CountClass
{

public:
	CountClass() { ctErrPWD = 0; ctErrUSR = 0; firsttime = 0; }
	~CountClass() {}

	DWORD ctErrPWD;			// 密码错误次数
	DWORD ctErrUSR;			// 用户名错误次数	
	DWORD firsttime;		// 首次出现时间戳
};

class JudgeConext
{
public:
	~JudgeConext()
	{
	}
	JudgeConext()
	{
		hEvent = INVALID_HANDLE_VALUE;
		hLog = INVALID_HANDLE_VALUE;
	}
	JudgeConext(HANDLE e, HANDLE l): hEvent(e), hLog(l)
	{
	}

	HANDLE hEvent;
	HANDLE hLog;
	
	static HANDLE CloseNotify;
	static std::unordered_map <std::wstring, CountClass*> m_Hips;
};


/*
typedef struct
{
	WCHAR* SourceName;
	WCHAR* Computername;
	SID*   UserSid;
	WCHAR* Strings;
	BYTE*  Data;
	CHAR*  Pad;
	DWORD Length;
}ExtData;
*/
// 登陆失败Event
/*
- - <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
- <System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
  <EventID>4625</EventID> 
  <Version>0</Version> 
  <Level>0</Level> 
  <Task>12544</Task> 
  <Opcode>0</Opcode> 
  <Keywords>0x8010000000000000</Keywords> 
  <TimeCreated SystemTime="2018-12-31T07:15:06.929593400Z" /> 
  <EventRecordID>794</EventRecordID> 
  <Correlation /> 
  <Execution ProcessID="488" ThreadID="2552" /> 
  <Channel>Security</Channel> 
  <Computer>WIN-F4RAKLS2S1R</Computer> 
  <Security /> 
  </System>
- <EventData>
  <Data Name="SubjectUserSid">S-1-5-18</Data> 
  <Data Name="SubjectUserName">WIN-F4RAKLS2S1R$</Data> 
  <Data Name="SubjectDomainName">WORKGROUP</Data> 
  <Data Name="SubjectLogonId">0x3e7</Data> 
  <Data Name="TargetUserSid">S-1-0-0</Data> 
  <Data Name="TargetUserName">admin8</Data> 
  <Data Name="TargetDomainName">WIN-F4RAKLS2S1R</Data> 
  <Data Name="Status">0xc000006d</Data> 
  <Data Name="FailureReason">%%2313</Data> 
  <Data Name="SubStatus">0xc0000064</Data> 
  <Data Name="LogonType">10</Data> 
  <Data Name="LogonProcessName">User32</Data> 
  <Data Name="AuthenticationPackageName">Negotiate</Data> 
  <Data Name="WorkstationName">WIN-F4RAKLS2S1R</Data> 
  <Data Name="TransmittedServices">-</Data> 
  <Data Name="LmPackageName">-</Data> 
  <Data Name="KeyLength">0</Data> 
  <Data Name="ProcessId">0x31c</Data> 
  <Data Name="ProcessName">C:\Windows\System32\winlogon.exe</Data> 
  <Data Name="IpAddress">192.168.206.1</Data> 
  <Data Name="IpPort">6709</Data> 
  </EventData>
  </Event>
*/