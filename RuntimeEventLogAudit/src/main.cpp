#include "pch.h"
#include "notify.h"
#include "lock.h"


HANDLE JudgeConext::CloseNotify = INVALID_HANDLE_VALUE;
std::unordered_map <std::wstring, CountClass*> JudgeConext::m_Hips;

CRITICAL_SECTION Mutex::m_cs;
bool Mutex::is_init;


// DEMO
// https://docs.microsoft.com/zh-cn/windows/desktop/EventLog/receiving-event-notification
// https://docs.microsoft.com/zh-cn/windows/desktop/EventLog/querying-for-event-source-messages

// windows Event
// https://blog.csdn.net/xiliang_pan/article/details/41805023
// https://blog.csdn.net/lygzscnt12/article/details/79495361

// Get the record number to the last record in the log file.
DWORD GetLastRecordNumber(HANDLE hEventLog, DWORD* pdwRecordNumber)
{
	DWORD status = ERROR_SUCCESS;
	DWORD OldestRecordNumber = 0;
	DWORD NumberOfRecords = 0;

	wprintf(L"in GetLastRecordNumber\n");
	if (!GetOldestEventLogRecord(hEventLog, &OldestRecordNumber))
	{
		wprintf(L"GetOldestEventLogRecord failed with %lu.\n", status = GetLastError());
		goto cleanup;
	}
	wprintf(L"out GetLastRecordNumber2 \n");
	if (!GetNumberOfEventLogRecords(hEventLog, &NumberOfRecords))
	{
		wprintf(L"GetOldestEventLogRecord failed with %lu.\n", status = GetLastError());
		goto cleanup;
	}

	*pdwRecordNumber = OldestRecordNumber + NumberOfRecords - 1;

	wprintf(L"out GetLastRecordNumber\n");

cleanup:

	return status;
}

// Read a single record from the event log.
DWORD ReadRecord(HANDLE hEventLog, PBYTE & pBuffer, DWORD dwRecordNumber, DWORD dwFlags)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwBytesToRead = sizeof(EVENTLOGRECORD);
	DWORD dwBytesRead = 0;
	DWORD dwMinimumBytesToRead = 0;
	PBYTE pTemp = NULL;

	//printf("in ReadRecord\n");
	// The initial size of the buffer is not big enough to read a record, but ReadEventLog
	// requires a valid pointer. The ReadEventLog function will fail and return the required 
	// buffer size; reallocate the buffer to the required size.
	pBuffer = (PBYTE)malloc(sizeof(EVENTLOGRECORD));

	// Get the required buffer size, reallocate the buffer and then read the event record.
	if (!ReadEventLog(hEventLog, dwFlags, dwRecordNumber, pBuffer, dwBytesToRead, &dwBytesRead, &dwMinimumBytesToRead))
	{
		status = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == status)
		{
			status = ERROR_SUCCESS;

			pTemp = (PBYTE)realloc(pBuffer, dwMinimumBytesToRead);
			if (NULL == pTemp)
			{
				wprintf(L"Failed to reallocate memory for the record buffer (%d bytes).\n", dwMinimumBytesToRead);
				goto cleanup;
			}

			pBuffer = pTemp;

			dwBytesToRead = dwMinimumBytesToRead;

			if (!ReadEventLog(hEventLog, dwFlags, dwRecordNumber, pBuffer, dwBytesToRead, &dwBytesRead, &dwMinimumBytesToRead))
			{
				wprintf(L"Second ReadEventLog failed with %lu.\n", status = GetLastError());
				goto cleanup;
			}
		}
		else
		{
			if (ERROR_HANDLE_EOF != status)
			{
				wprintf(L"ReadEventLog failed with %lu.\n", status);
				goto cleanup;
			}
		}
	}

	//wprintf(L"OUT ReadRecord\n");
cleanup:

	return status;
}

// Get the last record number in the log file and read it.
// This positions the cursor, so that we can begin reading 
// new records when the service notifies us that new records were 
// written to the log file.
DWORD SeekToLastRecord(HANDLE hEventLog)
{
	DWORD status = ERROR_SUCCESS;
	DWORD dwLastRecordNumber = 0;
	PBYTE pRecord = NULL;

	//wprintf(L"in SeekToLastRecord\n");

	status = GetLastRecordNumber(hEventLog, &dwLastRecordNumber);
	if (ERROR_SUCCESS != status)
	{
		wprintf(L"GetLastRecordNumber failed.\n");
		goto cleanup;
	}

	//wprintf(L"in SeekToLastRecord 2\n");
	status = ReadRecord(hEventLog, pRecord, dwLastRecordNumber, EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ);
	if (ERROR_SUCCESS != status)
	{
		wprintf(L"ReadRecord failed seeking to record %lu.\n", dwLastRecordNumber);
		goto cleanup;
	}

cleanup:

	if (pRecord)
		free(pRecord);

	//wprintf(L"OUT SeekToLastRecord\n");
	return status;
}

// Get a string that contains the time stamp of when the event 
// was generated.
void GetTimestamp(const DWORD Time, WCHAR DisplayString[])
{
	ULONGLONG ullTimeStamp = 0;
	ULONGLONG SecsTo1970 = 116444736000000000;
	SYSTEMTIME st;
	FILETIME ft, ftLocal;

	ullTimeStamp = Int32x32To64(Time, 10000000) + SecsTo1970;
	ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
	ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);

	FileTimeToLocalFileTime(&ft, &ftLocal);
	FileTimeToSystemTime(&ftLocal, &st);
	StringCchPrintf(DisplayString, MAX_TIMESTAMP_LEN, L"%d/%d/%d %.2d:%.2d:%.2d",
		st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);
}
DWORD GetEventTypeName(DWORD EventType)
{
	DWORD index = 0;

	switch (EventType)
	{
	case EVENTLOG_ERROR_TYPE:
		index = 0;
		break;
	case EVENTLOG_WARNING_TYPE:
		index = 1;
		break;
	case EVENTLOG_INFORMATION_TYPE:
		index = 2;
		break;
	case EVENTLOG_AUDIT_SUCCESS:
		index = 3;
		break;
	case EVENTLOG_AUDIT_FAILURE:
		index = 4;
		break;
	}

	return index;
}

typedef bool ( *frule )(CountClass* cc, DWORD nowtime);

//1. 错误总数累计>=10次
bool rule1(CountClass* cc, DWORD nowtime)
{
	return (cc->ctErrPWD + cc->ctErrUSR) > 10;
}

//2. 30s内>=5次错误 
bool rule2(CountClass* cc , DWORD nowtime)
{
	if ((nowtime - cc->firsttime) < 30)
	{
		return (cc->ctErrPWD + cc->ctErrUSR) > 5;
	}
	return false;
}
// rule 表
frule g_rule[] = { rule2,rule1 };

// RDP check
void OnJudge(EventData& ed)
{
	bool ban = false;
	switch (ed.eventID)
	{
	case EVENT_TYPE_LOGON_SUCCESS:
		// not do
		break;
	case EVENT_TYPE_LOGON_UNSUCCESSFUL:
		if (ed.eventType == EVENTLOG_AUDIT_FAILURE)
		{
			// 局域网环境 判断IP即可
			std::wstring ip = ed.eventData[L"IpAddress"];

			// 工作组\域 环境 (可能)需要结合该字段
			std::wstring domain = ed.eventData[L"TargetDomainName"];
			std::wstring logonType = ed.eventData[L"LogonType"];

			std::wstring username = ed.eventData[L"TargetUserName"];
			std::wstring statusCode = std::wstring(ed.eventData[L"SubStatus"]);
			
			if (logonType == EVENT_LOGON_NET || logonType == EVENT_LOGON_RDP)
			{
				CountClass* cc = nullptr;
				
				// 锁住
				autoLock al;

				// lock
				// 新用户
				if (JudgeConext::m_Hips.find(ip) == JudgeConext::m_Hips.end())
				{
					cc = new CountClass();
					cc->firsttime = ed.time;
					JudgeConext::m_Hips[ip] = cc;
				}
				else {
					// 存在取出来
					cc = JudgeConext::m_Hips[ip];
				}

				// 无此用户
				if (statusCode == EVENT_STATUES_NOT_FOUND_USERNAME)
				{
					cc->ctErrUSR++;
					//InterlockedAdd((LONG*)&(cc->ctErrUSR), 1);
				}
				// 密码错误
				else if (statusCode == EVENT_STATUES_PASSWORD_WRONG)
				{
					cc->ctErrPWD++;
					//InterlockedAdd((LONG*)&(cc->ctErrPWD), 1);
				}

				// rule check
				for (int i = 0; i < sizeof(g_rule) / sizeof(frule); ++i)
				{
					if ((g_rule[i])(cc, ed.time))
					{
						ban = true;
						break;
					}
				}

				wprintf(L"from ip=%s try use %s logon\ntotal error USR %d PWD %d \n", ip.c_str(), 
					username.c_str(), 
					cc->ctErrUSR,
					cc->ctErrPWD);
				if (ban)
				{
					// 至于 怎么 block ip 自己发挥
					wprintf(L"ip = %s you are bannd \n", ip.c_str());
				}
			}
		}
		break;
	default:
		break;
	}
}

void NotifyCallback(PVOID parg)
{
	JudgeConext* pNC = (JudgeConext*)parg;
	DWORD OldestRecord = 0, NumberOfRecords = 0, status;
	PBYTE pRecord = NULL;

	OldestRecord = 0;
	NumberOfRecords = 0;
	// 获取最老的事件日志
	status = ERROR_SUCCESS;
	// Read the first record to prime the loop.
	status = ReadRecord(pNC->hLog, pRecord, 0, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ);
	if (ERROR_SUCCESS != status && ERROR_HANDLE_EOF != status)
	{
		wprintf(L"ReadRecord (priming read) failed.\n");
	}

	// DWORD dtmp = 0;
	//wprintf(L"in NotifyCallback %s \n", (LPWSTR)(pRecord + sizeof(EVENTLOGRECORD)));

	//ExtData ext;
	// event 来源
	//ext.SourceName =  (WCHAR*)((PBYTE)pRecord + sizeof(EVENTLOGRECORD));
	// 产生event 的电脑名称
	//ext.Computername = (WCHAR*)(ext.SourceName + lstrlenW(ext.SourceName)) + 1; // len + padding

	if (0 == wcscmp(PROVIDER_NAME, (LPWSTR)(pRecord + sizeof(EVENTLOGRECORD))))
	{
		DWORD EventID = ((PEVENTLOGRECORD)pRecord)->EventID & 0xFFFF;
		//DWORD record_number = ((PEVENTLOGRECORD)pRecord)->RecordNumber;
		//WCHAR EventTime[MAX_TIMESTAMP_LEN] = { 0 };
	
		EventData ed;
		ed.time = ((PEVENTLOGRECORD)pRecord)->TimeWritten;
		ed.eventType = ((PEVENTLOGRECORD)pRecord)->EventType;
		ed.eventID = EventID;
	
	/*
		
		GetTimestamp(((PEVENTLOGRECORD)pRecord)->TimeWritten, EventTime);
		wprintf(L"EventTime: %s\n", EventTime);
		wprintf(L"record number: %lu\n", record_number);
		wprintf(L"EventID: %d\n", EventID);
		wprintf(L"EventType: %s\n", pEventTypeNames[GetEventTypeName(((PEVENTLOGRECORD)pRecord)->EventType)]);

		//wprintf(L"event type: %s\n", pEventTypeNames[GetEventTypeName(((PEVENTLOGRECORD)pRecord)->EventType)]);
		wprintf(L"DataLength: %d\n", ((PEVENTLOGRECORD)pRecord)->DataLength);
		wprintf(L"DataOffset: %x\n", ((PEVENTLOGRECORD)pRecord)->DataOffset);
		wprintf(L"NumStrings:%d %d\n", ((PEVENTLOGRECORD)pRecord)->NumStrings , ((PEVENTLOGRECORD)pRecord)->StringOffset);
		
	*/	
		PWCHAR pWString = NULL;

		

		// 格式化模板 %%2313
		for (int i = 0, offset = ((PEVENTLOGRECORD)pRecord)->StringOffset; 
			i < MIN(((PEVENTLOGRECORD)pRecord)->NumStrings, sizeof(KEYs) / sizeof(WCHAR*));
			++i)
		{
			pWString = (WCHAR*)(pRecord + offset);
			//wprintf(L"[%d]: %s\n", i, pWString);
			ed.eventData[KEYs[i]] = std::wstring(pWString);
			offset += (lstrlenW(pWString) + 1) * sizeof(WCHAR);
		}
		
		OnJudge(ed);

	/*
		if (((PEVENTLOGRECORD)pRecord)->DataLength > 0)
		{
			wprintf(L"event data: %s\n", (LPWSTR)(pRecord + ((PEVENTLOGRECORD)pRecord)->DataOffset));
		}

		switch (EventID)
		{
			case EVENT_TYPE_LOGON_SUCCESS:
				break;
			case EVENT_TYPE_LOGON_UNSUCCESSFUL:
				break;
			default:
				break;
		}
	*/

		free(pRecord);
	}
}

void NotifyThread(PVOID parg)
{
	JudgeConext* pNC = (JudgeConext*)parg;
	// 移动到最新的日志
	SeekToLastRecord(pNC->hLog);
	//TODO 改全局退出
	while (1)
	{
		while (1)
		{
			wprintf(L"come on~\n");
			// 等待事件
			WaitForSingleObject(pNC->hEvent, -1);
			// 创建线程 进行处理
			std::thread(NotifyCallback, pNC).detach();
			ResetEvent(pNC->hEvent);
		}
	}
}

void BlockRdpBrute()
{
	HANDLE hEvent = CreateEventW(NULL, true, false, NOTIFY_LOG_COME_ON);
	HANDLE hEventLog = OpenEventLogW(NULL, SECURITY_LOG);

	if (hEvent != INVALID_HANDLE_VALUE && hEventLog != INVALID_HANDLE_VALUE )
	{
		// 绑定事件日志
		if (NotifyChangeEventLog(hEventLog, hEvent) != 0)
		{
			JudgeConext* pNC = new JudgeConext(hEvent, hEventLog);
			// 线程分离
			std::thread(NotifyThread, pNC).detach();
		}
	}
}

int main()
{
	JudgeConext::CloseNotify = CreateEventW(0, 0, 0, 0);
	BlockRdpBrute();
	
	// 阻塞住
	WaitForSingleObject(JudgeConext::CloseNotify, -1);
}
