#pragma once
#include <windows.h>

class Mutex
{
private:
	Mutex()
	{
	}

public:
	~Mutex() {

	}
public:
	static void lock()
	{
		init();
		EnterCriticalSection(&Mutex::m_cs);
	}
	static void unlock()
	{
		LeaveCriticalSection(&Mutex::m_cs);
	}

	static void init()
	{
		if (is_init == 0)
		{
			is_init = 0x1;
			InitializeCriticalSection(&Mutex::m_cs);
		}
	}
private:
	static CRITICAL_SECTION m_cs;
	static bool is_init;
};


class autoLock {
public:
	//构造的时候调用lock。
	inline autoLock() { Mutex::lock(); }
	//析构的时候调用unlock。
	inline ~autoLock() { Mutex::unlock(); }
};
