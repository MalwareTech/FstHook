#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include "Hook.h"
#include "HookDispatch.h"

extern LPVOID DispatchTable;
extern DWORD DispatchTableEnd;

/*
	Hooks a function by adding it to the dispatch table
*/
BOOL AddProxyProcedure(CHAR *FunctionName, DWORD NumParameters, LPVOID ProxyAddress)
{
	LPVOID FunctionAddress;
	LPVOID *LocalDispatchTable;
	DWORD ordinal, TableSize;

	FunctionAddress = GetProcAddress(GetModuleHandleA("ntdll.dll"), FunctionName);
	if(!FunctionAddress)
	{
		printf("AddProxyFunction(%s) failed, unable to resolve function\n", FunctionName);
		return FALSE;
	}

	//Function must start with mov eax, xxxx
	if(*(BYTE *)FunctionAddress != 0xB8)
	{
		printf("AddProxyFunction(%s) failed, invalid NT function prologue\n", FunctionName);
		return FALSE;
	}

	ordinal = *(DWORD *)((DWORD)FunctionAddress+1);
	TableSize = (ordinal*8)+8;

	//Table not allocated yet, allocate a new one
	if(!DispatchTable)
	{
		LocalDispatchTable = (LPVOID *)DispatchAlloc(TableSize);
		if(!LocalDispatchTable)
		{
			printf("AddProxyFunction(%s) failed, couldn't allocate %X bytes for dispatch table\n", 
				FunctionName, TableSize);

			return FALSE;
		}

		//Update table
		DispatchTableEnd = (DWORD)LocalDispatchTable + TableSize;
		DispatchTable = LocalDispatchTable;
	}
	
	//Table is too small, resize it
	else if(((DWORD)DispatchTable + TableSize) > DispatchTableEnd)
	{
		LocalDispatchTable = (LPVOID *)DispatchTable;
		DispatchTable = NULL;

		LocalDispatchTable = (LPVOID *)DispatchRealloc(LocalDispatchTable, TableSize);
		if(!LocalDispatchTable)
		{
			printf("AddProxyFunction(%s) failed, couldn't allocate %X bytes for dispatch table\n", 
				FunctionName, TableSize);

			return FALSE;
		}

		//Update table
		DispatchTableEnd = (DWORD)LocalDispatchTable + TableSize;
		DispatchTable = LocalDispatchTable;
	}

	//Set new table entry
	LocalDispatchTable[ordinal*2] = (LPVOID *)ProxyAddress;
	LocalDispatchTable[(ordinal*2)+1] = (LPVOID *)NumParameters;
	return TRUE;
}

/*
	Unhooks a function by removing it from the dispatch table
*/
VOID DelProxyProcedure(CHAR *FunctionName)
{

	LPVOID FunctionAddress;
	CHAR *LocalDispatchTable;
	DWORD ordinal, TableSize;

	if(!DispatchTable)
		return; 

	FunctionAddress = GetProcAddress(GetModuleHandleA("ntdll.dll"), FunctionName);
	if(!FunctionAddress)
		return;

	if(*(BYTE *)FunctionAddress != 0xB8)
		return;

	ordinal = *(DWORD *)((DWORD)FunctionAddress+1);
	TableSize = (ordinal*8)+8;

	if(((DWORD)DispatchTable + TableSize) > DispatchTableEnd)
		return;

	if(!DispatchTable)
		return;

	LocalDispatchTable = (CHAR *)DispatchTable;

	//Clear table entry
	LocalDispatchTable[ordinal*2] = NULL;
	LocalDispatchTable[(ordinal*2)+1] = NULL;
	return;
}

/*
	Hooks KiFastSystemCall and KiIntSystemCall to intercept all calls from the current process 

	KiFastSystemCall only has 4 writable bytes, so we'll write a short jump to KiIntSystemCall
	where we will perform a regular jump to the dispatch procedure. although KiIntSystemCall is
	no longer used, we'll still process calls to it, just in case.
*/
BOOL HookSystemCall()
{
	LPVOID KiFastSystemCall, KiIntSystemCall, RegionStart, RegionEnd;
	HMODULE ntdll;
	DWORD OldProtection;
	BYTE KiFastHook[] = {0xEB, 0x00}; //jmp short KiIntHook+1
	BYTE KiIntHook[] = {0xFD, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90}; //std; jmp dispatch; nop; nop
	
	ntdll = GetModuleHandleA("ntdll.dll");

	KiIntSystemCall = GetProcAddress(ntdll, "KiIntSystemCall");
	KiFastSystemCall = GetProcAddress(ntdll, "KiFastSystemCall");

	if(!KiFastSystemCall || !KiIntSystemCall)
	{
		printf(
			__FUNCTION__"() failed, "
			"Unable to locate required procedure:\n"
			"KiFastSystemCall addr (%X)\n"
			"KiIntSystemCall addr (%X)\n",
			KiFastSystemCall, KiIntSystemCall
		);

		return FALSE;
	}

	RegionStart = min(KiIntSystemCall, KiFastSystemCall);
	RegionEnd = max(KiIntSystemCall, KiFastSystemCall);

	//Make sure the distance between KiFastSystemCall and KiIntSystemCall isn't
	//too big for short jump (leaving 3 bytes of space for jump + std instruction)
	if(((DWORD)RegionEnd - (DWORD)RegionStart) > (127 - 3))
	{
		printf(__FUNCTION__"() failed, short jump distance too large: %d\n",
			(DWORD)RegionEnd - (DWORD)RegionStart);

		return FALSE;
	}

	if(!VirtualProtect(RegionStart, 127, PAGE_EXECUTE_READWRITE, &OldProtection))
	{
		printf(__FUNCTION__"() failed, unable to change region protection, error code: %d\n", 
			GetLastError()
		);

		return FALSE;
	}

	//Set the jump offset for the jump from KiIntSystemCall to the dispatch procedure
	*(DWORD *)&KiIntHook[2] = (DWORD)dispatch - (DWORD)KiIntSystemCall - 6;

	//Atomically write KiIntHook to KiIntSystemCall
	_InterlockedCompareExchange64((LONGLONG *)KiIntSystemCall, 
								*(LONGLONG *)KiIntHook, 
								*(LONGLONG *)KiIntSystemCall);

	//Short jump will jump to from KiFastSystemCall to KiIntSystemCall (after std instruction)
	KiFastHook[1] = (BYTE)((DWORD)KiIntSystemCall - (DWORD)KiFastSystemCall - 1);

	//Atomically write KiFastHook to KiFastSystemCall
	_InterlockedCompareExchange16((SHORT *)KiFastSystemCall,
								*(SHORT *)KiFastHook,
								*(SHORT *)KiFastSystemCall);

//	VirtualProtect(RegionStart, 127, OldProtection, &OldProtection);
//	FlushInstructionCache(GetCurrentProcess(), RegionStart, 127);

	return TRUE;
}