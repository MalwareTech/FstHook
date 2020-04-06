#include <Windows.h>
#include <stdio.h>
#include "HookDispatch.h"

LPVOID *DispatchTable = NULL;
DWORD DispatchTableEnd = 0;

/*
	Due to the weird calling convention of KiFastSystemCall, we need to format the
	stack to _stdcall, before calling the proxy function
*/
void __declspec(naked) PrepareStack(DWORD Ordinal, DWORD ProxyFunction, DWORD NumArguments)
{
	_asm
	{
		push ebp
		mov ebp, esp

		//Get address of last argument (First argument is ebp+0x18)
		mov ecx, [NumArguments]
		lea edx, [ecx*4+0x18]

		//Push all the arguments to the stack in reverse order
PushArg:
		push [ebp+edx]
		sub edx, 4
		sub ecx, 1

		test ecx, ecx
		jnz PushArg

		//First parameter, used to call clean KiFastSystemCall
		push [Ordinal]

		call [ProxyFunction]

		pop ebp
		retn 0x0C
	}
}

/*
	Dispatch calls from hooked KiIntSystemCall and KiFastSystemCall
	KiIntSystemCalls are simply passed to original handler
	KiFastSystemCalls are dispatched to the appropriate proxy procedure
*/
void __declspec(naked) dispatch()
{
	_asm
	{
		//Check value of direction flag
		pushfd
		cld
		pop edx
		and edx, 0x400
		shr edx, 0x0A

		//If direction flag is 1, call came from KiIntSystemCall
		test edx, edx
		jnz KiIntSystemCall

		//Either no functions are hooked yet or we're resizing DispatchTable
		cmp [DispatchTable], 0
		je KiFastSystemCall

		//calculate offset to pointer in dispatch table
		mov edx, [DispatchTable]
		lea edx, [eax*8+edx]

		//Make sure address is inside the dispatch table
		cmp edx, dword PTR [DispatchTableEnd]
		jge kiFastSystemCall

		//If pointer is 0, the function is not hooked
		cmp dword ptr [edx], 0
		je kiFastSystemCall

		//Push proxy function address, number of arguments and ordinal to stack
		push [edx+4]
		push [edx]
		push eax
		call PrepareStack
		
		retn

kiFastSystemCall:
		mov edx, esp
		sysenter
		retn

KiIntSystemCall:
		lea edx, [esp+8]
		int 0x2E
		retn
	}
}

/*
	Used for functions to call original KiFastSystemCall
	To perform a system call we simply put the function ordinal into eax and
	the stack pointer into edx
*/
void __declspec(naked) KiFastSystemCallClean(DWORD ordinal)
{
	_asm
	{
		//Load ordinal into eax and remove it from the stack
		pop edx
		pop eax
		push edx

		//Execute clean KiFastSystemCall
		call KiFastSystemCall

		//Make up for the ordinal we removed
		push [esp]

		retn

KiFastSystemCall:
		mov edx, esp
		sysenter
		retn
	}
}