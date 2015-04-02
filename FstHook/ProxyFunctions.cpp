#include <windows.h>
#include <stdio.h>
#include "HookDispatch.h"
#include "ProxyFunctions.h"

/*
	The dispatcher passes the ordinal to the proxy function, so both the NewNtXx and 
	RealNtXx procedures must have ordinal as their first parameter (this is for calling
	the original KiFastSystemCall)

	NewNtXx is the function which gets called when the hooked function is called and must
	be WINAPI / NTAPI (_stdcall)

	RealNtXx is an alias for KiFastSystemCallClean which is used to call the original
	unhooked version of a function and must be __cdecl
*/

typedef NTSTATUS (__cdecl *TypeRealNtResumeThread)(DWORD ordinal, HANDLE ThreadHandle, PULONG SuspendCount);
TypeRealNtResumeThread RealNtResumeThread  = (TypeRealNtResumeThread)KiFastSystemCallClean;

typedef NTSTATUS (__cdecl *TypeRealNtCreateFile)(DWORD ordinal, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, 
												 PVOID IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, 
												 ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, 
												 ULONG EaLength);
TypeRealNtCreateFile RealNtCreateFile = (TypeRealNtCreateFile)KiFastSystemCallClean;


NTSTATUS NTAPI NewNtResumeThread(DWORD ordinal, HANDLE ThreadHandle, PULONG SuspendCount)
{
	printf("Hook caught NtResumeThread(%X)\n", ThreadHandle, SuspendCount);

	return RealNtResumeThread(ordinal, ThreadHandle, SuspendCount);
}

NTSTATUS NTAPI NewNtCreateFile(DWORD ordinal, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, 
								PVOID IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, 
								ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	printf("Hook caught NtCreateFile(%ws)\n", ObjectAttributes->ObjectName->Buffer);

	return RealNtCreateFile(ordinal, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, 
							ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}