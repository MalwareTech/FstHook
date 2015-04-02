/*
	This example hooks KiFastSystemCall and uses a dispatch table to call proxy procedures
	the method is fully detailed in my article here:
	http://www.malwaretech.com/2014/06/usermode-system-call-hooking-betabot.html
*/

#include <windows.h>
#include <stdio.h>
#include "Hook.h"
#include "ProxyFunctions.h"

/*
	Example Usage
*/
void main()
{

	HookSystemCall();

	//Hook NtCreateFile and NtResumeThread
	AddProxyProcedure("NtCreateFile", 11, NewNtCreateFile);
	AddProxyProcedure("NtResumeThread", 2, NewNtResumeThread);

	//The below function calls will be intercepted by our proxy functions (handlers)
	ResumeThread((HANDLE)0x1337);
	CreateFileA("C:\\Users\\Admin\\Documents\\test.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	//Unhook NtCreateFile and NtResumeThread
	DelProxyProcedure("NtCreateFile");
	DelProxyProcedure("NtResumeThread");
	getchar();
}