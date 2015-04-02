BOOL HookSystemCall();
BOOL AddProxyProcedure(CHAR *FunctionName, DWORD NumParameters, LPVOID ProxyAddress);
VOID DelProxyProcedure(CHAR *FunctionName);

#define DispatchAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
#define DispatchRealloc(mem, size) HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, mem, size);