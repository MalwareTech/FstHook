void dispatch();
void KiFastSystemCallClean(DWORD ordinal);

#define sysenter __asm _emit 0x0F __asm _emit 0x34