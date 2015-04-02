typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

NTSTATUS NTAPI NewNtResumeThread(DWORD ordinal, HANDLE ThreadHandle, PULONG SuspendCount);
NTSTATUS NTAPI NewNtCreateFile(DWORD ordinal, PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, 
							   PVOID IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, 
							   ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

