#pragma once
#pragma once

#include <Windows.h>
#include <winternl.h>

#ifndef FILE_H
#define FILE_H

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

typedef NTSTATUS(WINAPI* PNtQueryInformationToken)(
    __in HANDLE                  TokenHandle,
    __in TOKEN_INFORMATION_CLASS TokenInformationClass,
    __out PVOID                  TokenInformation,
    __in ULONG                   TokenInformationLength,
    __out_opt PULONG             ReturnLength
    );

typedef NTSTATUS(__stdcall* PNtCreateFile)(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength
    );

typedef NTSTATUS(NTAPI* PNtFsControlFile)(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            FsControlCode,
    PVOID            InputBuffer,
    ULONG            InputBufferLength,
    PVOID            OutputBuffer,
    ULONG            OutputBufferLength
    );

typedef struct _SYSTEM_HANDLE
{
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR HandleCount;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

extern PNtQuerySystemInformation ntQuerySystemInformation;
extern PNtFsControlFile ntFsControlFile;
extern PNtCreateFile ntCreateFile;

DWORD32 initNTFunction();
DWORD64 getObjAddr(HANDLE objHdl, DWORD targetPID);
void hexdump(BYTE* mem, unsigned int len);
void catchErr(int code);
DWORD NTAPI RtlComputeCrc32(DWORD dwInitial, const BYTE* pData, INT iLen);
void spawnShellUsingShellcode(size_t processID);

#endif