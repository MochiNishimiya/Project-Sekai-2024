#ifndef _WIN_DEFS_H_
#define _WIN_DEFS_H_

#define EPROC_TOKEN_OFFSET 0x4b8

typedef struct _DISPATCHER_HEADER
{
    union
    {
        volatile long Lock;
        long LockNV;
        struct
        {
            unsigned char Type;
            unsigned char Signalling;
            unsigned char Size;
            unsigned char Reserved1;
        };
        struct
        {
            unsigned char TimerType;
            union
            {
                unsigned char TimerControlFlags;
                struct
                {
                    struct
                    {
                        unsigned char Absolute : 1;
                        unsigned char Wake : 1;
                        unsigned char EncodedTolerableDelay : 6;
                    };
                    unsigned char Hand;
                    union
                    {
                        unsigned char TimerMiscFlags;
                        struct
                        {
                            unsigned char Index : 6;
                            unsigned char Inserted : 1;
                            volatile unsigned char Expired : 1;
                        };
                    };
                };
            };
        };
        struct
        {
            unsigned char Timer2Type;
            union
            {
                unsigned char Timer2Flags;
                struct
                {
                    struct
                    {
                        unsigned char Timer2Inserted : 1;
                        unsigned char Timer2Expiring : 1;
                        unsigned char Timer2CancelPending : 1;
                        unsigned char Timer2SetPending : 1;
                        unsigned char Timer2Running : 1;
                        unsigned char Timer2Disabled : 1;
                        unsigned char Timer2ReservedFlags : 2;
                    };
                    unsigned char Timer2ComponentId;
                    unsigned char Timer2RelativeId;
                };
            };
        };
        struct
        {
            unsigned char QueueType;
            union
            {
                unsigned char QueueControlFlags;
                struct
                {
                    struct
                    {
                        unsigned char Abandoned : 1;
                        unsigned char DisableIncrement : 1;
                        unsigned char QueueReservedControlFlags : 6;
                    };
                    unsigned char QueueSize;
                    unsigned char QueueReserved;
                };
            };
        };
        struct
        {
            unsigned char ThreadType;
            unsigned char ThreadReserved;
            union
            {
                unsigned char ThreadControlFlags;
                struct
                {
                    struct
                    {
                        unsigned char CycleProfiling : 1;
                        unsigned char CounterProfiling : 1;
                        unsigned char GroupScheduling : 1;
                        unsigned char AffinitySet : 1;
                        unsigned char Tagged : 1;
                        unsigned char EnergyProfiling : 1;
                        unsigned char SchedulerAssist : 1;
                        unsigned char ThreadReservedControlFlags : 1;
                    };
                    union
                    {
                        unsigned char DebugActive;
                        struct
                        {
                            unsigned char ActiveDR7 : 1;
                            unsigned char Instrumented : 1;
                            unsigned char Minimal : 1;
                            unsigned char Reserved4 : 2;
                            unsigned char AltSyscall : 1;
                            unsigned char Emulation : 1;
                            unsigned char Reserved5 : 1;
                        };
                    };
                };
            };
        };
        struct
        {
            unsigned char MutantType;
            unsigned char MutantSize;
            unsigned char DpcActive;
            unsigned char MutantReserved;
        };
    };
    long SignalState;
    LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, * PDISPATCHER_HEADER;

typedef struct _KEVENT
{
    struct _DISPATCHER_HEADER Header;
} KEVENT, * PKEVENT;

#endif