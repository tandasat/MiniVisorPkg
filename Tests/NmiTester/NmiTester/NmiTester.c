#include <intrin.h>
#include <ntifs.h>

_Function_class_(NMI_CALLBACK)
_IRQL_requires_same_
static
BOOLEAN
HandleNmi (
    _In_opt_ PVOID Context,
    _In_ BOOLEAN Handled
    )
{
    volatile long* nmiCount;

    UNREFERENCED_PARAMETER(Handled);

    nmiCount = (long*)Context;
    InterlockedIncrement(nmiCount);

    return TRUE;
}

VOID
static
Sleep (
    UINT64 Milliseconds
    )
{
    LARGE_INTEGER interval;

    PAGED_CODE();

    interval.QuadPart = -(LONGLONG)(10000 * Milliseconds);
    (VOID)KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

typedef struct _KAFFINITY_EX
{
    USHORT Count;
    USHORT Size;
    ULONG Reserved;
    KAFFINITY Bitmap[20];
} KAFFINITY_EX, *PKAFFINITY_EX;

typedef
VOID
(NTAPI*HALSENDNMI_TYPE) (
    CONST KAFFINITY_EX* AffinityEx
    );

EXTERN_C
VOID
NTAPI
KeInitializeAffinityEx (
    KAFFINITY_EX *Affinity
    );

EXTERN_C
VOID
NTAPI
KeAddProcessorAffinityEx (
    KAFFINITY_EX *Affinity,
    ULONG ProcessorBitmask
    );

EXTERN_C
NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    static UNICODE_STRING halSendNmiName = RTL_CONSTANT_STRING(L"HalSendNMI");
    NTSTATUS status;
    volatile ULONG nmiCount;
    PVOID registration;
    HALSENDNMI_TYPE halSendNMI;
    ULONG processorBitMask;
    KAFFINITY_EX affinity;
    ULONG processorCount;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    registration = NULL;

    //
    // It makes no sense to run this test on the UP system.
    //
    processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (processorCount == 1)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // Register our NMI callback.
    //
    halSendNMI = (HALSENDNMI_TYPE)MmGetSystemRoutineAddress(&halSendNmiName);
    if (halSendNMI == NULL)
    {
        status = STATUS_PROCEDURE_NOT_FOUND;
        goto Exit;
    }

    nmiCount = 0;
    registration = KeRegisterNmiCallback(HandleNmi, (PVOID)&nmiCount);
    if (registration == NULL)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // Send NMI to all active processors. Wait is required to minimize the
    // chance to refer to the counter variable before the callback is processed
    // on the other processors.
    //
    KeInitializeAffinityEx(&affinity);
    processorBitMask = 0;
    for (ULONG i = 0; i < processorCount; ++i)
    {
        KeAddProcessorAffinityEx(&affinity, i);
    }

    halSendNMI(&affinity);
    Sleep(1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_ERROR_LEVEL,
               "NmiCount = %lu\n",
               nmiCount);

    //
    // Make sure the NMI occurred on the all processors. If not, probably need
    // more sleep.
    //
    if (nmiCount != processorCount)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // Send NMI many times and see if it gets droppped.
    //
    nmiCount = 0;
    for (ULONG issuedNmiCount = 0; issuedNmiCount < 10000; ++issuedNmiCount)
    {
        if (nmiCount != issuedNmiCount * processorCount)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "NMI dropped: %lu actual vs %lu expected\n",
                       nmiCount,
                       issuedNmiCount * processorCount);
            status = STATUS_UNSUCCESSFUL;
            goto Exit;
        }

        halSendNMI(&affinity);
        Sleep(1);

        if ((issuedNmiCount % 100) == 0)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "Processed %lu times\n",
                       issuedNmiCount);
        }
    }

    //
    // Good!
    //
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_ERROR_LEVEL,
               "NMI successfully processed %lu times\n",
               nmiCount);

    status = STATUS_CANCELLED;

Exit:
    if (registration != NULL)
    {
        NT_VERIFY(NT_SUCCESS(KeDeregisterNmiCallback(registration)));
    }
    return status;
}
