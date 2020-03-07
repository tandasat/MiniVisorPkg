/*!
    @file WinPlatform.c

    @brief Windows specific platform API.

    @details Some of API in this module can be called from the host. See the
        description of each API.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "WinPlatform.h"
#include "WinLogger.h"
#include "../../MiniVisor.h"

MV_SECTION_INIT DRIVER_INITIALIZE DriverEntry;

MV_SECTION_PAGED static DRIVER_UNLOAD DriverUnload;

//
// The pool tag value used across the project.
//
#define MV_POOL_TAG     ((UINT32)'vniM')

//
// Maps conversion between MV_STATUS and NTSTATUS.
//
typedef struct _STATUS_MAPPING
{
    MV_STATUS MvStatus;
    NTSTATUS NtStatus;
} STATUS_MAPPING;

static CONST STATUS_MAPPING k_StatusMapping[] =
{
    { MV_STATUS_SUCCESS,                STATUS_SUCCESS, },
    { MV_STATUS_UNSUCCESSFUL,           STATUS_UNSUCCESSFUL, },
    { MV_STATUS_ACCESS_DENIED,          STATUS_ACCESS_DENIED, },
    { MV_STATUS_INSUFFICIENT_RESOURCES, STATUS_INSUFFICIENT_RESOURCES, },
    { MV_STATUS_HV_OPERATION_FAILED,    STATUS_HV_OPERATION_FAILED, },
};

/*!
    @brief Converts MV_STATUS to NTSTATUS.

    @param[in] Status - The MV_STATUS to convert from.

    @return The converted NTSTATUS.
 */
static
NTSTATUS
ConvertMvToNtStatus (
    _In_ MV_STATUS Status
    )
{
    for (UINT32 i = 0; i < RTL_NUMBER_OF(k_StatusMapping); ++i)
    {
        if (Status == k_StatusMapping[i].MvStatus)
        {
            return k_StatusMapping[i].NtStatus;
        }
    }

    //
    // Update the mapping when this assert hits.
    //
    MV_ASSERT(FALSE);
    return STATUS_INVALID_PARAMETER;
}

/*!
    @brief Converts NTSTATUS to MV_STATUS.

    @param[in] Status - The NTSTATUS to convert from.

    @return The converted MV_STATUS.
 */
static
MV_STATUS
ConvertNtToMvStatus (
    _In_ NTSTATUS Status
    )
{
    for (UINT32 i = 0; i < RTL_NUMBER_OF(k_StatusMapping); ++i)
    {
        if (Status == k_StatusMapping[i].NtStatus)
        {
            return k_StatusMapping[i].MvStatus;
        }
    }
    return MV_STATUS_UNSUCCESSFUL;
}

/*!
    @brief The platform specific module entry point.

    @param[in] DriverObject - The driver's driver object.

    @param[in] RegistryPath - The path to the driver's registry key.

    @return STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
MV_SECTION_INIT
_Use_decl_annotations_
NTSTATUS
DriverEntry (
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
    )
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    //
    // Opts-in no-execute (NX) non-paged pool for security when available.
    //
    // By defining POOL_NX_OPTIN as 1 and calling this function, non-paged pool
    // allocation by the ExAllocatePool family with the NonPagedPool flag
    // automatically allocates NX non-paged pool on Windows 8 and later versions
    // of Windows, while on Windows 7 where NX non-paged pool is unsupported,
    // executable non-paged pool is returned as usual. The merit of this is that
    // the NonPagedPoolNx flag does not have to be used. Since the flag is
    // unsupported on Windows 7, being able to stick with the NonPagedPool flag
    // help keep code concise.
    //
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //
    // Start cross-platform initialization.
    //
    return ConvertMvToNtStatus(InitializeMiniVisor());
}

/*!
    @brief The platform specific module unload callback.

    @param[in] DriverObject - The driver's driver object.
 */
MV_SECTION_PAGED
_Use_decl_annotations_
static
VOID
DriverUnload (
    PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();

    //
    // Start cross-platform clean up.
    //
    CleanupMiniVisor();
}

MV_SECTION_INIT
_Use_decl_annotations_
MV_STATUS
InitializePlatform (
    )
{
    NTSTATUS status;
    LOGGER_CONFIGURATION loggerConfig;

    PAGED_CODE();

    //
    // Initialize in-house logger. Enable all flags.
    //
    loggerConfig.Level = LogLevelDebug;
    loggerConfig.Flags.AsUInt32 = MAXUINT32;
    loggerConfig.FlushIntervalInMs = 500;
    loggerConfig.BufferSize = (SIZE_T)(32 * PAGE_SIZE) * GetActiveProcessorCount();
    loggerConfig.FilePath = L"\\SystemRoot\\Minivisor.log";
    status = InitializeLogger(&loggerConfig);
    if (NT_ERROR(status))
    {
        LOG_EARLY_ERROR("InitializeLogger failed : %08x", status);
        goto Exit;
    }

Exit:
    return ConvertNtToMvStatus(status);
}

MV_SECTION_PAGED
_Use_decl_annotations_
VOID
CleanupPlatform (
    )
{
    PAGED_CODE();

    CleanupLogger();
}

MV_SECTION_PAGED
_Use_decl_annotations_
VOID
Sleep (
    UINT64 Milliseconds
    )
{
    LARGE_INTEGER interval;

    PAGED_CODE();

    interval.QuadPart = -(LONGLONG)(10000 * Milliseconds);
    (VOID)KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

UINT32
GetActiveProcessorCount (
    )
{
    return KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
}

UINT32
GetCurrentProcessorNumber (
    )
{
    return KeGetCurrentProcessorNumberEx(NULL);
}

_Use_decl_annotations_
UINT64
GetPhysicalAddress (
    VOID* VirualAddress
    )
{
    return (UINT64)MmGetPhysicalAddress(VirualAddress).QuadPart;
}

_Use_decl_annotations_
VOID*
GetVirtualAddress (
    UINT64 PhysicalAddress
    )
{
    PHYSICAL_ADDRESS pa;

    pa.QuadPart = (LONGLONG)PhysicalAddress;
    return MmGetVirtualForPhysical(pa);
}

_Use_decl_annotations_
VOID*
AllocateSystemMemory (
    UINT64 PageCount
    )
{
    VOID* pages;
    SIZE_T allocationBytes;

    MV_ASSERT(PageCount > 0);

    allocationBytes = (SIZE_T)PageCount * PAGE_SIZE;

    //
    // This is bogus.
    // "The current function is permitted to run at an IRQ level above the
    //  maximum permitted for 'ExAllocatePoolWithTag' (1)."
    //
#pragma warning(suppress: 28118)
    pages = ExAllocatePoolWithTag(NonPagedPool, allocationBytes, MV_POOL_TAG);
    if (pages == NULL)
    {
        goto Exit;
    }
    RtlZeroMemory(pages, allocationBytes);

Exit:
    return pages;
}

_Use_decl_annotations_
VOID
FreeSystemMemory (
    VOID* Pages,
    UINT64 PageCount
    )
{
    UNREFERENCED_PARAMETER(PageCount);

    ExFreePoolWithTag(Pages, MV_POOL_TAG);
}

MV_SECTION_PAGED
_Use_decl_annotations_
VOID*
ReserveVirtualAddress (
    UINT64 PageCount
    )
{
    PAGED_CODE();

    return MmAllocateMappingAddress(PageCount * PAGE_SIZE, MV_POOL_TAG);
}

MV_SECTION_PAGED
_Use_decl_annotations_
VOID
FreeReservedVirtualAddress (
    VOID* Pages,
    UINT64 PageCount
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(PageCount);

    MmFreeMappingAddress(Pages, MV_POOL_TAG);
}

MV_SECTION_PAGED
_Use_decl_annotations_
VOID
RunOnAllProcessors (
    USER_PASSIVE_CALLBACK* Callback,
    VOID* Context
    )
{
    UINT32 numberOfProcessors;

    PAGED_CODE();

    numberOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (UINT32 index = 0; index < numberOfProcessors; ++index)
    {
        NTSTATUS status;
        PROCESSOR_NUMBER processorNumber;
        GROUP_AFFINITY newAffinity, prevAffinity;

        status = KeGetProcessorNumberFromIndex(index, &processorNumber);
        if (NT_ERROR(status))
        {
            MV_ASSERT(FALSE);
            continue;
        }

        RtlZeroMemory(&newAffinity, sizeof(newAffinity));
        newAffinity.Group = processorNumber.Group;
        newAffinity.Mask = 1ull << processorNumber.Number;
        KeSetSystemGroupAffinityThread(&newAffinity, &prevAffinity);
        Callback(Context);
        KeRevertToUserGroupAffinityThread(&prevAffinity);
    }
}

_Use_decl_annotations_
VOID
InitializeSystemSpinLock (
    SPIN_LOCK* SpinLock
    )
{
    *SpinLock = SpinLockReleased;
}

_Use_decl_annotations_
UINT8
AcquireSystemSpinLock (
    SPIN_LOCK* SpinLock
    )
{
    KIRQL oldIrql;

    //
    // Raise IRQL if the current is lower than DISPATCH_LEVEL.
    //
    oldIrql = KeGetCurrentIrql();
    if (oldIrql < DISPATCH_LEVEL)
    {
        oldIrql = KeRaiseIrqlToDpcLevel();
    }

    for (;;)
    {
        //
        // Attempt to acquire the lock.
        //
        if (InterlockedBitTestAndSet64(SpinLock, 0) == SpinLockReleased)
        {
            //
            // Acquired the lock.
            //
            MV_ASSERT(*SpinLock == SpinLockAcquired);
            _Analysis_assume_lock_acquired_(*SpinLock);
            break;
        }

        while (*SpinLock == SpinLockAcquired)
        {
            //
            // Someone already acquired it. Spin unless the some of release it.
            //
            YieldProcessor();
        }
    }

    return oldIrql;
}

//
// "The IRQL in 'PreviousContext' was never restored."
//
#pragma warning(push)
#pragma warning(disable: __WARNING_IRQL_NOT_USED)

_Use_decl_annotations_
VOID
ReleaseSystemSpinLock (
    SPIN_LOCK* SpinLock,
    UINT8 PreviousContext
    )
{
    //
    // Prevent CPU and compiler re-ordering, and make sure any operations are
    // done before releasing the spin lock.
    //
    MemoryBarrier();
    *SpinLock = SpinLockReleased;
    _Analysis_assume_lock_released_(*SpinLock);

    //
    // Lowers IRQL if necessary.
    //
    if (PreviousContext < DISPATCH_LEVEL)
    {
        KeLowerIrql(PreviousContext);
    }
}

#pragma warning(pop)
