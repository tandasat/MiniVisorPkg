/*!
    @file EfiPlatform.c

    @details Some of API in this module can be called from the host. See the
        description of each API.

    @brief EFI specific platform API.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "EfiPlatform.h"
#include <Guid/EventGroup.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Pi/PiDxeCis.h>
#include <Protocol/MpService.h>
#include <Protocol/LoadedImage.h>
#include "EfiLogger.h"
#include "../../MiniVisor.h"

//
// Maps conversion between MV_STATUS and NTSTATUS.
//
typedef struct _STATUS_MAPPING
{
    MV_STATUS MvStatus;
    EFI_STATUS EfiStatus;
} STATUS_MAPPING;

static CONST STATUS_MAPPING k_StatusMapping[] =
{
    { MV_STATUS_SUCCESS,                EFI_SUCCESS, },
    { MV_STATUS_UNSUCCESSFUL,           EFI_ABORTED, },
    { MV_STATUS_ACCESS_DENIED,          EFI_ACCESS_DENIED, },
    { MV_STATUS_INSUFFICIENT_RESOURCES, EFI_OUT_OF_RESOURCES, },
    { MV_STATUS_HV_OPERATION_FAILED,    EFI_UNSUPPORTED, },
};

//
// The multi-processor protocol. Only available during the boot-time.
//
static EFI_MP_SERVICES_PROTOCOL* g_MpServices;

/*!
    @brief Converts MV_STATUS to EFI_STATUS.

    @param[in] Status - The MV_STATUS to convert from.

    @return The converted EFI_STATUS.
 */
static
EFI_STATUS
ConvertMvToEfiStatus (
    MV_STATUS Status
    )
{
    for (UINT32 i = 0; i < RTL_NUMBER_OF(k_StatusMapping); ++i)
    {
        if (Status == k_StatusMapping[i].MvStatus)
        {
            return k_StatusMapping[i].EfiStatus;
        }
    }

    //
    // Update the mapping when this assert hits.
    //
    MV_ASSERT(FALSE);
    return EFI_ABORTED;
}

/*!
    @brief Converts EFI_STATUS to MV_STATUS.

    @param[in] Status - The EFI_STATUS to convert from.

    @return The converted MV_STATUS.
 */
static
MV_STATUS
ConvertEfiToMvStatus (
    EFI_STATUS Status
    )
{
    for (UINT32 i = 0; i < RTL_NUMBER_OF(k_StatusMapping); ++i)
    {
        if (Status == k_StatusMapping[i].EfiStatus)
        {
            return k_StatusMapping[i].MvStatus;
        }
    }
    return MV_STATUS_UNSUCCESSFUL;
}

/*!
    @brief Displays information about the current module.

    @details Use of this API at the run-time is not allowed.

    @return EFI_SUCCESS on success; otherwise, an appropriate error code.
 */
static
EFI_STATUS
PrintLoadedImageInformation (
    )
{
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL* loadedImageInfo;
    CHAR16* devicePath;

    devicePath = NULL;

    status = gBS->OpenProtocol(gImageHandle,
                               &gEfiLoadedImageProtocolGuid,
                               (VOID**)&loadedImageInfo,
                               gImageHandle,
                               NULL,
                               EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(status))
    {
        LOG_ERROR("OpenProtocol failed : %r", status);
        goto Exit;
    }

    devicePath = ConvertDevicePathToText(loadedImageInfo->FilePath, TRUE, TRUE);
    if (devicePath == NULL)
    {
        LOG_ERROR("ConvertDevicePathToText failed");
        status = EFI_OUT_OF_RESOURCES;
        goto Exit;
    }

    LOG_INFO("%s - %llx:%llx",
             devicePath,
             loadedImageInfo->ImageBase,
             MV_ADD2PTR(loadedImageInfo->ImageBase, loadedImageInfo->ImageSize));

Exit:
    if (devicePath != NULL)
    {
        FreePool(devicePath);
    }
    return status;
}

/*!
    @brief The platform specific module entry point.

    @param[in] ImageHandle - The handle of this module.

    @param[in] SystemTable - The boot service table pointer.

    @return EFI_SUCCESS on success; otherwise, an appropriate error code.
 */
EFI_STATUS
EFIAPI
DriverEntry (
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE* SystemTable
    )
{
    ASSERT(ImageHandle == gImageHandle);
    ASSERT(SystemTable->BootServices == gBS);

    return ConvertMvToEfiStatus(InitializeMiniVisor());
}

/*!
    @brief The platform specific module unload callback.

    @param[in] ImageHandle - The handle of this module.

    @return Always EFI_SUCCESS.
 */
EFI_STATUS
EFIAPI
DriverUnload (
    EFI_HANDLE ImageHandle
    )
{
    CleanupMiniVisor();
    return EFI_SUCCESS;
}

MV_STATUS
InitializePlatform (
    )
{
    EFI_STATUS status;
    BOOLEAN isLoggerInitialized;

    status = InitializeLogger();
    if (EFI_ERROR(status))
    {
        LOG_EARLY_ERROR("InitializeLogger failed : %r", status);
        goto Exit;
    }
    isLoggerInitialized = TRUE;

    PrintLoadedImageInformation();

    //
    // Locate the protocol for multi-processor handling. UEFI on a Hyper-V VM
    // does not implement this and fails.
    //
    status = gBS->LocateProtocol(&gEfiMpServiceProtocolGuid,
                                 NULL,
                                 &g_MpServices);
    if (EFI_ERROR(status))
    {
        LOG_ERROR("LocateProtocol failed : %r", status);
        goto Exit;
    }

Exit:
    if (EFI_ERROR(status))
    {
        if (isLoggerInitialized != FALSE)
        {
            CleanupLogger();
        }
    }
    return ConvertEfiToMvStatus(status);
}

VOID
CleanupPlatform (
    )
{
    CleanupLogger();
}

UINT32
GetActiveProcessorCount (
    )
{
    EFI_STATUS status;
    UINTN numberOfProcessors;
    UINTN numberOfEnabledProcessors;

    status = g_MpServices->GetNumberOfProcessors(g_MpServices,
                                                 &numberOfProcessors,
                                                 &numberOfEnabledProcessors);
    if (EFI_ERROR(status))
    {
        LOG_ERROR("GetNumberOfProcessors failed : %r", status);
        MV_PANIC();
    }

    return (UINT32)numberOfEnabledProcessors;
}

UINT32
GetCurrentProcessorNumber (
    )
{
    EFI_STATUS status;
    UINTN processorNumber;

    status = g_MpServices->WhoAmI(g_MpServices, &processorNumber);
    if (EFI_ERROR(status))
    {
        LOG_ERROR("WhoAmI failed : %r", status);
        MV_PANIC();
    }

    return (UINT32)processorNumber;
}

UINT64
GetPhysicalAddress (
    VOID* VirualAddress
    )
{
    //
    // Assume the current CR3 uses the identity mapping. This is the case during
    // the boot time or execution of the host.
    //
    return (UINT64)VirualAddress;
}

VOID*
GetVirtualAddress (
    UINT64 PhysicalAddress
    )
{
    //
    // This function assume the current CR3 uses the identity mapping. This is
    // the case during the boot time or execution of the host.
    //
    return (VOID*)PhysicalAddress;
}

VOID*
AllocateSystemMemory (
    UINT64 PageCount
    )
{
    VOID* pages;

    pages = AllocateRuntimePages(PageCount);
    if (pages == NULL)
    {
        goto Exit;
    }
    ZeroMem(pages, PageCount * EFI_PAGE_SIZE);

Exit:
    return pages;
}

VOID
FreeSystemMemory (
    VOID* Pages,
    UINT64 PageCount
    )
{
    FreePages(Pages, PageCount);
}

VOID*
ReserveVirtualAddress (
    UINT64 PageCount
    )
{
    return AllocateSystemMemory(PageCount);
}

VOID
FreeReservedVirtualAddress (
    VOID* BaseAddress,
    UINT64 PageCount
    )
{
    FreeSystemMemory(BaseAddress, PageCount);
}

VOID
RunOnAllProcessors (
    USER_PASSIVE_CALLBACK* Callback,
    VOID* Context
    )
{
    EFI_STATUS status;

    Callback(Context);
    if (GetActiveProcessorCount() == 1)
    {
        goto Exit;
    }

    status = g_MpServices->StartupAllAPs(g_MpServices,
                                         Callback,
                                         TRUE,
                                         NULL,
                                         0,
                                         Context,
                                         NULL);
    if (EFI_ERROR(status))
    {
        LOG_ERROR("StartupAllAPs failed : %r", status);
        MV_PANIC();
    }

Exit:
    return;
}

VOID
InitializeSystemSpinLock (
    SPIN_LOCK* SpinLock
    )
{
    (VOID)InitializeSpinLock(SpinLock);
}

UINT8
AcquireSystemSpinLock (
    SPIN_LOCK* SpinLock
    )
{
    //
    // This function does not raise TPL as it is not available at the run time.
    //
    (VOID)AcquireSpinLock(SpinLock);
    return 0;
}

VOID
ReleaseSystemSpinLock (
    SPIN_LOCK* SpinLock,
    UINT8 PreviousContext
    )
{
    ASSERT(PreviousContext == 0);
    (VOID)ReleaseSpinLock(SpinLock);
}
