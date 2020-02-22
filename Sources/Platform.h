/*!
    @file Platform.h

    @brief Platform specific API.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

//
// Spin lock type and state names.
//
#if defined(NTDDI_VERSION)
typedef volatile LONG64 SPIN_LOCK;
typedef enum _SPIN_LOCK_STATE
{
    SpinLockReleased,
    SpinLockAcquired,
} SPIN_LOCK_STATE;
#else
#include <Library/SynchronizationLib.h>
#endif

/*!
    @brief Initializes platform specific bits.

    @return MV_STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
MV_STATUS
InitializePlatform (
    );

/*!
    @brief Cleans up platform specific bits.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
CleanupPlatform (
    );

/*!
    @brief Stalls execution of the current processor.

    @details Use of this API from the host is not allowed.

    @param[in] Milliseconds - The time to stall in milliseconds.
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
Sleep (
    _In_ UINT64 Milliseconds
    );

/*!
    @brief Returns the active logical processor count.

    @details Use of this API from the host is not allowed.

    @return The active logical processor count.
 */
UINT32
GetActiveProcessorCount (
    );

/*!
    @brief Returns the current processor number. The BSP will return 0.

    @details Use of this API from the host is not allowed.

    @return The current processor number. 0 for BSP.
 */
UINT32
GetCurrentProcessorNumber (
    );

/*!
    @brief Returns the physical address of the given virtual address.

    @param[in] VirualAddress - A virtual address to retrieve its physical
        address for the current CR3. This must be non paged pool, otherwise the
        result is undefined.

    @return The physical address of the given virtual address.
 */
UINT64
GetPhysicalAddress (
    _In_ VOID* VirualAddress
    );

/*!
    @brief Returns the virtual address of the given physical address.

    @param[in] PhysicalAddress - The physical address to retrieve its virtual
        address for the current CR3.

    @return The virtual address of the given physical address.
 */
VOID*
GetVirtualAddress (
    _In_ UINT64 PhysicalAddress
    );

/*!
    @brief Allocates page-aligned, zero-initialized physical memory resident pages.

    @details Use of this API from the host is not allowed.

    @param[in] PageCount - The page count to allocate.

    @return The base of allocated pointer, or NULL on failure. The caller must
        free the return value with FreeSystemMemory().
 */
__drv_allocatesMem(Mem)
_IRQL_requires_max_(DISPATCH_LEVEL)
_Post_maybenull_
_Post_writable_byte_size_(PageCount * PAGE_SIZE)
_Must_inspect_result_
VOID*
AllocateSystemMemory (
    _In_ UINT64 PageCount
    );

/*!
    @brief Frees the memory allocated by AllocateSystemMemory().

    @details Use of this API from the host is not allowed.

    @param[in] Pages - The pointer to free.

    @param[in] PageCount - Unused.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
FreeSystemMemory (
    _Pre_notnull_ __drv_freesMem(Mem) VOID* Pages,
    _In_ UINT64 PageCount
    );

/*!
    @brief Reserves the virtual address. The returned address is not accessible.

    @details Use of this API from the host is not allowed.

    @param[in] PageCount - The page count to reserve.

    @return The address of reserved region on success or NULL. The caller must
        free this value with FreeReservedVirtualAddress().
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
VOID*
ReserveVirtualAddress (
    _In_ UINT64 PageCount
    );

/*!
    @brief Frees the address reserved with ReserveVirtualAddress().

    @details Use of this API from the host is not allowed.

    @param[in] Pages - The pointer returned from ReserveVirtualAddress().

    @param[in] PageCount - Unused.
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
FreeReservedVirtualAddress (
    _In_ VOID* Pages,
    _In_ UINT64 PageCount
    );

typedef
VOID
USER_PASSIVE_CALLBACK (
    _Inout_ VOID* Context
    );

/*!
    @brief Executes the callback at the PASSIVE_LEVEL on each processor one by one.

    @details Use of this API from the host is not allowed.

    @param[in] Callback - The pointer to the function to execute.

    @param[in,out] Context - The pointer to arbitrary context data.
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
RunOnAllProcessors (
    _In_ USER_PASSIVE_CALLBACK* Callback,
    _Inout_ VOID* Context
    );

/*!
    @brief Initializes the spin lock.

    @param[out] SpinLock - The pointer to spin lock to initialize.
 */
VOID
InitializeSystemSpinLock (
    _Out_ SPIN_LOCK* SpinLock
    );

/*!
    @brief Acquires the spin lock.

    @details The custom spin lock is used because NT provided spin lock API is
        not compatible with Driver Verifier when they are used from hypervisor.

    @param[in,out] SpinLock - The pointer to the spin lock to acquire.

    @return The opaque previous context.
 */
_Requires_lock_not_held_(*SpinLock)
_Acquires_lock_(*SpinLock)
_IRQL_requires_max_(HIGH_LEVEL)
_IRQL_saves_
_IRQL_raises_(DISPATCH_LEVEL)
UINT8
AcquireSystemSpinLock (
    _Inout_ SPIN_LOCK* SpinLock
    );

/*!
    @brief Release the spin lock and lowers IRQL if necessary.

    @details The custom spin lock is used because NT provided spin lock API is
        not compatible with Driver Verifier when they are used from hypervisor.

    @param[in,out] SpinLock - The spin lock to release.

    @param[in] PreviousContext - The opaque previous context returned by the
        AcquireSpinLock function.
 */
_Requires_lock_held_(*SpinLock)
_Releases_lock_(*SpinLock)
_IRQL_requires_max_(HIGH_LEVEL)
VOID
ReleaseSystemSpinLock (
    _Inout_ SPIN_LOCK* SpinLock,
    _In_ _IRQL_restores_ UINT8 PreviousContext
    );
