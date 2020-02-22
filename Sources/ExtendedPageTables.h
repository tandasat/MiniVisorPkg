/*!
    @file ExtendedPageTables.h

    @brief Functions for EPT handling.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 -, Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

/*!
    @brief Checks whether the EPT entry is present.

    @param[in] EptEntry - The pointer to the EPT entry to check.

    @return TRUE when the entry is present.
 */
#define MV_IS_EPT_ENTRY_PRESENT(EptEntry) \
    (((EptEntry)->ReadAccess != FALSE) || \
     ((EptEntry)->WriteAccess != FALSE) || \
     ((EptEntry)->ExecuteAccess != FALSE))

/*!
    @brief Copies the permission of the EPT entry to the other entry.

    @param[out] Destination - The pointer to the EPT entry to updates its permission.

    @param[in] EptEntry - The pointer to the EPT entry to copy its permission from.
 */
#define MV_COPY_EPT_ENTRY_PERMISSIONS(Destination, EptEntry) \
    (Destination)->ReadAccess = (EptEntry)->ReadAccess; \
    (Destination)->WriteAccess = (EptEntry)->WriteAccess; \
    (Destination)->ExecuteAccess = (EptEntry)->ExecuteAccess

/*!
    @brief Aggregates the permission of the EPT entry to the other entry.

    @param[out] Destination - The pointer to the EPT entry to updates its permission.

    @param[in] EptEntry - The pointer to the EPT entry to aggregate its permission from.
 */
#define MV_AGGREGATE_EPT_ENTRY_PERMISSIONS(Destination, EptEntry) \
    (Destination)->ReadAccess &= (EptEntry)->ReadAccess; \
    (Destination)->WriteAccess &= (EptEntry)->WriteAccess; \
    (Destination)->ExecuteAccess &= (EptEntry)->ExecuteAccess

//
// Holds the context specific to EPT.
//
typedef struct _EPT_CONTEXT
{
    //
    // EPTP written to VMCS.
    //
    EPT_POINTER EptPointer;

    //
    // The virtual address of the EPT PML4.
    //
    EPT_PML4* EptPml4;
} EPT_CONTEXT;

/*!
    @brief Initializes EPT with pass-through style configurations.

    @param[in,out] EptContext - A pointer to the EPT context to initialize.

    @return MV_STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_Must_inspect_result_
MV_STATUS
InitializeExtendedPageTables (
    _Inout_ EPT_CONTEXT* EptContext
    );

/*!
    @brief Cleans up EPT context.

    @param[in,out] EptContext - A pointer to the EPT context to clean up.
 */
VOID
CleanupExtendedPageTables (
    _Inout_ EPT_CONTEXT* EptContext
    );

/*!
    @brief Updates the EPT PTE for the given GPA with new HPA and permissions.

    @param[in] EptPml4 - The pointer to the EPT PML4.

    @param[in] GuestPhysicalAddress - The GPA to update its EPT PTE.

    @param[in] HostPhysicalAddress - The pointer to the HPA to update to. If NULL
        is specified, the function does not change the translation.

    @param[in] Permissions - The pointer to the new permission to update to. If
        NULL is specified, the functions does not change the permissions.

    @return MV_STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_Must_inspect_result_
MV_STATUS
UpdateExtendPageTables (
    _In_ EPT_PML4* EptPml4,
    _In_ UINT64 GuestPhysicalAddress,
    _In_opt_ CONST UINT64* HostPhysicalAddress,
    _In_opt_ CONST EPT_ENTRY* Permissions
    );

/*!
    @brief Invalidate guest-physical and combined caches.

    @param[in] EptPointer - The EPT pointer to invalidate associated caches. If
        0 is specified, caches associated with any EPT pointers are invalidated.
 */
VOID
InvalidateEptDerivedCache (
    _In_ UINT64 EptPointer
    );

/*!
    @brief Invalidate liner and combined caches.

    @param[in] VirtualProcessorId - The VPID to invalidate associated caches. If
        0 is specified, caches associated with any VPID are invalidated.
 */
VOID
InvalidateVpidDerivedCache (
    _In_ UINT16 VirtualProcessorId
    );
