/*!
    @file MemoryAccess.h

    @brief Functions for guest virtual memory access from the hypervisor.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"
#include "Ia32.h"

typedef struct _MEMORY_ACCESS_CONTEXT
{
    //
    // Reserved virtual address (page) for access to the guest virtual memory
    // from the hypervisor.
    //
    VOID* ReservedPage;

    //
    // The pointer to the PTE of the reserved page.
    //
    PTE_64* Pte;

    //
    // The address of the page table that is dynamically allocated to translate
    // ReservedPage with the 4KB page (and not the large page).
    //
    PTE_64* AllocatedPageTable;
} MEMORY_ACCESS_CONTEXT;

//
// Error information can be filled by (Read|Write)GuestVirtualAddress().
//
typedef struct _MEMORY_ACCESS_ERROR_INFORMATION
{
    EXCEPTION_VECTOR ErrorType;
    union
    {
        struct
        {
            PAGE_FAULT_EXCEPTION ErrorCode;
            UINT64 FaultAddress;
        } PageFault;
    } u;
} MEMORY_ACCESS_ERROR_INFORMATION;

/*!
    @brief Initializes the memory access context.

    @param[out] Context - The pointer to the context to initialize. On success,
        the caller must clean up this context with CleanupMemoryAccess().

    @param[in] HostCr3 - The host CR3.

    @return MV_STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
MV_STATUS
InitializeMemoryAccess (
    _Out_ MEMORY_ACCESS_CONTEXT* Context,
    _In_ CR3 HostCr3
    );

/*!
    @brief Cleans up the memory access context initialized with
        InitializeMemoryAccess().

    @param[in,out] Context - The pointer to the context to clean up.
 */
_IRQL_requires_max_(APC_LEVEL)
VOID
CleanupMemoryAccess (
    _Inout_ MEMORY_ACCESS_CONTEXT* Context
    );

/*!
    @brief Retrieves the physical address associated with the guest virtual
        address.

    @details This function walks through the guest paging structures and for the
        given virtual address and retrieves the guest physical address of it.
        This is equivalent to changing the current CR3 with the guest CR3 and
        calling GetPhysicalAddress(). This function, however, exists to avoid
        problems associated with CR3 update, for example, on Windows, updating
        the CR3 crashes the system immediately if the KVA Shadow is enabled and
        the guest CR3 contains the USER CR3, as it does not map our code.

    @param[in] Context - The pointer to the memory access context.

    @param[in] GuestVirtualAddress - The guest virtual address to look for its
        physical address.

    @param[out] AggregatedPagePermissions - The pointer to the paging-structure
        entry to receive aggregated copy of the page permissions specified in
        the guest paging structure entries used to translate the guest virtual
        address. If the guest physical address is mapped to the physical address,
        Write, Supervisor, and ExecuteDisable bits are updated accordingly, and
        the rest of bits are cleared.

    @return The physical address associated with the specified virtual address if
        exists. Otherwise, MV_INVALID_PHYSICAL_ADDRESS.
 */
_Must_inspect_result_
_Success_(return != MV_INVALID_PHYSICAL_ADDRESS)
UINT64
GetPhysicalAddressForGuest (
    _In_ MEMORY_ACCESS_CONTEXT* Context,
    _In_ UINT64 GuestVirtualAddress,
    _Out_opt_ PT_ENTRY_64* AggregatedPagePermissions
    );

/*!
    @brief Reads memory from the location specified as the guest virtual address.

    @param[in] Context - See ReadOrWriteGuestVirtualAddress().

    @param[in] KernelMode - See ReadOrWriteGuestVirtualAddress().

    @param[in] GuestVirtualAddress - See ReadOrWriteGuestVirtualAddress().

    @param[out] Buffer - See ReadOrWriteGuestVirtualAddress().

    @param[in] BytesToRead - See ReadOrWriteGuestVirtualAddress().

    @param[out] ErrorInformation - See ReadOrWriteGuestVirtualAddress().

    @return See ReadOrWriteGuestVirtualAddress().
 */
_Must_inspect_result_
BOOLEAN
ReadGuestVirtualAddress (
    _In_ MEMORY_ACCESS_CONTEXT* Context,
    _In_ BOOLEAN KernelMode,
    _In_ UINT64 GuestVirtualAddress,
    _Out_writes_bytes_(BytesToRead) VOID* Buffer,
    _In_ UINT64 BytesToRead,
    _Out_ MEMORY_ACCESS_ERROR_INFORMATION* ErrorInformation
    );

/*!
    @brief Write memory to the location specified as the guest virtual address.

    @param[in] Context - See ReadOrWriteGuestVirtualAddress().

    @param[in] KernelMode - See ReadOrWriteGuestVirtualAddress().

    @param[in] GuestVirtualAddress - See ReadOrWriteGuestVirtualAddress().

    @param[out] Data - See ReadOrWriteGuestVirtualAddress().

    @param[in] BytesToWrite - See ReadOrWriteGuestVirtualAddress().

    @param[out] ErrorInformation - See ReadOrWriteGuestVirtualAddress().

    @return See ReadOrWriteGuestVirtualAddress().
 */
_Must_inspect_result_
BOOLEAN
WriteGuestVirtualAddress (
    _In_ MEMORY_ACCESS_CONTEXT* Context,
    _In_ BOOLEAN KernelMode,
    _In_ UINT64 GuestVirtualAddress,
    _In_reads_bytes_(BytesToWrite) CONST VOID* Data,
    _In_ UINT64 BytesToWrite,
    _Out_ MEMORY_ACCESS_ERROR_INFORMATION* ErrorInformation
    );

/*!
    @brief Maps the specified guest page number to the current address space.

    @param[in] Context - The pointer to the memory access context.

    @param[in] GuestPageNumber - The guest page number (ie, the guest virtual
        address without lower 12bits) to map to the host address space.

    @return The virtual address mapping the same physical page as specified as
        the page number, or NULL if the specified page number does not have
        a corresponding physical page. The caller must unmap the return value
        with UnmapGuestPage() when it is no longer needed.
 */
_Must_inspect_result_
VOID*
MapGuestPage (
    _Inout_ MEMORY_ACCESS_CONTEXT* Context,
    _In_ UINT64 GuestPageNumber
    );

/*!
    @brief Unmaps the address mapped with MapGuestPage().

    @param[in] Context - The pointer to the memory access context.

    @param[in] MappedVa - The pointer returned by MapGuestPage().
 */
VOID
UnmapGuestPage (
    _Inout_ MEMORY_ACCESS_CONTEXT* Context,
    _In_ VOID* MappedVa
    );
