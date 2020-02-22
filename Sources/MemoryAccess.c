/*!
    @file MemoryAccess.c

    @brief Functions for guest virtual memory access from the hypervisor.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "MemoryAccess.h"
#include "HostUtils.h"
#include "Platform.h"
#include "MemoryManager.h"

/*!
    @brief Split a 2MB EPT PDE to 512 EPT PTEs.

    @param[in,out] PdeLarge - The pointer to the 2MB EPT PDE to split.

    @return MV_STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
static
_Must_inspect_result_
MV_STATUS
Split2MbPage (
    _Inout_ PDE_2MB_64* PdeLarge
    )
{
    MV_STATUS status;
    PDE_64* pde;
    PTE_64* pt;
    UINT64 paBase;
    UINT64 paToMap;

    MV_ASSERT(PdeLarge->LargePage != FALSE);

    //
    // Allocate the PT as we are going to split one 2MB page to 512 4KB pages.
    //
    pt = MmAllocatePages(1);
    if (pt == NULL)
    {
        status = MV_STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Clear the large page bit, and propagate the current permissions to the
    // all entries in the PT.
    //
    PdeLarge->LargePage = FALSE;
    __stosq((UINT64*)pt, PdeLarge->Flags, PT_ENTRY_COUNT);

    //
    // Update the page frame of each PTE.
    //
    paBase = (PdeLarge->PageFrameNumber << PAGE_SHIFT_2BM);
    for (UINT32 ptIndex = 0; ptIndex < PT_ENTRY_COUNT; ++ptIndex)
    {
        paToMap = paBase + ((UINT64)ptIndex * PAGE_SIZE);
        pt[ptIndex].PageFrameNumber = (paToMap >> PAGE_SHIFT);
    }

    //
    // Finally, update the PDE by pointing to the PT.
    //
    pde = (PDE_64*)PdeLarge;
    pde->Reserved1 = pde->Reserved2 = 0;
    pde->PageFrameNumber = (GetPhysicalAddress(pt) >> PAGE_SHIFT);

    status = MV_STATUS_SUCCESS;

Exit:
    return status;
}

/*!
    @brief Returns the pointer to the final paging structure entry used to
        translate the given virtual address in the current CR3.

    @param[in] VirtualAddress - The virtual address to retrieve its PTE.

    @param[in] HostCr3 - The host CR3.

    @param[out] PageMapLevel - The pointer to the integer to receive the level of
        paging structures of the returned entry.

    @return The pointer to the final paging structure when the virtual address
        is not mapped in the physical address. If not, returns the pointer to the
        paging structure entry that indicated that the page is not present (ie,
        the Present bit is cleared).
 */
static
_Must_inspect_result_
PT_ENTRY_64*
GetPteForVa (
    _In_ VOID* VirtualAddress,
    _In_ CR3 HostCr3,
    _Out_opt_ UINT32* PageMapLevel
    )
{
    ADDRESS_TRANSLATION_HELPER helper;
    UINT32 level;
    PT_ENTRY_64* finalEntry;
    PML4E_64* pml4;
    PML4E_64* pml4e;
    PDPTE_64* pdpt;
    PDPTE_64* pdpte;
    PDE_64* pd;
    PDE_64* pde;
    PTE_64* pt;
    PTE_64* pte;

    helper.AsUInt64 = (UINT64)VirtualAddress;

    //
    // Locate PML4E from CR3.
    //
    pml4 = (PML4E_64*)GetVirtualAddress(HostCr3.AddressOfPageDirectory << PAGE_SHIFT);
    pml4e = &pml4[helper.AsIndex.Pml4];
    if (pml4e->Present == FALSE)
    {
        finalEntry = (PT_ENTRY_64*)pml4e;
        level = PT_LEVEL_PML4E;
        goto Exit;
    }

    //
    // Locate PDPTE from PML4E. If the located entry indicates this is the 1GB
    // page, return the entry.
    //
    pdpt = (PDPTE_64*)GetVirtualAddress(pml4e->PageFrameNumber << PAGE_SHIFT);
    pdpte = &pdpt[helper.AsIndex.Pdpt];
    if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE))
    {
        finalEntry = (PT_ENTRY_64*)pdpte;
        level = PT_LEVEL_PDPTE;
        goto Exit;
    }

    //
    // Locate PDE from PDPTE. If the located entry indicates this is the 2MB
    // page, return the entry.
    //
    pd = (PDE_64*)GetVirtualAddress(pdpte->PageFrameNumber << PAGE_SHIFT);
    pde = &pd[helper.AsIndex.Pd];
    if ((pde->Present == FALSE) || (pde->LargePage != FALSE))
    {
        finalEntry = (PT_ENTRY_64*)pde;
        level = PT_LEVEL_PDE;
        goto Exit;
    }

    //
    // Locate PTE from PDE and return it.
    //
    pt = (PTE_64*)GetVirtualAddress(pde->PageFrameNumber << PAGE_SHIFT);
    pte = &pt[helper.AsIndex.Pt];
    finalEntry = (PT_ENTRY_64*)pte;
    level = PT_LEVEL_PTE;

Exit:
    if (ARGUMENT_PRESENT(PageMapLevel))
    {
        *PageMapLevel = level;
    }
    return finalEntry;
}

MV_SECTION_PAGED
_Use_decl_annotations_
MV_STATUS
InitializeMemoryAccess (
    MEMORY_ACCESS_CONTEXT* Context,
    CR3 HostCr3
    )
{
    MV_STATUS status;
    UINT32 level;
    VOID* reservedPage;
    PT_ENTRY_64* reservedPagePte;
    PTE_64* allocatedPageTable;

    PAGED_CODE();

    allocatedPageTable = NULL;

    //
    // Reserve a single page that will map the guest's memory to access it from
    // the hypervisor. At this point, this page is not mapped to anywhere and not
    // accessible. MapPa() will do this job.
    //
    reservedPage = ReserveVirtualAddress(1);
    if (reservedPage == NULL)
    {
        status = MV_STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Get the address of the paging structures entry that has the translation
    // for the virtual address. If the resulted entry is a PDE, it means the
    // virtual address is within a large (2MB) page and cannot safely modify its
    // contents. Split the PDE into PTEs in this case. This is the case on EFI
    // because we built our own identity mapping using large pages.
    //
    reservedPagePte = GetPteForVa(reservedPage, HostCr3, &level);
    if (level == PT_LEVEL_PDE)
    {
        MV_ASSERT(reservedPagePte->LargePage != FALSE);
        status = Split2MbPage((PDE_2MB_64*)reservedPagePte);
        if (MV_ERROR(status))
        {
            goto Exit;
        }
        reservedPagePte = GetPteForVa(reservedPage, HostCr3, &level);
        allocatedPageTable = PAGE_ALIGN(reservedPagePte);
        MV_ASSERT(level == PT_LEVEL_PTE);
        MV_ASSERT(reservedPagePte->LargePage == FALSE);
    }

    //
    // Drop the translation of the virtual address. This is not required and done
    // to track map/unmap state of the reserved page. The entry may already not
    // have translation. This is the case on Windows because of underneath API.
    //
    reservedPagePte->Flags = 0;

    //
    // We are good. Fill out the context structure.
    //
    status = MV_STATUS_SUCCESS;
    Context->ReservedPage = reservedPage;
    Context->Pte = (PTE_64*)reservedPagePte;
    Context->AllocatedPageTable = allocatedPageTable;

Exit:
    if (MV_ERROR(status))
    {
        if (reservedPage != NULL)
        {
            FreeReservedVirtualAddress(reservedPage, 1);
        }
    }
    return status;
}

MV_SECTION_PAGED
_Use_decl_annotations_
VOID
CleanupMemoryAccess (
    MEMORY_ACCESS_CONTEXT* Context
    )
{
    PAGED_CODE();

    //
    // Mapping should not be active; otherwise, FreeReservedVirtualAddress()
    // will bug checks.
    //
    MV_ASSERT(Context->Pte->Present == FALSE);

    if (Context->AllocatedPageTable != NULL)
    {
        MmFreePages(Context->AllocatedPageTable);
    }

    FreeReservedVirtualAddress(Context->ReservedPage, 1);
}

/*!
    @brief Maps the given physical address to the reserved page.

    @details This function modifies the PTE of the reserved page to map the given
        physical address to the virtual address. This function maps the virtual
        address as writable regardless of the permission of the virtual address
        used by the guest.

    @param[in,out] Context - The pointer to the memory access context.

    @param[in] PhysicalAddress - The physical address to map to the reserved
        virtual address.

    @return The virtual address that maps the specified physical address. The
        caller must unmap this using UnmapPa() when mapping is no longer needed.
 */
static
_Must_inspect_result_
VOID*
MapPa (
    _Inout_ MEMORY_ACCESS_CONTEXT* Context,
    _In_ UINT64 PhysicalAddress
    )
{
    //
    // Make sure the caller called UnmapPa(). This is purely for easier state
    // tracking.
    //
    MV_ASSERT(Context->Pte->Flags == 0);

    //
    // Make the page present and writable, change the page frame, then flush TLB.
    //
    Context->Pte->Present = TRUE;
    Context->Pte->Write = TRUE;
    Context->Pte->PageFrameNumber = (PhysicalAddress >> PAGE_SHIFT);
    __invlpg(Context->ReservedPage);

    //
    // Return the pointer within the reserved page with the page offset.
    //
    return MV_ADD2PTR(Context->ReservedPage, (PhysicalAddress & PAGE_MASK));
}

/*!
    @brief Unmaps the physical address that is currently mapped to the reserved
        page.

    @param[in,out] Context - The pointer to the memory access context.
 */
static
VOID
UnmapPa (
    _Inout_ MEMORY_ACCESS_CONTEXT* Context
    )
{
    MV_ASSERT(Context->Pte->Flags != 0);

    //
    // Invalidates the reserved page.
    //
    Context->Pte->Flags = 0;
    __invlpg(Context->ReservedPage);
}

/*!
    @brief Reads or writes memory from or to the location specified as the
        physical address.

    @param[in] Context - The pointer to the memory access context.

    @param[in] OperationType - Indicates whether this is read or write operation.

    @param[in] PhysicalAddress - The physical address to read or write memory.

    @param[in,out] Buffer - The pointer to buffer to store the read memory,
        or the pointer to buffer containing data to write.

    @param[in] BytesToCopy - The size to read or write in bytes.
 */
static
VOID
ReadOrWriteOnPhysicalAddress (
    _In_ MEMORY_ACCESS_CONTEXT* Context,
    _In_ OPERATION_TYPE OperationType,
    _In_ UINT64 PhysicalAddress,
    _When_(OperationType == OperationRead, _Out_writes_bytes_(BytesToCopy))
    _When_(OperationType == OperationWrite, _In_reads_bytes_(BytesToCopy)) VOID* Buffer,
    _In_ UINT64 BytesToCopy
    )
{
    VOID* mappedVa;

    //
    // BytesToCopy should be more than one and within the range or the page.
    //
    MV_ASSERT(BytesToCopy != 0);
    MV_ASSERT(BytesToCopy <= (PAGE_SIZE - (PhysicalAddress & PAGE_MASK)));

    //
    // Map the physical address to this address space and copy to or from it.
    //
    mappedVa = MapPa(Context, PhysicalAddress);
    if (OperationType == OperationRead)
    {
        RtlCopyMemory(Buffer, mappedVa, BytesToCopy);
    }
    else
    {
        RtlCopyMemory(mappedVa, Buffer, BytesToCopy);
    }
    UnmapPa(Context);
}

_Use_decl_annotations_
UINT64
GetPhysicalAddressForGuest (
    MEMORY_ACCESS_CONTEXT* Context,
    UINT64 GuestVirtualAddress,
    PT_ENTRY_64* AggregatedPagePermissions
    )
{
    UINT64 pa;
    ADDRESS_TRANSLATION_HELPER helper;
    PT_ENTRY_64 permission;
    CR3 guestCr3;
    UINT64 tableBasePa;
    UINT64 tableEntryPa;
    PML4E_64 pml4e;
    PDPTE_64 pdpte;
    PDE_64 pde;
    PTE_64 pte;

    //
    // Return MV_INVALID_PHYSICAL_ADDRESS if the virtual address is not mapped into
    // the guest address space (ie, there is no associated physical memory).
    //
    pa = MV_INVALID_PHYSICAL_ADDRESS;
    helper.AsUInt64 = GuestVirtualAddress;
    permission.Flags = 0;
    guestCr3.Flags = VmxRead(VMCS_GUEST_CR3);

    //
    // Read the guest PML4E from the guest CR3. If the page is present, save the
    // permission bits.
    //
    tableBasePa = (guestCr3.AddressOfPageDirectory << PAGE_SHIFT);
    tableEntryPa = tableBasePa + (helper.AsIndex.Pml4 * sizeof(PML4E_64));
    ReadOrWriteOnPhysicalAddress(Context, OperationRead, tableEntryPa, &pml4e, sizeof(pml4e));
    if (pml4e.Present == FALSE)
    {
        goto Exit;
    }
    permission.Write = pml4e.Write;
    permission.Supervisor = pml4e.Supervisor;
    permission.ExecuteDisable = pml4e.ExecuteDisable;

    //
    // Read the guest PDPTE from the guest PML4E. If the page is present,
    // aggregate the permission bits.
    //
    tableBasePa = (pml4e.PageFrameNumber << PAGE_SHIFT);
    tableEntryPa = tableBasePa + (helper.AsIndex.Pdpt * sizeof(PDPTE_64));
    ReadOrWriteOnPhysicalAddress(Context, OperationRead, tableEntryPa, &pdpte, sizeof(pdpte));
    if (pdpte.Present == FALSE)
    {
        goto Exit;
    }
    permission.Write &= pdpte.Write;
    permission.Supervisor &= pdpte.Supervisor;
    permission.ExecuteDisable |= pdpte.ExecuteDisable;

    //
    // In case of the 1GB page, compute the physical address and exit.
    //
    if (pdpte.LargePage != FALSE)
    {
        PDPTE_1GB_64 pdpte1Gb;

        pdpte1Gb.Flags = pdpte.Flags;
        pa = (pdpte1Gb.PageFrameNumber << PAGE_SHIFT_1GB) | helper.AsPageOffset.Mapping1Gb;
        goto Exit;
    }

    //
    // Same. Read the guest PDE from the guest PDPTE. If the page is present,
    // aggregate the permission bits.
    //
    tableBasePa = (pdpte.PageFrameNumber << PAGE_SHIFT);
    tableEntryPa = tableBasePa + (helper.AsIndex.Pd * sizeof(PDE_64));
    ReadOrWriteOnPhysicalAddress(Context, OperationRead, tableEntryPa, &pde, sizeof(pde));
    if (pde.Present == FALSE)
    {
        goto Exit;
    }
    permission.Write &= pde.Write;
    permission.Supervisor &= pde.Supervisor;
    permission.ExecuteDisable |= pde.ExecuteDisable;

    //
    // Same. If the page is the 2MB page, exit here.
    //
    if (pde.LargePage != FALSE)
    {
        PDE_2MB_64 pde2Mb;

        pde2Mb.Flags = pde.Flags;
        pa = (pde2Mb.PageFrameNumber << PAGE_SHIFT_2BM) | helper.AsPageOffset.Mapping2Mb;
        goto Exit;
    }

    //
    // Same. Read the guest PTE from the guest PDE. If the page is present,
    // aggregate the permission bits. Finally, compute the physical address.
    //
    tableBasePa = (pde.PageFrameNumber << PAGE_SHIFT);
    tableEntryPa = tableBasePa + (helper.AsIndex.Pt * sizeof(PTE_64));
    ReadOrWriteOnPhysicalAddress(Context, OperationRead, tableEntryPa, &pte, sizeof(pte));
    if (pte.Present == FALSE)
    {
        goto Exit;
    }
    permission.Write &= pte.Write;
    permission.Supervisor &= pte.Supervisor;
    permission.ExecuteDisable |= pte.ExecuteDisable;

    pa = (pte.PageFrameNumber << PAGE_SHIFT) | helper.AsPageOffset.Mapping4Kb;

Exit:
    //
    // Return the collected permission bits on success.
    //
    if ((pa != MV_INVALID_PHYSICAL_ADDRESS) &&
        ARGUMENT_PRESENT(AggregatedPagePermissions))
    {
        *AggregatedPagePermissions = permission;
    }
    return pa;
}

/*!
    @brief Reads or writes memory from or the location specified as the guest
        virtual address.

    @param[in] Context - The pointer to the memory access context.

    @param[in] OperationType - Whether this is a read or write operation.

    @param[in] KernelMode - Whether this is kernel-mode access.

    @param[in] GuestVirtualAddress - The guest virtual address to work on.

    @param[in,out] Buffer - The pointer to buffer to store the read memory,
        or the pointer to buffer containing data to write.

    @param[in] BytesToCopy - The size to read or write in bytes.

    @param[out] ErrorInformation - The pointer to the structure to receive error
        information on failure. On success, this structure is cleared to zero.

    @return TRUE when the requested operation is completed. Otherwise, for example,
        when it encountered page permission violation in the middle, FALSE.
 */
static
_Success_(return != FALSE)
_Must_inspect_result_
BOOLEAN
ReadOrWriteGuestVirtualAddress (
    _In_ MEMORY_ACCESS_CONTEXT* Context,
    _In_ OPERATION_TYPE OperationType,
    _In_ BOOLEAN KernelMode,
    _In_ UINT64 GuestVirtualAddress,
    _When_(OperationType == OperationRead, _Out_writes_bytes_(BytesToCopy))
    _When_(OperationType == OperationWrite, _In_reads_bytes_(BytesToCopy)) VOID* Buffer,
    _In_ UINT64 BytesToCopy,
    _Out_ MEMORY_ACCESS_ERROR_INFORMATION* ErrorInformation
    )
{
    BOOLEAN successful;
    UINT64 physicalAddress;
    VOID* failedVa;
    UINT64 guestVaToOperate;
    UINT8* currentBuffer;
    UINT64 remainingBytesToCopy;

    //
    // Likely a programming error. Catch it.
    //
    MV_ASSERT(BytesToCopy != 0);

    RtlZeroMemory(ErrorInformation, sizeof(*ErrorInformation));

    successful = FALSE;

    //
    // Start iterating memory access until all request bytes are processed.
    // Each iteration is at most 4KB-length.
    //
    // Note that this is broken in that it does not guarantee atomicity of memory
    // access. Consider the case where a single memory access is performed on the
    // page boundary, and only the 2nd page is paged out. This logic will access
    // to the first page, then injects #PF to complete access to the 2nd page.
    // As this lets the guest to execute the #PF handler and there is a relatively
    // larger window that allows other core to modify the 2nd page meanwhile.
    //
    failedVa = NULL;
    currentBuffer = Buffer;
    guestVaToOperate = GuestVirtualAddress;
    remainingBytesToCopy = BytesToCopy;
    while (remainingBytesToCopy > 0)
    {
        UINT64 bytesToOperate;
        UINT64 accessibleBytes;
        PT_ENTRY_64 permissions;

        //
        // Round down the operation length to the page-boundary.
        //
        accessibleBytes = PAGE_SIZE - (guestVaToOperate & PAGE_MASK);
        bytesToOperate = MV_MIN(accessibleBytes, remainingBytesToCopy);

        //
        // Try to get the physical address.
        //
        physicalAddress = GetPhysicalAddressForGuest(Context,
                                                     guestVaToOperate,
                                                     &permissions);
        if ((physicalAddress == MV_INVALID_PHYSICAL_ADDRESS) ||
            ((permissions.Write == FALSE) && (OperationType == OperationWrite)) ||
            ((permissions.Supervisor == FALSE) && (KernelMode == FALSE)))
        {
            //
            // Either the page not present, write access to non-writable page, or
            // kernel address access from the user-mode. Inject #PF(ErrorCode).
            // See: Interrupt 14-Page-Fault Exception (#PF)
            //
            ErrorInformation->ErrorType = PageFault;
            ErrorInformation->u.PageFault.FaultAddress = guestVaToOperate;
            ErrorInformation->u.PageFault.ErrorCode.Present = (physicalAddress != MV_INVALID_PHYSICAL_ADDRESS);
            ErrorInformation->u.PageFault.ErrorCode.Write = (OperationType == OperationWrite);
            ErrorInformation->u.PageFault.ErrorCode.UserModeAccess = (KernelMode == FALSE);
            goto Exit;
        }

        //
        // Copy bytes from or to the physical address as requested.
        //
        ReadOrWriteOnPhysicalAddress(Context,
                                     OperationType,
                                     physicalAddress,
                                     currentBuffer,
                                     bytesToOperate);

        currentBuffer += bytesToOperate;
        guestVaToOperate += bytesToOperate;
        remainingBytesToCopy -= bytesToOperate;
    }

    successful = TRUE;

Exit:
    return successful;
}

_Use_decl_annotations_
BOOLEAN
ReadGuestVirtualAddress (
    MEMORY_ACCESS_CONTEXT* Context,
    BOOLEAN KernelMode,
    UINT64 GuestVirtualAddress,
    VOID* Buffer,
    UINT64 BytesToRead,
    MEMORY_ACCESS_ERROR_INFORMATION* ErrorInformation
    )
{
    return ReadOrWriteGuestVirtualAddress(Context,
                                          OperationRead,
                                          KernelMode,
                                          GuestVirtualAddress,
                                          Buffer,
                                          BytesToRead,
                                          ErrorInformation);
}

_Use_decl_annotations_
BOOLEAN
WriteGuestVirtualAddress (
    MEMORY_ACCESS_CONTEXT* Context,
    BOOLEAN KernelMode,
    UINT64 GuestVirtualAddress,
    CONST VOID* Data,
    UINT64 BytesToWrite,
    MEMORY_ACCESS_ERROR_INFORMATION* ErrorInformation
    )
{
    return ReadOrWriteGuestVirtualAddress(Context,
                                          OperationWrite,
                                          KernelMode,
                                          GuestVirtualAddress,
                                          (VOID*)Data,
                                          BytesToWrite,
                                          ErrorInformation);
}

_Use_decl_annotations_
VOID*
MapGuestPage (
    MEMORY_ACCESS_CONTEXT* Context,
    UINT64 GuestPageNumber
    )
{
    UINT64 physicalAddress;
    VOID* mappedVa;

    mappedVa = NULL;

    physicalAddress = GetPhysicalAddressForGuest(Context,
                                                 (GuestPageNumber << PAGE_SHIFT),
                                                 NULL);
    if (physicalAddress == MV_INVALID_PHYSICAL_ADDRESS)
    {
        goto Exit;
    }

    mappedVa = MapPa(Context, physicalAddress);

Exit:
    return mappedVa;
}

_Use_decl_annotations_
VOID
UnmapGuestPage (
    MEMORY_ACCESS_CONTEXT* Context,
    VOID* MappedVa
    )
{
    MV_ASSERT(MappedVa == Context->ReservedPage);
    DBG_UNREFERENCED_PARAMETER(MappedVa);

    UnmapPa(Context);
}
