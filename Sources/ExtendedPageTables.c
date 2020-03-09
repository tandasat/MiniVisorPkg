/*!
    @file ExtendedPageTables.c

    @brief Functions for EPT handling.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "ExtendedPageTables.h"
#include "Asm.h"
#include "Ia32.h"
#include "MemoryManager.h"
#include "Platform.h"
#include "Logger.h"
#include "MemoryType.h"
#include "Ia32Utils.h"

//
// The set of EPT paging structure entries involved with to translate the GPA.
//
typedef struct _EPT_ENTRIES
{
    EPT_PML4* Pml4e;
    union
    {
        EPDPTE_1GB* AsLargePage;
        EPDPTE* AsRegularPage;
    } Pdpte;
    union
    {
        EPDE_2MB* AsLargePage;
        EPDE* AsRegularPage;
    } Pde;
    EPTE* Pte;
} EPT_ENTRIES;
C_ASSERT(sizeof(EPT_ENTRIES) == sizeof(VOID*) * 4);

/*!
    @brief Cleans up all EPT entries and the tables recursively.

    @param[in,out] EptTable - The pointer to the EPT table to clean up.

    @param[in] PageMapLevel - The level of the table.
 */
static
VOID
CleanupTables (
    _Inout_ _Pre_notnull_ EPT_ENTRY* EptTable,
    _In_ UINT32 PageMapLevel
    )
{
    //
    // EPT PT does not have any subtables to delete, and so attempting so is
    // invalid.
    //
    MV_ASSERT(PageMapLevel != EPT_LEVEL_PTE);

    //
    // Go through all 512 entries in the table.
    //
    for (UINT32 i = 0; i < 512; ++i)
    {
        EPT_ENTRY eptEntry;
        VOID* subTable;

        eptEntry = EptTable[i];

        //
        // Go to the next entry of the table if the entry is not initialized or
        // is a large page entry, which does not point to the next table.
        //
        if ((eptEntry.PageFrameNumber == 0) ||
            (eptEntry.LargePage != FALSE))
        {
            continue;
        }

        //
        // Get the address of the subtable. Free it if it is EPT PTE (ie, the
        // current table is EPT PD) as EPT PTE does not have any more subtables.
        // Otherwise, perform the same operations against the subtable.
        //
        subTable = GetVirtualAddress(eptEntry.PageFrameNumber << PAGE_SHIFT);
        if (PageMapLevel == EPT_LEVEL_PDE)
        {
            MmFreePages(subTable);
        }
        else
        {
            CleanupTables(subTable, PageMapLevel - 1);
        }
    }

    //
    // All subtables referenced from this table were freed. It is OK to free
    // this table as well.
    //
    MmFreePages(EptTable);
}

/*!
    @brief Builds EPT paging structures for the range of 512GB managed by the
        given EPT PML4E.

    @param[in,out] EptPml4 - The pointer to the EPT PML4.

    @param[in] EptPml4Index - The index within the EPT PML4 to build translation.

    @return MV_STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
static
_Must_inspect_result_
MV_STATUS
BuildEptEntriesFor512Gb (
    _Inout_ EPT_PML4* EptPml4,
    _In_ UINT32 EptPml4Index
    )
{
    static CONST UINT64 oneGigaByte = (1 * 1024 * 1024 * 1024);
    static CONST UINT64 twoMegaByte = (2 * 1024 * 1024);

    MV_STATUS status;
    EPT_ENTRY defaultPermissions;
    UINT64 hostPhysicalAddress;
    IA32_MEMORY_TYPE memoryType;
    EPT_ENTRIES eptEntries;
    EPDPTE* eptPdpt;
    EPDE_2MB* eptPd;
    EPTE* eptPt;

    defaultPermissions.Flags = 0;
    defaultPermissions.ReadAccess = TRUE;
    defaultPermissions.WriteAccess = TRUE;
    defaultPermissions.ExecuteAccess = TRUE;

    //
    // Allocate the EPT PDPT and fill with the default all allow permissions, and
    // initialize the EPT PML4 with it.
    //
    eptPdpt = MmAllocatePages(1);
    if (eptPdpt == NULL)
    {
        status = MV_STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    __stosq((UINT64*)eptPdpt, defaultPermissions.Flags, EPT_PDPTE_ENTRY_COUNT);

    eptEntries.Pml4e = &EptPml4[EptPml4Index];
    eptEntries.Pml4e->ReadAccess = TRUE;
    eptEntries.Pml4e->WriteAccess = TRUE;
    eptEntries.Pml4e->ExecuteAccess = TRUE;
    eptEntries.Pml4e->PageFrameNumber = (GetPhysicalAddress(eptPdpt) >> PAGE_SHIFT);

    //
    // Initialize all 512 entries in the EPT PDPT pointed by the EPT PML4E.
    //
    for (UINT32 eptPdptIndex = 0; eptPdptIndex < EPT_PDPTE_ENTRY_COUNT; ++eptPdptIndex)
    {
        //
        // Allocate the EPT PD and fill with the default all allow permissions,
        // and initialize the EPT PDTE with it.
        //
        eptPd = MmAllocatePages(1);
        if (eptPd == NULL)
        {
            status = MV_STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        __stosq((UINT64*)eptPd, defaultPermissions.Flags, EPT_PDE_ENTRY_COUNT);

        eptEntries.Pdpte.AsRegularPage = &eptPdpt[eptPdptIndex];
        eptEntries.Pdpte.AsRegularPage->PageFrameNumber = (GetPhysicalAddress(eptPd) >> PAGE_SHIFT);

        //
        // Initialize all 512 entries in the EPT PD pointed by the EPT PDPTE.
        //
        for (UINT32 eptPdIndex = 0; eptPdIndex < EPT_PDE_ENTRY_COUNT; ++eptPdIndex)
        {
            eptEntries.Pde.AsLargePage = &eptPd[eptPdIndex];

            //
            // Use the 2MB translation if the entire 2MB managed by this PDE has
            // same memory type. Otherwise, this PDE points to the EPT PT.
            //
            hostPhysicalAddress = ComputeAddressFromIndexes(EptPml4Index,
                                                            eptPdptIndex,
                                                            eptPdIndex,
                                                            0);
            memoryType = GetMemoryTypeForRange(hostPhysicalAddress, twoMegaByte);
            if (memoryType != MEMORY_TYPE_INVALID)
            {
                eptEntries.Pde.AsLargePage->LargePage = TRUE;
                eptEntries.Pde.AsLargePage->MemoryType = memoryType;
                eptEntries.Pde.AsLargePage->PageFrameNumber = (hostPhysicalAddress >> PAGE_SHIFT_2BM);
                continue;
            }

            //
            // Cannot be the single 2MB page. Allocate the EPT PT and fill with
            // the default all allow permissions, and initialize the EPT PDE with it.
            //
            eptPt = MmAllocatePages(1);
            if (eptPt == NULL)
            {
                status = MV_STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }
            __stosq((UINT64*)eptPt, defaultPermissions.Flags, EPT_PTE_ENTRY_COUNT);
            eptEntries.Pde.AsRegularPage->PageFrameNumber = (GetPhysicalAddress(eptPt) >> PAGE_SHIFT);

            //
            // Initialize all 512 entries in the EPT PT pointed by the EPT PDE.
            //
            for (UINT32 eptPteIndex = 0; eptPteIndex < EPT_PTE_ENTRY_COUNT; ++eptPteIndex)
            {
                hostPhysicalAddress = ComputeAddressFromIndexes(EptPml4Index,
                                                                eptPdptIndex,
                                                                eptPdIndex,
                                                                eptPteIndex);
                memoryType = GetMemoryTypeForRange(hostPhysicalAddress, PAGE_SIZE);
                MV_ASSERT(memoryType != MEMORY_TYPE_INVALID);

                eptEntries.Pte = &eptPt[eptPteIndex];
                eptEntries.Pte->MemoryType = memoryType;
                eptEntries.Pte->PageFrameNumber = (hostPhysicalAddress >> PAGE_SHIFT);
            }
        }
    }

    status = MV_STATUS_SUCCESS;

Exit:
    return status;
}

/*!
    @brief Split a 2MB EPT PDE to 512 EPT PTEs.

    @param[in,out] EptPdeLarge - The pointer to the 2MB EPT PDE to split.

    @return MV_STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
static
_Must_inspect_result_
MV_STATUS
Split2MbPage (
    _Inout_ EPDE_2MB* EptPdeLarge
    )
{
    MV_STATUS status;
    EPDE* eptPde;
    EPTE* eptPt;
    UINT64 hostPaBase;
    UINT64 hostPaToMap;

    MV_ASSERT(EptPdeLarge->LargePage != FALSE);

    //
    // Allocate the EPT PT as we are going to split one 2MB page to 512 4KB pages.
    //
    eptPt = MmAllocatePages(1);
    if (eptPt == NULL)
    {
        status = MV_STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Clear the large page bit, and propagate the current permissions to the
    // all entries in the EPT PTE.
    //
    EptPdeLarge->LargePage = FALSE;
    __stosq((UINT64*)eptPt, EptPdeLarge->Flags, EPT_PTE_ENTRY_COUNT);

    //
    // Update the page frame of each EPT PTE.
    //
    hostPaBase = (EptPdeLarge->PageFrameNumber << PAGE_SHIFT_2BM);
    for (UINT32 eptPtIndex = 0; eptPtIndex < EPT_PTE_ENTRY_COUNT; ++eptPtIndex)
    {
        hostPaToMap = hostPaBase + ((UINT64)eptPtIndex * PAGE_SIZE);
        eptPt[eptPtIndex].PageFrameNumber = (hostPaToMap >> PAGE_SHIFT);
    }

    //
    // Finally, update the PDE by pointing to the EPT PT.
    //
    eptPde = (EPDE*)EptPdeLarge;
    eptPde->Reserved1 = eptPde->Reserved2 = eptPde->Reserved3 = eptPde->Reserved4 = 0;
    eptPde->PageFrameNumber = (GetPhysicalAddress(eptPt) >> PAGE_SHIFT);

    status = MV_STATUS_SUCCESS;

Exit:
    return status;
}

_Use_decl_annotations_
MV_STATUS
InitializeExtendedPageTables (
    EPT_CONTEXT* EptContext
    )
{
    MV_STATUS status;
    EPT_PML4* eptPml4;

    eptPml4 = MmAllocatePages(1);
    if (eptPml4 == NULL)
    {
        status = MV_STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    status = BuildEptEntriesFor512Gb(eptPml4, 0);
    if (MV_ERROR(status))
    {
        LOG_ERROR("BuildEptEntriesFor512Gb failed : %08x", status);
        goto Exit;
    }
    EptContext->EptPml4 = eptPml4;

    //
    // All EPT initialization completed successfully. Set up the
    // extended-page-table pointer (EPTP).
    //
    // The EPTP is the top level data structure for EPT that governs the vast
    // majority of EPT related behavior and is written to VMCS. This structure
    // can be understood as CR3 equivalent in EPT as it holds a physical address
    // of the EPT PML4 table.
    // See: 24.6.11 Extended-Page-Table Pointer (EPTP)
    //

    //
    // Specify the memory-type used for accessing to any of EPT paging-structures.
    // We use the memory-type as those structures are allocated, that is the
    // write-back memory type. We assume that CR0.CD (cache disabled) is 0, which
    // should always be the case here.
    // See: 28.2.6.1 Memory Type Used for Accessing EPT Paging Structures
    //
    EptContext->EptPointer.MemoryType = MEMORY_TYPE_WRITE_BACK;

    //
    // "This value is 1 less than the EPT page-walk length."
    // "The EPT translation mechanism (...) uses a page-walk length of 4".
    // See: Table 24-8. Format of Extended-Page-Table Pointer
    // See: 28.2.2 EPT Translation Mechanism
    //
    EptContext->EptPointer.PageWalkLength = EPT_PAGE_WALK_LENGTH_4;

    //
    // PFN of the EPT PML4 table.
    //
    EptContext->EptPointer.PageFrameNumber = GetPhysicalAddress(EptContext->EptPml4) >> PAGE_SHIFT;

Exit:
    if (MV_ERROR(status))
    {
        if (eptPml4 != NULL)
        {
            CleanupTables((EPT_ENTRY*)eptPml4, EPT_LEVEL_PML4E);
        }
    }
    return status;
}

_Use_decl_annotations_
VOID
CleanupExtendedPageTables (
    EPT_CONTEXT* EptContext
    )
{
    CleanupTables((EPT_ENTRY*)EptContext->EptPml4, EPT_LEVEL_PML4E);
}

_Use_decl_annotations_
MV_STATUS
UpdateExtendPageTables (
    EPT_PML4* EptPml4,
    UINT64 GuestPhysicalAddress,
    CONST UINT64* HostPhysicalAddress,
    CONST EPT_ENTRY* Permissions
    )
{
    MV_STATUS status;
    ADDRESS_TRANSLATION_HELPER helper;
    EPT_ENTRIES eptEntries;
    EPDPTE_1GB* eptPdpt;
    EPDE_2MB* eptPd;
    EPTE* eptPt;

    MV_ASSERT(ARGUMENT_PRESENT(HostPhysicalAddress) ||
              ARGUMENT_PRESENT(Permissions));

    //
    // Locate the EPT PML4E for the GPA.
    //
    helper.AsUInt64 = GuestPhysicalAddress;
    eptEntries.Pml4e = &EptPml4[helper.AsIndex.Pml4];
    MV_ASSERT(MV_IS_EPT_ENTRY_PRESENT(eptEntries.Pml4e) != FALSE);

    //
    // Locate the EPT PDPTE for the GPA. The entry must not be large page as we
    // do not use 1GB page.
    //
    eptPdpt = GetVirtualAddress(eptEntries.Pml4e->PageFrameNumber << PAGE_SHIFT);
    eptEntries.Pdpte.AsLargePage = &eptPdpt[helper.AsIndex.Pdpt];
    MV_ASSERT(MV_IS_EPT_ENTRY_PRESENT(eptEntries.Pdpte.AsRegularPage) != FALSE);
    MV_ASSERT(eptEntries.Pdpte.AsLargePage->LargePage == FALSE);

    //
    // Locate the EPT PDE for the GPA. If the entry is the 2MB page, split it.
    //
    eptPd = GetVirtualAddress(eptEntries.Pdpte.AsRegularPage->PageFrameNumber << PAGE_SHIFT);
    eptEntries.Pde.AsLargePage = &eptPd[helper.AsIndex.Pd];
    MV_ASSERT(MV_IS_EPT_ENTRY_PRESENT(eptEntries.Pde.AsRegularPage) != FALSE);

    if (eptEntries.Pde.AsLargePage->LargePage != FALSE)
    {
       status = Split2MbPage(eptEntries.Pde.AsLargePage);
       if (MV_ERROR(status))
       {
           goto Exit;
       }
    }

    MV_ASSERT(eptEntries.Pdpte.AsLargePage->LargePage == FALSE);

    //
    // Locate the EPT PTE for the GPA and update translation and permissions as
    // requested.
    //
    eptPt = GetVirtualAddress(eptEntries.Pde.AsRegularPage->PageFrameNumber << PAGE_SHIFT);
    eptEntries.Pte = &eptPt[helper.AsIndex.Pt];
    if (ARGUMENT_PRESENT(HostPhysicalAddress))
    {
        eptEntries.Pte->PageFrameNumber = (*HostPhysicalAddress >> PAGE_SHIFT);
    }
    if (ARGUMENT_PRESENT(Permissions))
    {
        eptEntries.Pte->ReadAccess = Permissions->ReadAccess;
        eptEntries.Pte->WriteAccess = Permissions->WriteAccess;
        eptEntries.Pte->ExecuteAccess = Permissions->ExecuteAccess;
    }

    status = MV_STATUS_SUCCESS;

Exit:
    return status;
}

_Use_decl_annotations_
VOID
InvalidateEptDerivedCache (
    UINT64 EptPointer
    )
{
    INVEPT_DESCRIPTOR descriptor;
    INVEPT_TYPE type;

    RtlZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.EptPointer = EptPointer;
    type = (EptPointer == 0) ? InveptAllContext : InveptSingleContext;
    MV_VERIFY(AsmInvept(type, &descriptor) == VmxResultOk);
}

_Use_decl_annotations_
VOID
InvalidateVpidDerivedCache (
    UINT16 VirtualProcessorId
    )
{
    INVVPID_DESCRIPTOR descriptor;
    INVVPID_TYPE type;

    RtlZeroMemory(&descriptor, sizeof(descriptor));
    descriptor.Vpid = VirtualProcessorId;
    type = (VirtualProcessorId == 0) ? InvvpidAllContext : InvvpidSingleContext;
    MV_VERIFY(AsmInvvpid(type, &descriptor)== VmxResultOk);
}
