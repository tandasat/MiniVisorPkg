/*!
    @file EfiHostInitialization.c

    @brief EFI specific implementation of host environment initialization.

    @details On EFI, the host uses its own paging structures (CR3) and interrupt
        descriptor table (IDT).

        Its own paging structures is preferable and the most straightforward
        approach to void impact from the physical mode to the virtual mode
        transition happens during OS startup time. After this transition (ie,
        SetVirtualAddressMap is called from a boot loader), the paging structures
        that is used at the physical mode and the host would be using it becomes
        invalid, as nothing runs on the physical mode anymore. This results in
        crash (triple fault) when VM-exit occurs. One solution could be to
        subscribe the SetVirtualAddressMap event and notify the host to switch
        to the new CR3 for the virtual mode, but this has to be done for all
        logical processors requiring some inter processor calls. The MP protocol
        could do the job but is no longer available at the moment of the transition
        notification because the system is already switched from the boot time to
        the run time.

        Its own interrupt descriptor table is required for the same reason. After
        transitioning to the virtual mode, the existing IDT becomes invalid. One
        might think the host IDT is not relevant as interrupts are disabled. The
        fact is that NMI still occurs while the host is running, and also, having
        basic diagnose handlers are useful in case of access violation, for example.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "EfiHostInitialization.h"
#include "EfiAsm.h"
#include "EfiPlatform.h"
#include "../../Ia32Utils.h"
#include "EfiLogger.h"

//
// The format of the IDT.
//
typedef struct _INTERRUPT_GATE_DESCRIPTOR
{
    UINT16 Offset15To0 : 16;
    UINT16 SegmentSelector : 16;
    UINT8 Reserved0;
    UINT8 GateType;
    UINT16 Offset31To16;
    UINT32 Offset63To32;
    UINT32 Reserved1;
} INTERRUPT_GATE_DESCRIPTOR;
C_ASSERT(sizeof(INTERRUPT_GATE_DESCRIPTOR) == 16);

//
// Collections of paging structures. Only the single PDPT is accommodated to
// handle only up to 512GB of physical memory.
//
typedef struct _PAGING_STRUCTURES
{
    //
    // There is only one PML4, unless 5-level page mapping is enabled.
    //
    DECLSPEC_ALIGN(PAGE_SIZE) PML4E_64 Pml4[PML4_ENTRY_COUNT];

    //
    // Only one PDPT is used for PML4[0]. This covers 512GB of the physical memory
    // range and is sufficient for our purpose.
    //
    DECLSPEC_ALIGN(PAGE_SIZE) PDPTE_64 Pdpt[1][PDPT_ENTRY_COUNT];

    //
    // PDs are assigned for each PDPT entry, meaning that 512 (PDPTEs) multiplied
    // by the PDT entry count.
    //
    DECLSPEC_ALIGN(PAGE_SIZE) PDE_2MB_64 Pdt[1][PDPT_ENTRY_COUNT][PDT_ENTRY_COUNT];
} PAGING_STRUCTURES;

//
// Paging related.
//
static PAGING_STRUCTURES g_HostPagingStructures;
static CR3 g_HostCr3;

//
// IDT related.
//
static INTERRUPT_GATE_DESCRIPTOR g_HostIdt[IDT_ENTRY_COUNT];
static IDTR g_HostIdtr;

/*!
    @brief Initializes the host paging structures.

    @details This function fills out the statically allocated paging structures
        and builds the identity mapping. All translation is done with 2MB pages
        since not 4KB granularity configuration is not needed.

        The identity mapping works because when the host is loaded, the EFI system
        also uses the identity mapping, meaning that it is essentially making a
        clone of existing paging structures.

        Note that page protections are all writable and executable. One may drop
        the executable attribute for outside the range of the .text section of
        this module and drop writable for the same range to be W^X.
 */
static
VOID
InitializeHostPagingStructures (
    )
{
    PML4E_64* pml4;
    PDPTE_64* pdpt;
    PDE_2MB_64* pdt;
    UINT32 pml4Index;

    pml4Index = 0;
    pml4 = g_HostPagingStructures.Pml4;
    pdpt = g_HostPagingStructures.Pdpt[pml4Index];

    //
    // Fill out PML4, PDPT, PDT.
    //
    pml4[0].Present = TRUE;
    pml4[0].Write = TRUE;
    pml4[0].PageFrameNumber = GetPhysicalAddress(pdpt) >> PAGE_SHIFT;

    for (UINT32 pdptIndex = 0; pdptIndex < PDPT_ENTRY_COUNT; ++pdptIndex)
    {
        pdt = g_HostPagingStructures.Pdt[pml4Index][pdptIndex];

        pdpt[pdptIndex].Present = TRUE;
        pdpt[pdptIndex].Write = TRUE;
        pdpt[pdptIndex].PageFrameNumber = GetPhysicalAddress(pdt) >> PAGE_SHIFT;

        for (UINT32 pdIndex = 0; pdIndex < PDT_ENTRY_COUNT; ++pdIndex)
        {
            UINT64 physicalAddress;

            physicalAddress = ComputeAddressFromIndexes(pml4Index,
                                                        pdptIndex,
                                                        pdIndex,
                                                        0);
            pdt[pdIndex].Present = TRUE;
            pdt[pdIndex].Write = TRUE;
            pdt[pdIndex].LargePage = TRUE;
            pdt[pdIndex].PageFrameNumber = physicalAddress >> PAGE_SHIFT_2BM;
        }
    }

    //
    // Then initialize the CR3 to point to the PML4.
    //
    g_HostCr3.AddressOfPageDirectory = GetPhysicalAddress(pml4) >> PAGE_SHIFT;
}

/*!
    @brief Initializes the host IDT.

    @details This function fills out the IDT with AsmDefaultExceptionHandlers[N]
        where N is the interrupt number and initializes IDTR to point to the IDT.

        AsmDefaultExceptionHandlers is the array of stub functions to transfer
        execution to the main common logic in AsmCommonExceptionHandler.
 */
static
VOID
InitializeHostIdt (
    )
{
    UINT64 handlerBase;

    //
    // Get the beginning of the AsmDefaultExceptionHandlers to index.
    //
    handlerBase = (UINT64)&AsmDefaultExceptionHandlers;

    //
    // Fill out all IDT entries.
    //
    for (UINT32 i = 0; i < IDT_ENTRY_COUNT; ++i)
    {
        static const UINT64 sizeOfHandlerTill0x7f = 9;
        static const UINT64 sizeOfHandlerFrom0x80 = 12;
        UINT64 sizeOfHandler;
        UINT64 handlerAddress;

        //
        // Compute the address of AsmDefaultExceptionHandlers[i]. Each stub
        // function is 9 bytes up to 0x7f, and 12 bytes after that.
        //
        if (i < 0x80)
        {
            sizeOfHandler = sizeOfHandlerTill0x7f;
        }
        else
        {
            sizeOfHandler = sizeOfHandlerFrom0x80;
        }
        handlerAddress = (handlerBase + i * sizeOfHandler);

        //
        // Fill out the IDT entry. The type is 32-bit Interrupt gate: 0x8E
        //  P=1, DPL=00b, S=0, type=1110b => type_attr=1000_1110b=0x8E)
        //
        g_HostIdt[i].Offset15To0 = (UINT16)handlerAddress;
        g_HostIdt[i].Offset31To16 = (UINT16)(handlerAddress >> 16);
        g_HostIdt[i].Offset63To32 = (UINT32)(handlerAddress >> 32);
        g_HostIdt[i].SegmentSelector = AsmReadCs();
        g_HostIdt[i].GateType = 0x8E;
    }

    //
    // Finally initialize the IDTR to point to the IDT.
    //
    g_HostIdtr.Limit = sizeof(g_HostIdt) - 1;
    g_HostIdtr.BaseAddress = (UINT64)(&g_HostIdt[0]);
}

VOID
InitializeHostEnvironment (
    )
{
    InitializeHostPagingStructures();
    InitializeHostIdt();
}

CR3
GetHostCr3 (
    )
{
    return g_HostCr3;
}

CONST IDTR*
GetHostIdtr (
    )
{
    return &g_HostIdtr;
}

VOID
InitializeGdt (
    TASK_STATE_SEGMENT_64* NewTss,
    SEGMENT_DESCRIPTOR_64* NewGdt,
    UINT64 NewGdtSize,
    GDTR* OriginalGdtr
    )
{
    GDTR newGdtr;
    SEGMENT_SELECTOR taskRegister;
    SEGMENT_DESCRIPTOR_64 tssDescriptor;
    SEGMENT_DESCRIPTOR_64* tssDescriptorInGdt;
    UINT64 tssAddress;
    SEGMENT_DESCRIPTOR_32* newGdt32;

    //
    // Get the current GDTR.
    //
    _sgdt(&newGdtr);
    *OriginalGdtr = newGdtr;

    //
    // Copy contents of the existing GDT to the new GDT in the processor context.
    //
    RtlCopyMemory(NewGdt, (VOID*)newGdtr.BaseAddress, newGdtr.Limit);

    //
    // Set up TR pointing to the entry going to be added below in the GDT. Divide
    // by the size of SEGMENT_DESCRIPTOR_32 because the limit field is in bytes
    // while the index is index in the entry count.
    //
    taskRegister.Flags = 0;
    taskRegister.Index = (newGdtr.Limit + 1ull) / sizeof(SEGMENT_DESCRIPTOR_32);

    //
    // Update the GDTR. Change the base to the new location and increase the
    // limit to add one more entry for TR. Make sure we have enough space
    // in the processor context to copy the contents of GDT.
    //
    newGdtr.BaseAddress = (UINT64)NewGdt;
    newGdtr.Limit += sizeof(SEGMENT_DESCRIPTOR_64);
    MV_ASSERT(newGdtr.Limit < NewGdtSize);

    //
    // At this point, the TR points to uninitialized entry in the GDT. Set up
    // the Task State Segment Descriptor to be written to GDT.
    //
    tssAddress = (UINT64)NewTss;
    RtlZeroMemory(&tssDescriptor, sizeof(tssDescriptor));
    tssDescriptor.SegmentLimitLow = sizeof(*NewTss) - 1;
    tssDescriptor.BaseAddressLow = (tssAddress & MAXUINT16);
    tssDescriptor.BaseAddressMiddle = ((tssAddress >> 16) & MAXUINT8);
    tssDescriptor.BaseAddressHigh = ((tssAddress >> 24) & MAXUINT8);
    tssDescriptor.BaseAddressUpper = ((tssAddress >> 32) & MAXUINT32);
    tssDescriptor.Type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
    tssDescriptor.Present = TRUE;

    //
    // Update the GDT by writing entry for TSS, which is pointed by the TR.
    //
    newGdt32 = (SEGMENT_DESCRIPTOR_32*)NewGdt;
    tssDescriptorInGdt = (SEGMENT_DESCRIPTOR_64*)(&newGdt32[taskRegister.Index]);
    *tssDescriptorInGdt = tssDescriptor;

    //
    // Finally, update the GDTR and TR of the current processor. The VT-x
    // requires the guest task segment register to be configured correctly
    // and the UEFI platform typically does not (ie, TR being zero). Update TR
    // to point to the task segment just set up.
    //
    // See: 26.3.1.2 Checks on Guest Segment Registers
    //
    _lgdt(&newGdtr);
    AsmWriteTr(taskRegister.Flags);
}

VOID
CleanupGdt (
    CONST GDTR* OriginalGdtr
    )
{
    MV_ASSERT(OriginalGdtr->BaseAddress != 0);
    _lgdt((VOID*)OriginalGdtr);
}
