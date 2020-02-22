/*!
    @file MemoryType.c

    @brief Functions for MTRR (memory type range registers) handling.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "MemoryType.h"
#include "Logger.h"

//
// A physical address range and its memory type.
//
typedef struct _MEMORY_TYPE_RANGE
{
    BOOLEAN FixedMtrr;
    IA32_MEMORY_TYPE MemoryType;
    UINT64 RangeBase;   // Inclusive
    UINT64 RangeEnd;    // Exclusive
} MEMORY_TYPE_RANGE;

//
// Represents MTRR configurations on this system.
//
typedef struct _MTRR_CONTEXT
{
    //
    // The memory type should be used for physical addresses whose memory types
    // are not specified by MTRR.
    //
    IA32_MEMORY_TYPE DefaultMemoryType;

    //
    // The collection of physical memory address ranges and their memory types
    // collected from MTRR.
    //
    MEMORY_TYPE_RANGE MemoryTypeRanges[IA32_MTRR_COUNT];
} MTRR_CONTEXT;

//
// Mapping of physical addresses to memory types.
//
static MTRR_CONTEXT g_MtrrDatabase;


typedef struct _FIXED_MTRR_RANGE_INFORMATION
{
    //
    // The fixed-range MTRR MSR.
    //
    IA32_MSR_ADDRESS Msr;

    //
    // The start physical address where the fixed-range MTRR MSR manages.
    //
    UINT64 BaseAddress;

    //
    // The size where a single "range" of the fixed-range MTRR MSR manages.
    // A single fixed-range MTRR contains 8 ranges, and this field represents
    // the size a single range manages.
    // See: 11.11.2.2 Fixed Range MTRRs
    //
    UINT64 ManagedSize;
} FIXED_MTRR_RANGE_INFORMATION;

MV_SECTION_INIT
VOID
InitializeMemoryTypeMapping (
    )
{
    //
    // This array defines all fixed-range MTRRs.
    // See: 11.11.2.2 Fixed Range MTRRs
    //
    static CONST FIXED_MTRR_RANGE_INFORMATION rangeInformation[] =
    {
        { IA32_MTRR_FIX64K_00000, 0x0, 0x10000, },
        { IA32_MTRR_FIX16K_80000, 0x80000, 0x4000, },
        { IA32_MTRR_FIX16K_A0000, 0xA0000, 0x4000, },
        { IA32_MTRR_FIX4K_C0000,  0xC0000, 0x1000, },
        { IA32_MTRR_FIX4K_C8000,  0xC8000, 0x1000, },
        { IA32_MTRR_FIX4K_D0000,  0xD0000, 0x1000, },
        { IA32_MTRR_FIX4K_D8000,  0xD8000, 0x1000, },
        { IA32_MTRR_FIX4K_E0000,  0xE0000, 0x1000, },
        { IA32_MTRR_FIX4K_E8000,  0xE8000, 0x1000, },
        { IA32_MTRR_FIX4K_F0000,  0xF0000, 0x1000, },
        { IA32_MTRR_FIX4K_F8000,  0xF8000, 0x1000, },
    };

    UINT32 index;
    IA32_MTRR_DEF_TYPE_REGISTER defaultType;
    IA32_MTRR_CAPABILITIES_REGISTER capabilities;
    MEMORY_TYPE_RANGE rangeType;
    MTRR_CONTEXT* mtrr;
    IA32_MEMORY_TYPE memoryType;
    UINT64 baseForRange;

    mtrr = &g_MtrrDatabase;
    index = 0;
    defaultType.Flags = __readmsr(IA32_MTRR_DEF_TYPE);
    capabilities.Flags = __readmsr(IA32_MTRR_CAPABILITIES);

    RtlZeroMemory(&rangeType, sizeof(rangeType));
    rangeType.MemoryType = MEMORY_TYPE_INVALID;

    //
    // We assume MTRRs are enabled. This should always be the case.
    //
    MV_ASSERT(defaultType.MtrrEnable != FALSE);

    //
    // Use the fixed-range MTRRs when supported and enabled.
    //
    if ((capabilities.FixedRangeSupported != FALSE) &&
        (defaultType.FixedRangeMtrrEnable != FALSE))
    {
        //
        // Parse all fixed-range MTRRs.
        //
        for (UINT32 i = 0; i < RTL_NUMBER_OF(rangeInformation); ++i)
        {
            CONST FIXED_MTRR_RANGE_INFORMATION* range;
            IA32_MTRR_FIXED_RANGE_MSR fixedRange;

            range = &rangeInformation[i];
            fixedRange.Flags = __readmsr(range->Msr);

            //
            // The fixed-range MTRR consists of 8 memory type fields. Each of
            // them specifies the memory type of the range computed as follows:
            //  start address + (managed size * index of the range).
            // Go through each of them and save pairs of ranges and memory types.
            // See: 11.11.2.2 Fixed Range MTRRs
            // See: Table 11-9. Address Mapping for Fixed-Range MTRRs
            //
            for (UINT32 j = 0; j < RTL_NUMBER_OF(fixedRange.u.Types); ++j)
            {
                memoryType = fixedRange.u.Types[j];
                baseForRange = range->BaseAddress + (range->ManagedSize * j);

                //
                // Combine this entry if it is contiguous from the previous entry
                // with the same memory type.
                //
                if ((rangeType.MemoryType == memoryType) &&
                    (rangeType.RangeEnd == baseForRange))
                {
                    rangeType.RangeEnd += range->ManagedSize;
                }
                else
                {
                    //
                    // Otherwise, save the previous (possibly combined) entry to
                    // the database if exists. Then, keep the current entry for
                    // combining with any following contiguous entries.
                    //
                    if (rangeType.MemoryType != MEMORY_TYPE_INVALID)
                    {
                        mtrr->MemoryTypeRanges[index] = rangeType;
                        index++;
                    }
                    rangeType.FixedMtrr = TRUE;
                    rangeType.MemoryType = memoryType;
                    rangeType.RangeBase = baseForRange;
                    rangeType.RangeEnd = baseForRange + (range->ManagedSize);
                }
            }
        }
    }

    //
    // Go through all variable-range MTRRs.
    // See: 11.11.2.3 Variable Range MTRRs
    //
    for (UINT32 i = 0; i < capabilities.VariableRangeCount; ++i)
    {
        IA32_MSR_ADDRESS physMaskMsr, physBaseMsr;
        IA32_MTRR_PHYSMASK_REGISTER physMaskValue;
        IA32_MTRR_PHYSBASE_REGISTER physBaseValue;
        UINT32 length;
        UINT64 sizeInPages;

        //
        // The variable-range MTRR is described with a pair of MSRs:
        // IA32_MTRR_PHYSBASEn indicating the memory type and the starting
        // address and IA32_MTRR_PHYSMASKn indicating the size.
        //
        physMaskMsr = IA32_MTRR_PHYSMASK0 + (i * 2);
        physMaskValue.Flags = __readmsr(physMaskMsr);

        //
        // Skip if the IA32_MTRR_PHYSMASKn and IA32_MTRR_PHYSBASEn pair is
        // disabled.
        //
        if (physMaskValue.Valid == FALSE)
        {
            continue;
        }

        //
        // Compute the size of the range.
        //
        MV_VERIFY(_BitScanForward64((unsigned long*)&length, physMaskValue.PageFrameNumber) != 0);
        sizeInPages = (1ull << length);

        //
        // Get the starting address (in pages) and the memory type, then save
        // them.
        //
        physBaseMsr = IA32_MTRR_PHYSBASE0 + (i * 2);
        physBaseValue.Flags = __readmsr(physBaseMsr);

        memoryType = (IA32_MEMORY_TYPE)physBaseValue.Type;
        baseForRange = (physBaseValue.PageFrameNumber << PAGE_SHIFT);

        //
        // The same logic as above. Combine if contiguous, else save the entry
        // to the database and keep the current entry for combining with subsequent
        // entries.
        //
        if ((rangeType.FixedMtrr == FALSE) &&
            (rangeType.MemoryType == memoryType) &&
            (rangeType.RangeEnd == baseForRange))
        {
            rangeType.RangeEnd += (sizeInPages << PAGE_SHIFT);
        }
        else
        {
            if (rangeType.MemoryType != MEMORY_TYPE_INVALID)
            {
                mtrr->MemoryTypeRanges[index] = rangeType;
                index++;
            }
            rangeType.FixedMtrr = FALSE;
            rangeType.MemoryType = memoryType;
            rangeType.RangeBase = baseForRange;
            rangeType.RangeEnd = baseForRange + (sizeInPages << PAGE_SHIFT);
        }
    }

    //
    // Add the last entry to the database.
    //
    if (rangeType.MemoryType != MEMORY_TYPE_INVALID)
    {
        mtrr->MemoryTypeRanges[index] = rangeType;
    }

    mtrr->DefaultMemoryType = (IA32_MEMORY_TYPE)defaultType.DefaultMemoryType;

    //
    // Dump configured ranges.
    //
    LOG_DEBUG("Type=%u (Default)", mtrr->DefaultMemoryType);
    for (UINT32 i = 0; i <= index; ++i)
    {
        LOG_DEBUG("Type=%u Fixed=%u %016llx - %016llx",
                  mtrr->MemoryTypeRanges[i].MemoryType,
                  mtrr->MemoryTypeRanges[i].FixedMtrr,
                  mtrr->MemoryTypeRanges[i].RangeBase,
                  mtrr->MemoryTypeRanges[i].RangeEnd);
    }
}

_Use_decl_annotations_
IA32_MEMORY_TYPE
GetMemoryTypeForRange (
    UINT64 PhysicalAddress,
    UINT64 RangeSize
    )
{
    IA32_MEMORY_TYPE memoryType;
    MTRR_CONTEXT* mtrr;

    mtrr = &g_MtrrDatabase;

    memoryType = MEMORY_TYPE_INVALID;

    for (UINT32 i = 0; i < RTL_NUMBER_OF(mtrr->MemoryTypeRanges); ++i)
    {
        CONST MEMORY_TYPE_RANGE* range;

        range = &mtrr->MemoryTypeRanges[i];

        if ((range->RangeBase == 0) &&
            (range->RangeEnd == 0))
        {
            break;
        }

        //
        // Look for the next range information if the base address is outside
        // the range this entry manages.
        //
        if ((PhysicalAddress < range->RangeBase) ||
            (PhysicalAddress >= range->RangeEnd))
        {
            continue;
        }

        //
        // The first page is managed by the current MTRR entry. Then, all other
        // pages in the given range must fit in the current MTRR entry; otherwise
        // the given range has more than one MTRRs either explicitly or
        // implicitly. Bail out and report error in this case.
        //
        if ((PhysicalAddress + RangeSize - 1) >= range->RangeEnd)
        {
            goto Exit;
        }

        //
        // The fixed-range MTRR takes precedence.
        //
        // "If the physical address falls within the first 1 MByte of physical
        //  memory and fixed MTRRs are enabled, the processor uses the memory
        //  type stored for the appropriate fixed-range MTRR."
        // See: 11.11.4.1 MTRR Precedences
        //
        if (range->FixedMtrr != FALSE)
        {
            memoryType = range->MemoryType;
            goto Exit;
        }

        //
        // The UC memory type takes precedence.
        //
        // "If two or more variable memory ranges match and one of the memory
        //  types is UC, the UC memory type used."
        // See: 11.11.4.1 MTRR Precedences
        //
        if (range->MemoryType == MEMORY_TYPE_UNCACHEABLE)
        {
            memoryType = range->MemoryType;
            goto Exit;
        }

        //
        // The WT memory type takes precedence over the WB memory type.
        //
        // "If two or more variable memory ranges match and the memory types are
        //  WT and WB, the WT memory type is used."
        // See: 11.11.4.1 MTRR Precedences
        //
        if (((range->MemoryType == MEMORY_TYPE_WRITE_THROUGH) &&
             (memoryType == MEMORY_TYPE_WRITE_BACK)) ||
            ((range->MemoryType == MEMORY_TYPE_WRITE_BACK) &&
             (memoryType == MEMORY_TYPE_WRITE_THROUGH)))
        {
            memoryType = MEMORY_TYPE_WRITE_THROUGH;
        }
        else
        {
            //
            // Use the last matching MTRR (even with multiple entries overlap).
            //
            // "For overlaps not defined by the above rules, processor behavior
            //  is undefined."
            // See: 11.11.4.1 MTRR Precedences
            //
            memoryType = range->MemoryType;
        }
    }

    //
    // Use the default type if none of MTRRs controls any page in this range.
    //
    // "If no fixed or variable memory range matches, the processor uses the
    //  default memory type."
    // See: 11.11.4.1 MTRR Precedences
    //
    if (memoryType == MEMORY_TYPE_INVALID)
    {
        memoryType = mtrr->DefaultMemoryType;
    }

Exit:
    return memoryType;
}
