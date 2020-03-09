/*!
    @file Ia32Utils.c

    @brief Utility functions that could be used by both the host and non-host.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "Ia32Utils.h"
#include "Asm.h"
#include "Logger.h"

_Use_decl_annotations_
UINT64
ComputeAddressFromIndexes (
    UINT32 Pml4Index,
    UINT32 PdptIndex,
    UINT32 PdIndex,
    UINT32 PtIndex
    )
{
    ADDRESS_TRANSLATION_HELPER helper;

    helper.AsUInt64 = 0;
    helper.AsIndex.Pml4 = Pml4Index;
    helper.AsIndex.Pdpt = PdptIndex;
    helper.AsIndex.Pd = PdIndex;
    helper.AsIndex.Pt = PtIndex;
    return helper.AsUInt64;
}

UINT32
GetSegmentAccessRight (
    _In_ UINT16 SegmentSelector
    )
{
    SEGMENT_SELECTOR segmentSelector;
    UINT32 nativeAccessRight;
    VMX_SEGMENT_ACCESS_RIGHTS accessRight;

    segmentSelector.Flags = SegmentSelector;

    //
    // "In general, a segment register is unusable if it has been loaded with a
    //  null selector."
    // See: 24.4.1 Guest Register State
    //
    if ((segmentSelector.Table == 0) &&
        (segmentSelector.Index == 0))
    {
        accessRight.Flags = 0;
        accessRight.Unusable = TRUE;
        goto Exit;
    }

    //
    // Convert the native access right to the format for VMX. Those two formats
    // are almost identical except that first 8 bits of the native format does
    // not exist in the VMX format, and that few fields are undefined in the
    // native format but reserved to be zero in the VMX format.
    //
    nativeAccessRight = AsmLoadAccessRightsByte(SegmentSelector);
    MV_ASSERT(nativeAccessRight);
    accessRight.Flags = (nativeAccessRight >> 8);
    accessRight.Reserved1 = 0;
    accessRight.Reserved2 = 0;
    accessRight.Unusable = FALSE;

Exit:
    return accessRight.Flags;
}

/*!
    @brief Returns the segment descriptor corresponds to the SegmentSelector.

    @param[in] DescriptorTableBase - The address of the base of the descriptor
        table.

    @param[in] SegmentSelector - The segment selector value.

    @return The segment descriptor corresponds to the SegmentSelector.
 */
static
SEGMENT_DESCRIPTOR_32*
GetSegmentDescriptor (
    _In_ UINT64 DescriptorTableBase,
    _In_ UINT16 SegmentSelector
    )
{
    SEGMENT_SELECTOR segmentSelector;
    SEGMENT_DESCRIPTOR_32* segmentDescriptors;

    //
    // "Selects one of 8192 descriptors in the GDT or LDT. The processor multiplies
    //  the index value by 8 (the number of bytes in a segment descriptor) and
    //  adds the result to the base address of the GDT or LDT (from the GDTR or
    //  LDTR register, respectively)."
    // See: 3.4.2 Segment Selectors
    //
    segmentSelector.Flags = SegmentSelector;
    segmentDescriptors = (SEGMENT_DESCRIPTOR_32*)DescriptorTableBase;
    return &segmentDescriptors[segmentSelector.Index];
}

/*!
    @brief Returns the base address of SegmentDescriptor.

    @param[in] SegmentDescriptor - The segment descriptor from which retrieve
        the base address.

    @return The base address of SegmentDescriptor.
 */
static
UINT64
GetSegmentBaseByDescriptor (
    _In_ CONST SEGMENT_DESCRIPTOR_32* SegmentDescriptor
    )
{
    UINT64 segmentBase;
    UINT64 baseHigh, baseMiddle, baseLow;

    baseHigh = ((UINT64)SegmentDescriptor->BaseAddressHigh) << (6 * 4);
    baseMiddle = ((UINT64)SegmentDescriptor->BaseAddressMiddle) << (4 * 4);
    baseLow = SegmentDescriptor->BaseAddressLow;
    segmentBase = (baseHigh | baseMiddle | baseLow) & MAXUINT32;

    //
    // Few system descriptors are expanded to 16 bytes on x64. For practical
    // reasons, we only detect TSS descriptors (that is the System field is
    // cleared, and the Type field has either one of specific values).
    //
    // See: 3.5.2 Segment Descriptor Tables in IA-32e Mode
    //
    if ((SegmentDescriptor->System == 0) &&
        ((SegmentDescriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE) ||
         (SegmentDescriptor->Type == SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY)))
    {
        CONST SEGMENT_DESCRIPTOR_64* descriptor64;

        descriptor64 = (CONST SEGMENT_DESCRIPTOR_64*)SegmentDescriptor;
        segmentBase |= ((UINT64)descriptor64->BaseAddressUpper << 32);
    }
    return segmentBase;
}

UINT64
GetSegmentBase (
    _In_ UINT64 DescriptorTableBase,
    _In_ UINT16 SegmentSelector
    )
{
    UINT64 segmentBase;
    SEGMENT_SELECTOR segmentSelector;

    segmentSelector.Flags = SegmentSelector;

    if ((segmentSelector.Table == 0) &&
        (segmentSelector.Index == 0))
    {
        //
        // The null segment selectors technically does not point to a valid
        // segment descriptor, hence no valid base address either. We return
        // 0 for convenience, however.
        //
        // "The first entry of the GDT is not used by the processor. A segment
        //  selector that points to this entry of the GDT (that is, a segment
        //  selector with an index of 0 and the TI flag set to 0) is used as a
        //  "null segment selector."".
        // 3.4.2 Segment Selectors
        //
        segmentBase = 0;
        goto Exit;
    }

    //
    // For practical reasons, we do not support LDT. This will not be an issue
    // as we are running as a SYSTEM which will not use LDT.
    //
    // "Specifies the descriptor table to use: clearing this flag selects the GDT;
    //  setting this flag selects the current LDT."
    // See: 3.4.2 Segment Selectors
    //
    MV_ASSERT(segmentSelector.Table == 0);
    segmentBase = GetSegmentBaseByDescriptor(GetSegmentDescriptor(DescriptorTableBase,
                                                                  SegmentSelector));

Exit:
    return segmentBase;
}

_Use_decl_annotations_
CR0
AdjustCr0 (
    CR0 Cr0
    )
{
    CR0 newCr0, fixed0Cr0, fixed1Cr0;

    newCr0 = Cr0;
    fixed0Cr0.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
    fixed1Cr0.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
    newCr0.Flags &= fixed1Cr0.Flags;
    newCr0.Flags |= fixed0Cr0.Flags;
    return newCr0;
}

_Use_decl_annotations_
CR4
AdjustCr4 (
    CR4 Cr4
    )
{
    CR4 newCr4, fixed0Cr4, fixed1Cr4;

    newCr4 = Cr4;
    fixed0Cr4.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
    fixed1Cr4.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
    newCr4.Flags &= fixed1Cr4.Flags;
    newCr4.Flags |= fixed0Cr4.Flags;
    return newCr4;
}
