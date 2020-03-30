/*!
    @file Ia32Utils.h

    @brief Utility functions that could be used by both the host and non-host.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

/*!
    @brief Computes the address from the four page table indexes.

    @param[in] Pml4Index - The index for PML4.

    @param[in] PdptIndex - The index for PDPT.

    @param[in] PdIndex - The index for PE.

    @param[in] PtIndex - The index for PE.

    @return The resulted address.
 */
UINT64
ComputeAddressFromIndexes (
    _In_ UINT32 Pml4Index,
    _In_ UINT32 PdptIndex,
    _In_ UINT32 PdIndex,
    _In_ UINT32 PtIndex
    );

/*!
    @brief Returns the access right of the segment specified by the SegmentSelector
        for VMX.

    @param[in] SegmentSelector - The segment selector value.

    @return The access right of the segment for VMX.
 */
UINT32
GetSegmentAccessRight (
    _In_ UINT16 SegmentSelector
    );

/*!
    @brief Returns the base address of the segment specified by SegmentSelector.

    @param[in] DescriptorTableBase - The address of the base of the descriptor
        table.

    @param[in] SegmentSelector - The segment selector which points to the
        segment descriptor to retrieve the base address from.

    @return The base address of the segment specified by SegmentSelector.
 */
UINT64
GetSegmentBase (
    _In_ UINT64 DescriptorTableBase,
    _In_ UINT16 SegmentSelector
    );

/*!
    @brief Returns the CR0 value after the FIXED0 and FIXED1 MSR values are applied.

    @param[in] Cr0 - The CR0 value to apply the FIXED0 and FIXED1 MSR values.

    @return The CR0 value where the FIXED0 and FIXED1 MSR values are applied.
 */
CR0
AdjustCr0 (
    _In_ CR0 Cr0
    );

/*!
    @brief Returns the CR4 value after the FIXED0 and FIXED1 MSR values are applied.

    @param[in] Cr4 - The CR4 value to apply the FIXED0 and FIXED1 MSR values.

    @return The CR4 value where the FIXED0 and FIXED1 MSR values are applied.
 */
CR4
AdjustCr4 (
    _In_ CR4 Cr4
    );

/*!
    @brief Tests whether the specified hypervisor is installed on the system.

    @return TRUE when a specified hypervisor is installed on the system; otherwise FALSE.
 */
_Must_inspect_result_
BOOLEAN
IsHypervisorPresent (
    _In_ CONST CHAR* HyperVisorName
    );
