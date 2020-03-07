/*!
    @file MemoryType.h

    @brief Functions for MTRR (memory type range registers) handling.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

/*!
    @brief Initializes the MTRR context.
 */
VOID
InitializeMemoryTypeMapping (
    );

/*!
    @brief Returns a memory type for the given physical address range.

    @param[in] PhysicalAddress - The physical address to retrieve its memory type.

    @param[in] RangeSize - The size of the range to check.

    @return The memory type for the given physical address. If the range contains
        more than one memory type, MEMORY_TYPE_INVALID.
 */
IA32_MEMORY_TYPE
GetMemoryTypeForRange (
    _In_ UINT64 PhysicalAddress,
    _In_ UINT64 RangeSize
    );
