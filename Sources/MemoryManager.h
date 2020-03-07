/*!
    @file MemoryManager.h

    @brief Functions for memory management.

    @details All API in this file are prefixed with Mm because naive names
        conflict with platform API, for example, AllocatePages and FreePages in
        EDK2.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

/*!
    @brief Allocates the requested size of memory and initialize the singleton
        memory manager instance with it.

    @param[in] PageCount - The page count to allocate for the use by the
        memory manager.

    @return MV_STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
MV_STATUS
MmInitializeMemoryManager (
    _In_ UINT32 PageCount
    );

/*!
    @brief Cleans up the memory manager.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
MmCleanupMemoryManager (
    );

/*!
    @brief Allocates page-aligned, zero-initialized physical page backed pool.

    @param[in] PageCount - The page count to allocate.

    @return The base of allocated pointer, or NULL on failure. The caller must
        free the return value with FreeSystemMemory().
 */
_Post_maybenull_
_Post_writable_byte_size_(PageCount * PAGE_SIZE)
_Must_inspect_result_
VOID*
MmAllocatePages (
    _In_ UINT8 PageCount
    );

/*!
    @brief Frees the memory allocated by AllocatePages().

    @param[in] Pages - The pointer to free.
 */
VOID
MmFreePages (
    _Pre_notnull_ VOID* Pages
    );
