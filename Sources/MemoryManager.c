/*!
    @file MemoryManager.c

    @brief Functions for memory management.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "MemoryManager.h"
#include "Platform.h"
#include "Logger.h"
#if defined(MV_PLATFORM_EFI)
#include "Platform/EFI/EfiBitmap.h"
#endif

typedef struct _MEMORY_MANAGER_CONTEXT
{
    //
    // Lock for concurrent access to the this memory manager instance.
    //
    SPIN_LOCK SpinLock;

    //
    // The number of pages reserved for use by the memory manager, and the
    // pointer to the reserved pages.
    //
    UINT32 PageCount;
    VOID* AllocatedPages;

    //
    // The bit index pointing to the bit found to be clear and used by the latest
    // allocation within AllocatedPages. The memory manager will start look for
    // the next clear bit from this index as optimization.
    //
    UINT32 LastUsedBitIndex;

    //
    // The bitmap header and actual bitmap buffer. The memory manager tracks
    // which pages within AllocatedPages are allocated for caller by setting a
    // bit to the corresponding offset in this bitmap. For example, if
    // AllocatedPages[0] to AllocatedPages[3] are allocated, bit 0-3 of the
    // bitmap are set.
    //
    RTL_BITMAP BitmapHeader;
    VOID* AllocationBitmap;

    //
    // The array of the allocated page lengths for callers. The memory manager
    // tracks how many pages are allocated by the single request by setting the
    // length in a corresponding entry in this array. For example, if the caller
    // requests 3 pages, and the memory manager finds 3 contiguous free pages at
    // AllocatedPages[0], the memory manager sets 3 to AllocationLengthMap[0].
    // This is used to know the page length from the pointer on FreePages().
    //
    UINT8* AllocationLengthMap;
} MEMORY_MANAGER_CONTEXT;

//
// The singleton instance of the memory manager.
//
static MEMORY_MANAGER_CONTEXT g_MemoryManager;

MV_SECTION_PAGED
_Use_decl_annotations_
MV_STATUS
MmInitializeMemoryManager (
    UINT32 PageCount
    )
{
    MV_STATUS status;
    VOID* pages;
    UINT32 bitmapBytesCount;
    UINT32 bitmapPagesCount;
    VOID* bitmap;
    UINT8* lengthMap;
    UINT32 lengthMapBytesCount;
    UINT32 lengthMapPagesCount;
    MEMORY_MANAGER_CONTEXT* memoryManager;

    PAGED_CODE();

    memoryManager = &g_MemoryManager;
    lengthMapPagesCount = 0;
    lengthMap = NULL;
    bitmapPagesCount = 0;
    bitmap = NULL;
    pages = NULL;

    MV_ASSERT(PageCount > 0);
    MV_ASSERT(memoryManager->PageCount == 0);

    //
    // Allocate the memory pool for the memory manager. This can be VERY large
    // memory allocation request and fail on system with little RAM.
    //
    pages = AllocateSystemMemory(PageCount);
    if (pages == NULL)
    {
        status = MV_STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Computes how many bytes are required to cover the PageCount bits,
    // round it up to the page count (as we do not have API to allocate smaller
    // granularity), then allocate the bitmap.
    //
    bitmapBytesCount = (PageCount / CHAR_BIT) +
                       ((PageCount % CHAR_BIT) != 0);
    bitmapPagesCount = BYTES_TO_PAGES(bitmapBytesCount);
    bitmap = AllocateSystemMemory(bitmapPagesCount);
    if (bitmap == NULL)
    {
        status = MV_STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Compute the how many bytes are required to make the array of UINT8s
    // (lengths) for "PageCount" entries. Then, round it up to the page count
    // and allocate it.
    //
    lengthMapBytesCount = (PageCount * sizeof(UINT8));
    lengthMapPagesCount = BYTES_TO_PAGES(lengthMapBytesCount);
    lengthMap = AllocateSystemMemory(lengthMapPagesCount);
    if (lengthMap == NULL)
    {
        status = MV_STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // All good. Initialize the memory manager instance.
    //
    status = MV_STATUS_SUCCESS;

    InitializeSystemSpinLock(&memoryManager->SpinLock);
    memoryManager->PageCount = PageCount;
    memoryManager->AllocatedPages = pages;
    memoryManager->LastUsedBitIndex = 0;
    RtlInitializeBitMap(&memoryManager->BitmapHeader, bitmap, PageCount);
    memoryManager->AllocationBitmap = bitmap;
    memoryManager->AllocationLengthMap = lengthMap;

Exit:
    if (MV_ERROR(status))
    {
        if (lengthMap != NULL)
        {
            FreeSystemMemory(lengthMap, lengthMapPagesCount);
        }
        if (bitmap != NULL)
        {
            FreeSystemMemory(bitmap, bitmapPagesCount);
        }
        if (pages != NULL)
        {
            FreeSystemMemory(pages, PageCount);
        }
    }
    return status;
}

MV_SECTION_PAGED
_Use_decl_annotations_
VOID
MmCleanupMemoryManager (
    )
{
    UINT32 bitmapBytesCount;
    UINT32 bitmapPagesCount;
    UINT32 lengthMapBytesCount;
    UINT32 lengthMapPagesCount;
    MEMORY_MANAGER_CONTEXT* memoryManager;

    PAGED_CODE();

    memoryManager = &g_MemoryManager;

    //
    // The memory manager must be initialized already.
    //
    MV_ASSERT(memoryManager->PageCount != 0);
    MV_ASSERT(memoryManager->AllocatedPages != NULL);
    MV_ASSERT(memoryManager->AllocationLengthMap != NULL);
    MV_ASSERT(memoryManager->AllocatedPages != NULL);

    //
    // All memory allocated for the callers must be freed.
    //
    MV_ASSERT(RtlAreBitsClear(&memoryManager->BitmapHeader,
                              0,
                              memoryManager->PageCount) != FALSE);

    bitmapBytesCount = (memoryManager->PageCount / CHAR_BIT) +
                       ((memoryManager->PageCount % CHAR_BIT) != 0);
    bitmapPagesCount = BYTES_TO_PAGES(bitmapBytesCount);

    lengthMapBytesCount = (memoryManager->PageCount * sizeof(UINT8));
    lengthMapPagesCount = BYTES_TO_PAGES(lengthMapBytesCount);

    FreeSystemMemory(memoryManager->AllocationBitmap,
                        bitmapPagesCount);
    FreeSystemMemory(memoryManager->AllocationLengthMap,
                        lengthMapPagesCount);
    FreeSystemMemory(memoryManager->AllocatedPages,
                        memoryManager->PageCount);

    RtlZeroMemory(memoryManager, sizeof(*memoryManager));
}

_Use_decl_annotations_
VOID*
MmAllocatePages (
    UINT8 PageCount
    )
{
    VOID* pages;
    UINT32 bitIndex;
    MEMORY_MANAGER_CONTEXT* memoryManager;
    UINT8 oldIrql;

    memoryManager = &g_MemoryManager;

    //
    // Search the contiguous free page(s) that suffices the request.
    //
    oldIrql = AcquireSystemSpinLock(&memoryManager->SpinLock);
    bitIndex = RtlFindClearBitsAndSet(&memoryManager->BitmapHeader,
                                      PageCount,
                                      memoryManager->LastUsedBitIndex);
    ReleaseSystemSpinLock(&memoryManager->SpinLock, oldIrql);

    if (bitIndex == MAXUINT32)
    {
        MV_DEBUG_BREAK();
        LOG_ERROR("Memory allocation failed : %lu", (UINT32)PageCount * PAGE_SIZE);
        pages = NULL;
        goto Exit;
    }

    //
    // Return the page(s) from the pool, and update the book keeping fields.
    //
    pages = MV_ADD2PTR(memoryManager->AllocatedPages, ((UINT64)bitIndex * PAGE_SIZE));
    memoryManager->AllocationLengthMap[bitIndex] = PageCount;
    memoryManager->LastUsedBitIndex = bitIndex;

Exit:
    return pages;
}

_Use_decl_annotations_
VOID
MmFreePages (
    VOID* Pages
    )
{
    UINT64 offsetInBytes;
    UINT32 bitIndex;
    MEMORY_MANAGER_CONTEXT* memoryManager;
    UINT8 oldIrql;
    UINT8 pageLength;

    memoryManager = &g_MemoryManager;

    //
    // The pointer must be page aligned, within the range of
    // [AllocatedPages, AllocatedPages + PageCount).
    //
    MV_ASSERT(Pages == PAGE_ALIGN(Pages));
    MV_ASSERT((UINT64)Pages >= (UINT64)memoryManager->AllocatedPages);
    MV_ASSERT((UINT64)Pages <
              (UINT64)memoryManager->AllocatedPages + ((UINT64)memoryManager->PageCount * PAGE_SIZE));

    //
    // Compute the bit index corresponds to the pointer requested for freeing,
    // and look up its length with it. The length must be more than zero, meaning
    // that the page allocated for the caller.
    //
    offsetInBytes = ((UINT64)Pages - (UINT64)memoryManager->AllocatedPages);
    bitIndex = (UINT32)(offsetInBytes / PAGE_SIZE);
    pageLength = memoryManager->AllocationLengthMap[bitIndex];
    MV_ASSERT(pageLength > 0);

    //
    // Clears the bitmap and the length to "free" the page.
    //
    oldIrql = AcquireSystemSpinLock(&memoryManager->SpinLock);
    RtlClearBits(&memoryManager->BitmapHeader, bitIndex, pageLength);
    memoryManager->AllocationLengthMap[bitIndex] = 0;
    ReleaseSystemSpinLock(&memoryManager->SpinLock, oldIrql);
}
