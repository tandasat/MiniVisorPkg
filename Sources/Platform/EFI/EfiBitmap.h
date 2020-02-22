/*!
    @file EfiBitmap.h

    @brief EFI specific implementation of bitmap algorithm.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "EfiCommon.h"

typedef struct _RTL_BITMAP
{
    UINT32 SizeOfBitMap;    // Number of bits in bit map
    UINT32* Buffer;         // Pointer to the bit map itself
    UINT32 NextAvailableBitIndex;   // Index of the next cleared bit
    UINT32 SetBitCount;             // Number of bits currently set
} RTL_BITMAP;

/*!
    @brief Initializes the header of a bitmap variable.

    @param[out] BitMapHeader - The pointer to the bitmap variable to initialize.

    @param[in] BitMapBuffer - The pointer to caller-allocated memory for the bitmap
        itself.

    @param[in] SizeOfBitMap - The number of bits in the bitmap.
 */
VOID
RtlInitializeBitMap (
    RTL_BITMAP* BitMapHeader,
    UINT32* BitMapBuffer,
    UINT32 SizeOfBitMap
    );

/*!
    @brief Searches for a range of clear bits of a requested size within a bitmap
        and sets all bits in the range when it has been located.

    @param[out] BitMapHeader - The pointer to the RTL_BITMAP structure that
        describes the bitmap.

    @param[in] NumberToFind - How many contiguous clear bits will satisfy this
        request.

    @param[in] HintIndex - Unused.

    @return The zero-based starting bit index for a clear bit range of the
        requested size that it set, or it returns 0xFFFFFFFF if it cannot find
        such a range within the given bitmap variable.
 */
UINT32
RtlFindClearBitsAndSet (
    RTL_BITMAP* BitMapHeader,
    UINT32 NumberToFind,
    UINT32 HintIndex
    );

/*!
    @brief Determines whether a given range of bits within a bitmap variable is
        clear.

    @param[in] BitMapHeader - The pointer to the RTL_BITMAP structure that
        describes the bitmap.

    @param[in] StartingIndex - The start of the bit range to be tested.

    @param[in] Length - How many bits to test.

    @return Whether a given range of bits within a bitmap variable is clear.
 */
BOOLEAN
RtlAreBitsClear (
    RTL_BITMAP* BitMapHeader,
    UINT32 StartingIndex,
    UINT32 Length
    );

/*!
    @brief Sets all bits in the specified range of bits in the bitmap to zero.

    @param[out] BitMapHeader - The pointer to the RTL_BITMAP structure that
        describes the bitmap.

    @param[in] StartingIndex - Unused.

    @param[in] NumberToClear - How many bits to clear.
 */
VOID
RtlClearBits (
    RTL_BITMAP* BitMapHeader,
    UINT32 StartingIndex,
    UINT32 NumberToClear
    );
