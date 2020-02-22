/*!
    @file EfiBitmap.c

    @brief EFI specific implementation of bitmap algorithm.

    @details Implementation of algorithm is good enough for the current use of
        those API but is incomplete and broken, for example, bits are NEVER
        reused once they are set, even after they are "cleared".

        For complete implementation, one can copy ReactOS's implementation if
        licensing the project under GPL is acceptable. hvpp by wbenny has its own
        implementation of bitmap but is actually influenced by ReactOS
        implementation and such should be treated as GPL.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "EfiBitmap.h"

VOID
RtlInitializeBitMap (
    RTL_BITMAP* BitMapHeader,
    UINT32* BitMapBuffer,
    UINT32 SizeOfBitMap
    )
{
    BitMapHeader->SizeOfBitMap = SizeOfBitMap;
    BitMapHeader->Buffer = BitMapBuffer;
    BitMapHeader->NextAvailableBitIndex = 0;
    BitMapHeader->SetBitCount = 0;
}

UINT32
RtlFindClearBitsAndSet (
    RTL_BITMAP* BitMapHeader,
    UINT32 NumberToFind,
    UINT32 HintIndex
    )
{
    UINT32 clearBitIndex;

    //
    // Return error if the bitmap does not have enough bits after the current
    // index. In other words, it never search from the index 0 because implementation
    // never clears bits.
    //
    if (BitMapHeader->NextAvailableBitIndex + NumberToFind > BitMapHeader->SizeOfBitMap)
    {
        clearBitIndex = MAXUINT32;
        goto Exit;
    }

    //
    // "Find" clear bits, which is just using bits from the current position.
    //
    clearBitIndex = BitMapHeader->NextAvailableBitIndex;

    //
    // "Set" requested bits, which is just moving the index further.
    //
    BitMapHeader->SetBitCount += NumberToFind;
    BitMapHeader->NextAvailableBitIndex += NumberToFind;

Exit:
    return clearBitIndex;
}

BOOLEAN
RtlAreBitsClear (
    RTL_BITMAP* BitMapHeader,
    UINT32 StartingIndex,
    UINT32 Length
    )
{
    //
    // This implementation support checking only whether an entire bitmap is
    // cleared.
    //
    ASSERT(StartingIndex == 0);
    ASSERT(Length == BitMapHeader->SizeOfBitMap);

    return (BitMapHeader->SetBitCount == 0);
}

VOID
RtlClearBits (
    RTL_BITMAP* BitMapHeader,
    UINT32 StartingIndex,
    UINT32 NumberToClear
    )
{
    //
    // This implementation only change this counter, and never actually clear
    // bits and let them to be re-set.
    //
    BitMapHeader->SetBitCount -= NumberToClear;
}
