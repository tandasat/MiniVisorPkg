/*!
    @file WinAsm.h

    @brief Windows specific MASM-written functions.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "WinCommon.h"

/*!
    @brief Reads the value of LDTR.

    @return The value of LDTR.
 */
UINT16
AsmReadLdtr (
    );

/*!
    @brief Reads the value of TR.

    @return The value of TR.
 */
UINT16
AsmReadTr (
    );

/*!
    @brief Reads the value of ES.

    @return The value of ES.
 */
UINT16
AsmReadEs (
    );

/*!
    @brief Reads the value of CS.

    @return The value of CS.
 */
UINT16
AsmReadCs (
    );

/*!
    @brief Reads the value of SS.

    @return The value of SS.
 */
UINT16
AsmReadSs (
    );

/*!
    @brief Reads the value of DS.

    @return The value of DS.
 */
UINT16
AsmReadDs (
    );

/*!
    @brief Reads the value of FS.

    @return The value of FS.
 */
UINT16
AsmReadFs (
    );

/*!
    @brief Reads the value of GS.

    @return The value of GS.
 */
UINT16
AsmReadGs (
    );

/*!
    @brief Writes the value to TR.

    @param[in] TaskSelector - The value to write to TR.
 */
VOID
AsmWriteTr (
    _In_ UINT16 TaskSelector
    );
