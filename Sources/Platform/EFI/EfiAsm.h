/*!
    @file EfiAsm.h

    @brief EFI specific MASM-written functions.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "EfiCommon.h"

/*!
    @brief The array of the default host exception handlers.
 */
VOID
AsmDefaultExceptionHandlers (
    VOID
    );

/*!
    @brief The host NMI handler.
 */
VOID
AsmNmiExceptionHandler (
    VOID
    );
