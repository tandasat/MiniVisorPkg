/*!
    @file EfiLogger.h

    @brief EFI specific implementation of the logger.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "../../Logger.h"

/*!
    @brief Initializes the global logger.

    @return EFI_SUCCESS on success; otherwise, an appropriate error code.
 */
EFI_STATUS
InitializeLogger (
    );

/*!
    @brief Clean up the logger.
 */
VOID
CleanupLogger (
    );
