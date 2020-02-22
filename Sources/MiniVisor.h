/*!
    @file MiniVisor.h

    @brief MiniVisor initialization.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

/*!
    @brief Cross platform entry point. Initializes MiniVisor.

    @return MV_STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
MV_STATUS
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
InitializeMiniVisor (
    );

/*!
    @brief Cross platform clean up entry callback entry point. Cleans up MiniVisor.
 */
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
CleanupMiniVisor (
    );
