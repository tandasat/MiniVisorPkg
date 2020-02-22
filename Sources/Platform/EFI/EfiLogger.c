/*!
    @file EfiLogger.c

    @brief EFI specific implementation of the logger.

    @details Logging becomes no-op at the runtime when UefiDebugLibConOut is used,
        ie, -D DEBUG_ON_SERIAL_PORT is not set. See use of mPostEBS in
        edk2/MdePkg/Library/UefiDebugLibConOut/DebugLib.c for this behavior.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "EfiLogger.h"
#include <Guid/EventGroup.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PrintLib.h>

//
// The event handle for ExitBootServices event subscription.
//
static EFI_EVENT g_EfiExitBootServicesEvent;

//
// FALSE during boot time. Once the system is transition to the run time, any
// EFI API that depends on boot services directly or indirectly cannot be called.
// The most significant implication is the console output cannot be used anymore.
//
static BOOLEAN g_AtRuntime;

/*!
    @brief Handles the ExitBootServices notification.

    @details The solo purpose of this handler is to report the end of console
        debug output.

    @param[in] Event - Unused.

    @param[in] Context - Unused.
 */
static
VOID
EFIAPI
ExitBootServicesHandler (
    EFI_EVENT Event,
    VOID* Context
    )
{
    LOG_INFO("ExitBootServices was called. Ending console logging if used.");
    gBS->CloseEvent(g_EfiExitBootServicesEvent);
    g_AtRuntime = TRUE;
}

/*!
    @brief Registers ExitBootServices notification.

    @return EFI_SUCCESS on success; otherwise, an appropriate error code.
 */
static
EFI_STATUS
RegisterNotification (
    )
{
    EFI_STATUS status;

    status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,
                                TPL_NOTIFY,
                                ExitBootServicesHandler,
                                NULL,
                                &gEfiEventExitBootServicesGuid,
                                &g_EfiExitBootServicesEvent);
    if (EFI_ERROR(status))
    {
        LOG_ERROR("CreateEventEx failed : %r", status);
        goto Exit;
    }

Exit:
    return status;
}

EFI_STATUS
InitializeLogger (
    )
{
    EFI_STATUS status;

    status = RegisterNotification();
    if (EFI_ERROR(status))
    {
        LOG_ERROR("RegisterNotifications failed : %r", status);
        goto Exit;
    }

Exit:
    return status;
}

VOID
CleanupLogger (
    )
{
    if (g_AtRuntime == FALSE)
    {
        gBS->CloseEvent(g_EfiExitBootServicesEvent);
    }
}

VOID
LogMessage (
    LOG_LEVEL Level,
    CONST CHAR* FunctionName,
    CONST CHAR* Format,
    ...
    )
{
    //
    // Mapping from LOG_LEVEL to the EFI log level.
    //
    static CONST UINT64 debugLevelMapping[] =
    {
        0,
        DEBUG_ERROR,
        DEBUG_WARN,
        DEBUG_INFO,
        DEBUG_VERBOSE,
    };
    C_ASSERT(RTL_NUMBER_OF(debugLevelMapping) == LogLevelReserved);

    VA_LIST args;
    CHAR8 message[400];

    VA_START(args, Format);
    (VOID)AsciiVSPrint(message, sizeof(message), Format, args);
    VA_END(args);

    DebugPrint(debugLevelMapping[Level], "%a: %a\n", FunctionName, message);
}

VOID
LogEarlyErrorMessage (
    CONST CHAR* Format,
    ...
    )
{
    VA_LIST args;

    VA_START(args, Format);
    (VOID)DebugVPrint(DEBUG_ERROR, Format, args);
    VA_END(args);
}
