/*!
    @file Logger.h

    @brief Declarations of functions and structures for logging.

    @details Strings provided for the LOG_* macros are NOT removed from the
        release build. If you wish so, wrap them with preprocessor and make them
        no-op.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

//
// Logging chars and wide-chars require different format strings because of the
// difference of the formatting functions. Use them like the standard's PRIx macro
// family.
//
#if defined(MV_PLATFORM_WINDOWS)
#define LOG_PRIANSI     "s"
#define LOG_PRIUNICODE  "S"
#else
#define LOG_PRIANSI     "a"
#define LOG_PRIUNICODE  "s"
#endif

//
// Log levels.
//
typedef enum _LOG_LEVEL
{
    LogLevelNone,
    LogLevelError,
    LogLevelWarning,
    LogLevelInfo,
    LogLevelDebug,
    LogLevelReserved,
} LOG_LEVEL;

/*!
    @brief Logs the error message without depending on the logger to be initialized.

    @param[in] Format - The format string.
 */
#define LOG_EARLY_ERROR(Format, ...) \
    LogEarlyErrorMessage(Format ## "\n", __VA_ARGS__)

/*!
    @brief Logs the error-level message.

    @param[in] Format - The format string.
 */
#define LOG_ERROR(Format, ...) \
    LogMessage(LogLevelError, __FUNCTION__, (Format), __VA_ARGS__)

/*!
    @brief Logs the warning-level message.

    @param[in] Format - The format string.
 */
#define LOG_WARNING(Format, ...) \
    LogMessage(LogLevelWarning, __FUNCTION__, (Format), __VA_ARGS__)

/*!
    @brief Logs the information-level message.

    @param[in] Format - The format string.
 */
#define LOG_INFO(Format, ...) \
    LogMessage(LogLevelInfo, __FUNCTION__, (Format), __VA_ARGS__)

/*!
    @brief Logs the debug-level message.

    @param[in] Format - The format string.
 */
#define LOG_DEBUG(Format, ...) \
    LogMessage(LogLevelDebug, __FUNCTION__, (Format), __VA_ARGS__)

/*!
    @brief Logs the log message.

    @param[in] Level - The level of the message.

    @param[in] FunctionName - The name of the function initiated this logging.

    @param[in] Format - The format string.
 */
VOID
LogMessage (
    _In_ LOG_LEVEL Level,
    _In_ CONST CHAR* FunctionName,
    _In_ _Printf_format_string_ CONST CHAR* Format,
    ...
    );

/*!
    @brief Logs the error log message immediately.

    @param[in] Format - The format string.
 */
VOID
LogEarlyErrorMessage (
    _In_ _Printf_format_string_ CONST CHAR* Format,
    ...
    );
