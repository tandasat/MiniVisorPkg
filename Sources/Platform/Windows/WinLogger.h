/*!
    @file WinLogger.h

    @brief Windows specific implementation of the logger.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "../../Logger.h"

//
// The handy macros to specify in which section the code should be placed.
//
#define LOGGER_INIT  __declspec(code_seg("INIT"))
#define LOGGER_PAGED __declspec(code_seg("PAGE"))

//
// Extended configuration flags.
//
typedef union _LOGGER_CONFIGURATION_FLAGS
{
    struct
    {
        UINT32 EnableTimestamp : 1;
        UINT32 EnableLevel : 1;
        UINT32 EnableProcessorNumber : 1;
        UINT32 EnablePidTid : 1;
        UINT32 EnableProcessName : 1;
        UINT32 EnableFunctionName : 1;
    } u;

    UINT32 AsUInt32;
} LOGGER_CONFIGURATION_FLAGS;

//
// The configurations of the logger to initialize.
//
typedef struct _LOGGER_CONFIGURATION
{
    //
    // The maximum level of the log this logger will log. For example, the
    // information-level logs are discarded when LogLevelWarning is specified.
    // If LogLevelNone is set, the logger is disabled and none of logs are logged.
    //
    LOG_LEVEL Level;

    //
    // Extended configuration flags.
    //
    LOGGER_CONFIGURATION_FLAGS Flags;

    //
    // An interval to flush logs saved into log message buffer.
    //
    UINT32 FlushIntervalInMs;

    //
    // A size of log message buffer. The logger internally allocates two buffers
    // with this size.
    //
    SIZE_T BufferSize;

    //
    // The path to the file to save logs. The logger do not save logs into a file
    // when NULL is specified.
    //
    PCWSTR FilePath;
} LOGGER_CONFIGURATION;

_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
InitializeLogger (
    _In_ CONST LOGGER_CONFIGURATION* Configuration
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
CleanupLogger (
    );
