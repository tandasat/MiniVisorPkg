/*!
    @file WinLogger.c

    @brief Windows specific implementation of the logger.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "WinLogger.h"
#include "WinPlatform.h"

//
// Tells the CRT not to use a inline version of CRT functions, which use
// internal functions that lead to linker errors.
//
#define _NO_CRT_STDIO_INLINE

#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include <ntintsafe.h>

//
// "Error annotation: Must succeed pool allocations are forbidden. Allocation
//  failures cause a system crash."
//
#pragma warning(disable: __WARNING_ERROR)

//
// The pool tag for logging.
//
#define LOGGER_POOL_TAG     ((ULONG)'rgoL')

NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName (
    _In_ PEPROCESS Process
    );

//
// The maximum characters the DbgPrint family can handle at once.
//
#define LOGGER_MAX_DBGPRINT_LENGTH  512

//
// The format of a single debug log message stored in DEBUG_LOG_BUFFER::LogEntries.
//
#include <pshpack1.h>
typedef struct _DEBUG_LOG_ENTRY
{
    //
    // The system time of when this message is seen in the debug print callback.
    //
    LARGE_INTEGER Timestamp;

    //
    // The level of this message.
    //
    LOG_LEVEL Level;

    //
    // The number of the processor which generated this message.
    //
    ULONG ProcessorNumber;

    //
    // The process and thread IDs which generated this message.
    //
    CLIENT_ID ClientId;

    //
    // The name of the process which generated this message.
    //
    CHAR ProcessName[16];

    //
    // The name of the function where generated this message.
    //
    CHAR FunctionName[32];

    //
    // The length of the message stored in LogMessage in characters.
    //
    USHORT LogMessageLength;

    //
    // The debug log message, not including terminating null.
    //
    CHAR LogMessage[ANYSIZE_ARRAY];
} DEBUG_LOG_ENTRY;
#include <poppack.h>

//
// The active and inactive buffer layout.
//
typedef struct _DEBUG_LOG_BUFFER
{
    //
    // The pointer to the buffer storing the sequence of DEBUG_LOG_ENTRYs (it is
    // not a pointer to a single entry or an array of entries either).
    //
    DEBUG_LOG_ENTRY* LogEntries;

    //
    // The offset to the address where the next DEBUG_LOG_ENTRY should be saved,
    // counted from LogEntries.
    //
    UINT64 NextLogOffset;

    //
    // How many bytes are not saved into LogEntries due to lack of space.
    //
    SIZE_T OverflowedLogSize;
} DEBUG_LOG_BUFFER;

//
// The pair of log buffers used to save log messages in memory.
//
typedef struct _PAIRED_DEBUG_LOG_BUFFER
{
    //
    // Indicates whether ActiveLogBuffer and InactiveLogBuffer are usable.
    //
    BOOLEAN BufferValid;

    //
    // The lock must be held before accessing any other fields of this structure.
    //
    SPIN_LOCK ActiveLogBufferLock;

    //
    // The size of ActiveLogBuffer and InactiveLogBuffer.
    //
    SIZE_T BufferSize;

    //
    // The maximum size of overflow observed during use of this
    // PAIRED_DEBUG_LOG_BUFFER. Useful to know how much BufferSize should be
    // increased.
    //
    SIZE_T MaxOverflowedLogSize;

    //
    // The pointers to two buffers: active and inactive. Active buffer is used
    // to save new messages as they comes in. Inactive buffer is buffer accessed
    // and cleared up by the flush buffer thread. The flush buffer thread switches
    // them before flushing so that duration lock is held remains minimum.
    //
    DEBUG_LOG_BUFFER* ActiveLogBuffer;
    DEBUG_LOG_BUFFER* InactiveLogBuffer;

    //
    // Actual log buffers. Those are pointed by ActiveLogBuffer and
    // InactiveLogBuffer.
    //
    DEBUG_LOG_BUFFER LogBuffers[2];
} PAIRED_DEBUG_LOG_BUFFER;

//
// The logger instance.
//
typedef struct _LOGGER_CONTEXT
{
    LOG_LEVEL Level;            // See LOGGER_CONFIGURATION.
    LOGGER_CONFIGURATION_FLAGS Flags;   // See LOGGER_CONFIGURATION.
    ULONG FlushIntervalInMs;    // See LOGGER_CONFIGURATION.

    //
    // The log file handle. NULL if a log file is not used.
    //
    HANDLE LogFileHandle;

    //
    // The flush buffer thread.
    //
    PKTHREAD FlushBufferThread;

    //
    // The event to tell the flush buffer thread to exit.
    //
    KEVENT ThreadExitEvent;

    //
    // The log buffers.
    //
    PAIRED_DEBUG_LOG_BUFFER PairedLogBuffer;
} LOGGER_CONTEXT;

//
// The empty logger instance. Used when the logger is initialized with
// LogLevelNone. This is never "allocated" and "freed".
//
static LOGGER_CONTEXT k_EmptyLogger = { LogLevelNone, };

//
// The string representation of the log levels.
//
static CONST PCSTR k_LogLevelStrings[] =
{
    "NON",
    "ERR",
    "WRN",
    "INF",
    "DBG",
};

//
// The global logger instance.
//
static LOGGER_CONTEXT* g_Logger;

/*!
    @brief Flushes all save log messages.

    @param[in,out] Logger - The logger instance.
 */
static
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
FlushDebugLogEntries (
    _Inout_ LOGGER_CONTEXT* Logger
    )
{
    NTSTATUS status;
    KIRQL oldIrql;
    DEBUG_LOG_BUFFER* logBufferToFlush;
    IO_STATUS_BLOCK ioStatusBlock;

    status = STATUS_SUCCESS;

    //
    // Swap active and inactive buffer.
    //
    oldIrql = AcquireSystemSpinLock(&Logger->PairedLogBuffer.ActiveLogBufferLock);
    logBufferToFlush = Logger->PairedLogBuffer.ActiveLogBuffer;
    Logger->PairedLogBuffer.ActiveLogBuffer = Logger->PairedLogBuffer.InactiveLogBuffer;
    Logger->PairedLogBuffer.InactiveLogBuffer = logBufferToFlush;
    ReleaseSystemSpinLock(&Logger->PairedLogBuffer.ActiveLogBufferLock, oldIrql);
    MV_ASSERT(Logger->PairedLogBuffer.ActiveLogBuffer !=
              Logger->PairedLogBuffer.InactiveLogBuffer);

    //
    // Iterate all saved debug log messages (if exist).
    //
    for (ULONG offset = 0; offset < logBufferToFlush->NextLogOffset; /**/)
    {
        DEBUG_LOG_ENTRY* logEntry;
        CHAR logMessage[LOGGER_MAX_DBGPRINT_LENGTH];
        CHAR logTimestamp[20];
        CHAR logLevel[5];
        CHAR logProcessorNumber[5];
        CHAR logPidTid[13];
        CHAR logProcessName[17];
        CHAR logFunctionName[34];
        ANSI_STRING tmpLogLine;
        TIME_FIELDS timeFields;
        LARGE_INTEGER localTime;
        ULONG logMessageLength;

        logTimestamp[0] = ANSI_NULL;
        logLevel[0] = ANSI_NULL;
        logProcessorNumber[0] = ANSI_NULL;
        logPidTid[0] = ANSI_NULL;
        logProcessName[0] = ANSI_NULL;
        logFunctionName[0] = ANSI_NULL;

        logEntry = (DEBUG_LOG_ENTRY*)MV_ADD2PTR(logBufferToFlush->LogEntries, offset);

        //
        // Build a temporal ANSI_STRING to stringify a non-null terminated string.
        //
        tmpLogLine.Buffer = logEntry->LogMessage;
        tmpLogLine.Length = logEntry->LogMessageLength;
        tmpLogLine.MaximumLength = logEntry->LogMessageLength;

        if (Logger->Flags.u.EnableTimestamp != FALSE)
        {
            //
            // Convert the time stamp to the local time in the human readable format.
            //
            ExSystemTimeToLocalTime(&logEntry->Timestamp, &localTime);
            RtlTimeToTimeFields(&localTime, &timeFields);
            status = RtlStringCchPrintfA(logTimestamp,
                                         RTL_NUMBER_OF(logTimestamp),
                                         "%02hd-%02hd %02hd:%02hd:%02hd.%03hd\t",
                                         timeFields.Month,
                                         timeFields.Day,
                                         timeFields.Hour,
                                         timeFields.Minute,
                                         timeFields.Second,
                                         timeFields.Milliseconds);
            if (NT_ERROR(status))
            {
                MV_ASSERT(FALSE);
                break;
            }
        }
        if (Logger->Flags.u.EnableTimestamp != FALSE)
        {
            status = RtlStringCchPrintfA(logLevel,
                                         RTL_NUMBER_OF(logLevel),
                                         "%s\t",
                                         k_LogLevelStrings[logEntry->Level]);
            if (NT_ERROR(status))
            {
                MV_ASSERT(FALSE);
                break;
            }
        }
        if (Logger->Flags.u.EnableProcessorNumber != FALSE)
        {
            status = RtlStringCchPrintfA(logProcessorNumber,
                                         RTL_NUMBER_OF(logProcessorNumber),
                                         "%lu\t",
                                         logEntry->ProcessorNumber);
            if (NT_ERROR(status))
            {
                MV_ASSERT(FALSE);
                break;
            }
        }
        if (Logger->Flags.u.EnablePidTid != FALSE)
        {
            status = RtlStringCchPrintfA(logPidTid,
                                         RTL_NUMBER_OF(logPidTid),
                                         "%5lu\t%5lu\t",
                                         HandleToULong(logEntry->ClientId.UniqueProcess),
                                         HandleToULong(logEntry->ClientId.UniqueThread));
            if (NT_ERROR(status))
            {
                MV_ASSERT(FALSE);
                break;
            }
        }
        if (Logger->Flags.u.EnableProcessName != FALSE)
        {
            status = RtlStringCchPrintfA(logProcessName,
                                         RTL_NUMBER_OF(logProcessName),
                                         "%-15s\t",
                                         logEntry->ProcessName);
            if (NT_ERROR(status))
            {
                MV_ASSERT(FALSE);
                break;
            }
        }
        if (Logger->Flags.u.EnableFunctionName != FALSE)
        {
            status = RtlStringCchPrintfA(logFunctionName,
                                         RTL_NUMBER_OF(logFunctionName),
                                         "%-32s\t",
                                         logEntry->FunctionName);
            if (NT_ERROR(status))
            {
                MV_ASSERT(FALSE);
                break;
            }
        }

        status = RtlStringCchPrintfA(logMessage,
                                     RTL_NUMBER_OF(logMessage),
                                     "%s%s%s%s%s%s%Z\r\n",
                                     logTimestamp,
                                     logLevel,
                                     logProcessorNumber,
                                     logPidTid,
                                     logProcessName,
                                     logFunctionName,
                                     &tmpLogLine);
        if (NT_ERROR(status))
        {
            //
            // This should not happen, but if it does, just discard all log
            // messages. The next attempt will very likely fail too.
            //
            MV_ASSERT(FALSE);
            break;
        }

        logMessageLength = (ULONG)strlen(logMessage);

        if (Logger->LogFileHandle != NULL)
        {
            status = ZwWriteFile(Logger->LogFileHandle,
                                 NULL,
                                 NULL,
                                 NULL,
                                 &ioStatusBlock,
                                 logMessage,
                                 logMessageLength,
                                 NULL,
                                 NULL);
            if (NT_ERROR(status))
            {
                //
                // This can happen when the system is shutting down and the file
                // system was already unmounted. Nothing we can do here.
                //
                NOTHING;
            }
        }

        logMessage[logMessageLength - 2] = '\n';
        logMessage[logMessageLength - 1] = ANSI_NULL;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", logMessage);

        //
        // Compute the offset to the next entry by adding the size of the current
        // entry.
        //
        offset += RTL_SIZEOF_THROUGH_FIELD(DEBUG_LOG_ENTRY, LogMessageLength) +
            logEntry->LogMessageLength;
    }

    //
    // If the debug log messages exist, and no error happened before, flush the
    // log file. This may fail if the file system is unmounted after the last
    // successful write..
    //
    if ((Logger->LogFileHandle != NULL) &&
        (logBufferToFlush->NextLogOffset != 0) &&
        NT_SUCCESS(status))
    {
        (VOID)ZwFlushBuffersFile(Logger->LogFileHandle, &ioStatusBlock);
    }

    //
    // Update the maximum overflow size as necessary.
    //
    Logger->PairedLogBuffer.MaxOverflowedLogSize = max(
                                    Logger->PairedLogBuffer.MaxOverflowedLogSize,
                                    logBufferToFlush->OverflowedLogSize);

    //
    // Finally, clear the previously active buffer.
    //
    logBufferToFlush->NextLogOffset = 0;
    logBufferToFlush->OverflowedLogSize = 0;
}

/*!
    @brief The entry point of the flush buffer thread. Flushes logs at interval.

    @param[in] StartContext - The logger instance.
 */
LOGGER_PAGED
static
_Function_class_(KSTART_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
LogFlushThread (
    _In_ VOID* StartContext
    )
{
    NTSTATUS status;
    LOGGER_CONTEXT* logger;
    LARGE_INTEGER interval;

    PAGED_CODE();

    logger = (LOGGER_CONTEXT*)StartContext;
    interval.QuadPart = -(10000ll * logger->FlushIntervalInMs);

    do
    {
        //
        // Flush log buffer with interval, or exit when it is requested.
        //
        status = KeWaitForSingleObject(&logger->ThreadExitEvent,
                                       Executive,
                                       KernelMode,
                                       FALSE,
                                       &interval);
        FlushDebugLogEntries(logger);
    } while (status == STATUS_TIMEOUT);

    //
    // It is probably a programming error if non STATUS_SUCCESS is returned. Let
    // us catch that.
    //
    MV_ASSERT(status == STATUS_SUCCESS);
    PsTerminateSystemThread(status);
}

/*!
    @brief Initializes paired log buffers.

    @param[in] BufferSize - The size of each buffer to allocate.

    @param[out] PairedLogBuffer - The pointer to the paired log buffers.

    @return STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
LOGGER_INIT
static
_Must_inspect_result_
NTSTATUS
InitializePairedLogBuffer (
    _In_ SIZE_T BufferSize,
    _Out_ PAIRED_DEBUG_LOG_BUFFER* PairedLogBuffer
    )
{
    NTSTATUS status;
    DEBUG_LOG_ENTRY* logEntries1;
    DEBUG_LOG_ENTRY* logEntries2;

    RtlZeroMemory(PairedLogBuffer, sizeof(*PairedLogBuffer));

    //
    // Create paired log buffer.
    //
    logEntries1 = ExAllocatePoolWithTag(NonPagedPool, BufferSize, LOGGER_POOL_TAG);
    logEntries2 = ExAllocatePoolWithTag(NonPagedPool, BufferSize, LOGGER_POOL_TAG);
    if ((logEntries1 == NULL) || (logEntries2 == NULL))
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Initialize buffer variables, and mark the paired buffer as valid. This
    // lets the debug print callback use this paired buffer.
    //
    PairedLogBuffer->LogBuffers[0].LogEntries = logEntries1;
    PairedLogBuffer->LogBuffers[1].LogEntries = logEntries2;
    PairedLogBuffer->ActiveLogBuffer = &PairedLogBuffer->LogBuffers[0];
    PairedLogBuffer->InactiveLogBuffer = &PairedLogBuffer->LogBuffers[1];
    PairedLogBuffer->BufferSize = BufferSize;
    PairedLogBuffer->BufferValid = TRUE;

    status = STATUS_SUCCESS;

Exit:
    if (NT_ERROR(status))
    {
        if (logEntries2 != NULL)
        {
            ExFreePoolWithTag(logEntries2, LOGGER_POOL_TAG);
        }
        if (logEntries1 != NULL)
        {
            ExFreePoolWithTag(logEntries1, LOGGER_POOL_TAG);
        }
    }
    return status;
}

/*!
    @brief Cleans up paired log buffers.

    @param[in,out] PairedLogBuffer - The pointer to the paired log buffers to
        clean up.
 */
static
VOID
CleanupPairedLogBuffer (
    _Inout_ PAIRED_DEBUG_LOG_BUFFER* PairedLogBuffer
    )
{
    ExFreePoolWithTag(PairedLogBuffer->ActiveLogBuffer->LogEntries, LOGGER_POOL_TAG);
    ExFreePoolWithTag(PairedLogBuffer->InactiveLogBuffer->LogEntries, LOGGER_POOL_TAG);
}

LOGGER_INIT
_Use_decl_annotations_
NTSTATUS
InitializeLogger (
    CONST LOGGER_CONFIGURATION* Configuration
    )
{
    NTSTATUS status;
    LOGGER_CONTEXT* logger;
    HANDLE fileHandle;
    HANDLE threadHandle;

    PAGED_CODE();

    MV_ASSERT(g_Logger == NULL);

    logger = NULL;
    fileHandle = NULL;

    //
    // Return the empty logger without any initialization if LogLevelNone is
    // specified.
    //
    if (Configuration->Level == LogLevelNone)
    {
        g_Logger = &k_EmptyLogger;
        status = STATUS_SUCCESS;
        goto Exit;
    }

    MV_ASSERT(Configuration->BufferSize != 0);

    //
    // Open the log file handle if requested.
    //
    if (Configuration->FilePath != NULL)
    {
        UNICODE_STRING filePath;
        OBJECT_ATTRIBUTES objectAttributes;
        IO_STATUS_BLOCK ioStatusBlock;

        RtlInitUnicodeString(&filePath, Configuration->FilePath);
        InitializeObjectAttributes(&objectAttributes,
                                   &filePath,
                                   OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                   NULL,
                                   NULL);
        status = ZwCreateFile(&fileHandle,
                              FILE_APPEND_DATA | SYNCHRONIZE,
                              &objectAttributes,
                              &ioStatusBlock,
                              NULL,
                              FILE_ATTRIBUTE_NORMAL,
                              FILE_SHARE_READ,
                              FILE_OPEN_IF,
                              FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                              NULL,
                              0);
        if (NT_ERROR(status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "ZwCreateFile failed : %08x\n",
                       status);
            goto Exit;
        }
    }

    //
    // Create the logger instance.
    //
#pragma prefast(suppress: __WARNING_MEMORY_LEAK, "Ownership taken on success.")
    logger = ExAllocatePoolWithTag(NonPagedPool, sizeof(*logger), LOGGER_POOL_TAG);
    if (logger == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "Memory allocation failed : %Iu\n",
                   sizeof(*logger));
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(logger, sizeof(*logger));

    //
    // Initialize the created logger instance.
    //
    status = InitializePairedLogBuffer(Configuration->BufferSize,
                                       &logger->PairedLogBuffer);
    if (NT_ERROR(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "InitializePairedLogBuffer failed : %08x\n",
                   status);
        goto Exit;
    }

    logger->Level = Configuration->Level;
    logger->Flags.AsUInt32 = Configuration->Flags.AsUInt32;
    logger->FlushIntervalInMs = Configuration->FlushIntervalInMs;
    logger->LogFileHandle = fileHandle;
    KeInitializeEvent(&logger->ThreadExitEvent, SynchronizationEvent, FALSE);

    //
    // Create the log flush thread for this logger.
    //
    status = PsCreateSystemThread(&threadHandle,
                                  THREAD_ALL_ACCESS,
                                  NULL,
                                  NULL,
                                  NULL,
                                  LogFlushThread,
                                  logger);
    if (NT_ERROR(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "PsCreateSystemThread failed : %08x\n",
                   status);
        goto Exit;
    }

    //
    // Get the created thread object. This code should not fail.
    //
    status = ObReferenceObjectByHandle(threadHandle,
                                       THREAD_ALL_ACCESS,
                                       *PsThreadType,
                                       KernelMode,
                                       (VOID**)&logger->FlushBufferThread,
                                       NULL);
    MV_ASSERT(NT_SUCCESS(status));
    MV_VERIFY(NT_SUCCESS(ZwClose(threadHandle)));

    //
    // We are good. Return the handle.
    //
    g_Logger = logger;

Exit:
    if (NT_ERROR(status))
    {
        if (fileHandle != NULL)
        {
            MV_VERIFY(ZwClose(fileHandle));
        }
        if (logger != NULL)
        {
            if (logger->PairedLogBuffer.BufferValid != FALSE)
            {
                CleanupPairedLogBuffer(&logger->PairedLogBuffer);
            }
            ExFreePoolWithTag(logger, LOGGER_POOL_TAG);
        }
    }
    return status;
}

LOGGER_PAGED
_Use_decl_annotations_
VOID
CleanupLogger (
    )
{
    NTSTATUS status;
    LOGGER_CONTEXT* logger;
    SIZE_T maxOverflowedLogSize;

    PAGED_CODE();

    MV_ASSERT(g_Logger != NULL);

    logger = g_Logger;

    //
    // No need to do anything if the logger is an empty logger.
    //
    if (logger == &k_EmptyLogger)
    {
        goto Exit;
    }

    //
    // Signal the event to exit the flush buffer thread, and wait for termination.
    //
    (VOID)KeSetEvent(&logger->ThreadExitEvent, IO_NO_INCREMENT, FALSE);
    status = KeWaitForSingleObject(logger->FlushBufferThread,
                                   Executive,
                                   KernelMode,
                                   FALSE,
                                   NULL);
    MV_ASSERT(status == STATUS_SUCCESS);
    ObDereferenceObject(logger->FlushBufferThread);

    maxOverflowedLogSize = logger->PairedLogBuffer.MaxOverflowedLogSize;

    //
    // No one should be touching the log file now. Close it.
    //
    if (logger->LogFileHandle != NULL)
    {
        MV_VERIFY(NT_SUCCESS(ZwClose(logger->LogFileHandle)));
    }

    //
    // Free resources and the logger itself.
    //
    CleanupPairedLogBuffer(&logger->PairedLogBuffer);
    ExFreePoolWithTag(logger, LOGGER_POOL_TAG);

    if (maxOverflowedLogSize != 0)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "Cleaning up the logger. Max overflowed logs during the"
                   " session is %llu bytes.\n",
                   maxOverflowedLogSize);
    }

Exit:
    g_Logger = NULL;
}

/*!
    @brief Buffers the debug-level message to the paired log buffer.

    @param[in,out] Logger - The current logger instance.

    @param[in] Level - The level of the message.

    @param[in] FunctionName - The name of the function initiated this logging.

    @param[in] LogMessage - The message to save.

    @return STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
static
_Must_inspect_result_
NTSTATUS
BufferLog (
    _Inout_ LOGGER_CONTEXT* Logger,
    _In_ LOG_LEVEL Level,
    _In_ PCSTR FunctionName,
    _In_ PCSTR LogMessage
    )
{
    NTSTATUS status;
    USHORT logMessageLength;
    SIZE_T logEntrySize;
    BOOLEAN lockAcquired;
    DEBUG_LOG_ENTRY* logEntry;
    LARGE_INTEGER timestamp;
    KIRQL oldIrql;

    KeQuerySystemTime(&timestamp);

    oldIrql = 0;    // Suppress compiler false positive warning.
    lockAcquired = FALSE;

    //
    // Get the length of the message in characters.
    //
    status = RtlSizeTToUShort(strlen(LogMessage), &logMessageLength);
    if (NT_ERROR(status))
    {
        goto Exit;
    }

    logEntrySize = RTL_SIZEOF_THROUGH_FIELD(DEBUG_LOG_ENTRY, LogMessageLength) +
        logMessageLength;

    //
    // Acquire the lock to safely modify active buffer.
    //
    oldIrql = AcquireSystemSpinLock(&Logger->PairedLogBuffer.ActiveLogBufferLock);
    lockAcquired = TRUE;

    //
    // Bail out if a concurrent thread invalidated buffer.
    //
    if (Logger->PairedLogBuffer.BufferValid == FALSE)
    {
        status = STATUS_TOO_LATE;
        goto Exit;
    }

    //
    // If the remaining buffer is not large enough to save this message, count
    // up the overflowed size and bail out.
    //
    if (Logger->PairedLogBuffer.ActiveLogBuffer->NextLogOffset + logEntrySize >
        Logger->PairedLogBuffer.BufferSize)
    {
        Logger->PairedLogBuffer.ActiveLogBuffer->OverflowedLogSize += logEntrySize;
        status = STATUS_BUFFER_TOO_SMALL;
        goto Exit;
    }

    //
    // There are sufficient room to save the message. Get the address to save
    // the message within active buffer. On debug build, the address should be
    // filled with 0xff, indicating no one has yet touched there.
    //
    logEntry = (DEBUG_LOG_ENTRY*)MV_ADD2PTR(
                        Logger->PairedLogBuffer.ActiveLogBuffer->LogEntries,
                        Logger->PairedLogBuffer.ActiveLogBuffer->NextLogOffset);

    //
    // Save this message and update the offset to the address to save the next
    // message.
    //
    logEntry->Timestamp = timestamp;
    logEntry->Level = Level;
    logEntry->ProcessorNumber = KeGetCurrentProcessorNumberEx(NULL);
    logEntry->ClientId.UniqueProcess = PsGetCurrentProcessId();
    logEntry->ClientId.UniqueThread = PsGetCurrentThreadId();
    (VOID)RtlStringCchCopyA(logEntry->ProcessName,
                            RTL_NUMBER_OF_FIELD(DEBUG_LOG_ENTRY, ProcessName),
                            PsGetProcessImageFileName(PsGetCurrentProcess()));
    (VOID)RtlStringCchCopyA(logEntry->FunctionName,
                            RTL_NUMBER_OF_FIELD(DEBUG_LOG_ENTRY, FunctionName),
                            FunctionName);
    logEntry->LogMessageLength = logMessageLength;
    RtlCopyMemory(logEntry->LogMessage, LogMessage, logMessageLength);
    Logger->PairedLogBuffer.ActiveLogBuffer->NextLogOffset += logEntrySize;

    status = STATUS_SUCCESS;

Exit:
    if (lockAcquired != FALSE)
    {
        ReleaseSystemSpinLock(&Logger->PairedLogBuffer.ActiveLogBufferLock, oldIrql);
    }
    return status;
}

_Use_decl_annotations_
VOID
LogMessage (
    LOG_LEVEL Level,
    CONST CHAR* FunctionName,
    CONST CHAR* Format,
    ...
    )
{
    NTSTATUS status;
    LOGGER_CONTEXT* logger;
    va_list args;
    CHAR logMessage[400];

    MV_ASSERT(Level != LogLevelNone);

    logger = g_Logger;

    //
    // Skip if the log is more verbose than the requested level.
    //
    if (logger->Level < Level)
    {
        status = STATUS_SUCCESS;
        goto Exit;
    }

    //
    // Build a log message string and buffer it.
    //
    va_start(args, Format);
    status = RtlStringCchVPrintfA(logMessage,
                                  RTL_NUMBER_OF(logMessage),
                                  Format,
                                  args);
    va_end(args);
    if (NT_ERROR(status))
    {
        MV_ASSERT(FALSE);
        goto Exit;
    }

    status = BufferLog(logger, Level, FunctionName, logMessage);
    if (NT_ERROR(status))
    {
        goto Exit;
    }

Exit:
    return;
}

_Use_decl_annotations_
VOID
LogEarlyErrorMessage (
    CONST CHAR* Format,
    ...
    )
{
    va_list args;

    va_start(args, Format);
    (VOID)vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, args);
    va_end(args);
}
