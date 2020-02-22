/*!
    @file DumpActiveLogs.js

    @brief Implements the DumpActiveLogs function which dumps buffered log entries.

    @author Satoshi Tanda

    @copyright Copyright (c) 2019 - , Satoshi Tanda. All rights reserved.
 */
"use strict";

function initializeScript()
{
    return [new host.apiVersionSupport(1, 3)];
}

function invokeScript()
{
    //
    // Insert your script content here.  This method will be called whenever the script is
    // invoked from a client.
    //
    // See the following for more details:
    //
    //     https://aka.ms/JsDbgExt
    //
}

const log = x => host.diagnostics.debugLog(x + "\n");
const u64 = x => host.memory.readMemoryValues(x, 1, 8)[0];
const sizeof = x => host.evaluateExpression("sizeof(" + x + ")");
const str = (x) => host.memory.readString(x);
const strn = (x, y) => host.memory.readString(x, y);

/**
 * Returns an array of arrays of log entries where 0=ProcessName, 1=FunctionName,
 * and 2=LogMessage.
 *
 * Example:
 * kd> .scriptload C:\edk2\MiniVisorPkg\Builds\Platform\Windows\DumpActiveLogs.js
 * kd> dx Debugger.State.Scripts.DumpActiveLogs.Contents.DumpActiveLogs(),0xffff
 */
function DumpActiveLogs()
{
    let addr = host.getModuleSymbolAddress("MiniVisor", "g_Logger");
    let context = host.createPointerObject(u64(addr), "MiniVisor", "LOGGER_CONTEXT*");
    let entriesBase = context.PairedLogBuffer.ActiveLogBuffer.LogEntries;

    let logs = [];
    host.diagnostics.debugLog("Collecting buffered log entries.");
    for (let offset = 0; offset < context.PairedLogBuffer.ActiveLogBuffer.NextLogOffset; /**/)
    {
        let entry = host.createPointerObject(entriesBase.address.add(offset),
                                             "MiniVisor",
                                             "_DEBUG_LOG_ENTRY*");
        logs.push([
            str(entry.ProcessName),
            str(entry.FunctionName),
            strn(entry.LogMessage, entry.LogMessageLength),
        ]);
        offset += sizeof("_DEBUG_LOG_ENTRY") - 1 + entry.LogMessageLength;
        host.diagnostics.debugLog(".");
    }
    host.diagnostics.debugLog("\n");
    return logs;
}
