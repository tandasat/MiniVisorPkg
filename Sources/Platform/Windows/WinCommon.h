/*!
    @file WinCommon.h

    @brief Windows specific implementation of common things across the project.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include <intrin.h>
#include <ntifs.h>
#include <stdarg.h>

//
// "Error annotation: Must succeed pool allocations are forbidden. Allocation
//  failures cause a system crash."
//
#pragma warning(disable: __WARNING_ERROR)

/*!
    @brief Breaks into a debugger if present, and then triggers bug check.
 */
#define MV_PANIC() \
    MV_DEBUG_BREAK(); \
    __pragma(warning(push)) \
    __pragma(warning(disable: __WARNING_USE_OTHER_FUNCTION)) \
    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0, 0, 0, 0) \
    __pragma(warning(pop))

/*!
    @brief Breaks into a kernel debugger if present.

    @details This macro is emits software breakpoint that only hits when a
        kernel debugger is present. This macro is useful because it does not
        change the current frame unlike the DbgBreakPoint function, and
        breakpoint by this macro can be overwritten with NOP without impacting
        other breakpoints.
 */
#define MV_DEBUG_BREAK() \
    if (KD_DEBUGGER_NOT_PRESENT) \
    { \
        NOTHING; \
    } \
    else \
    { \
        __debugbreak(); \
    } \
    (VOID*)(0)

//
// The handy macros to specify in which section the code should be placed.
//
#define MV_SECTION_INIT     __declspec(code_seg("INIT"))
#define MV_SECTION_PAGED    __declspec(code_seg("PAGE"))

#define MV_ASSERT(x)        NT_ASSERT(x)
#define MV_VERIFY(x)        NT_VERIFY(x)
#define MV_MAX(x, y)        max((x), (y))
#define MV_MIN(x, y)        min((x), (y))
