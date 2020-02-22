/*!
    @file Common.h

    @brief Common things across the project.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#if defined(NTDDI_VERSION)
#include "Platform/Windows/WinCommon.h"
#else
#include "Platform/EFI/EfiCommon.h"
#endif
#include "Ia32.h"

//
// The platform agnostic status type.
//
typedef _Return_type_success_(return >= 0) long MV_STATUS;

//
// Possible status values.
//
#define MV_STATUS_SUCCESS                   ((MV_STATUS)0x00000000L)
#define MV_STATUS_UNSUCCESSFUL              ((MV_STATUS)0xC0000001L)
#define MV_STATUS_ACCESS_DENIED             ((MV_STATUS)0xC0000022L)
#define MV_STATUS_INSUFFICIENT_RESOURCES    ((MV_STATUS)0xC000009AL)
#define MV_STATUS_HV_OPERATION_FAILED       ((MV_STATUS)0xC0350071L)

//
// The status check macro(s).
//
#define MV_ERROR(Status)                    ((UINT32)(Status) >= (UINT32)0xc0000000)

//
// Computes offsets from the given pointer.
//
#define MV_ADD2PTR(Ptr, Value)              ((VOID*)((UINT8*)(Ptr) + (Value)))

//
// Hyper-V Hypervisor Top-Level Functional Specification (TLFS) related.
//
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS   ((UINT32)0x40000000)
#define CPUID_HV_INTERFACE                  ((UINT32)0x40000001)
#define CPUID_HV_MAX                        CPUID_HV_INTERFACE

//
// Indicates the invalid physical address.
//
#define MV_INVALID_PHYSICAL_ADDRESS         ((UINT64)-1)

//
// Replacement of BOOLEAN for the flag to indicate whether the operation is read
// or write.
//
typedef enum _OPERATION_TYPE
{
    OperationRead,
    OperationWrite,
} OPERATION_TYPE;

//
// The result type of Microsoft VMX-intrinsic functions.
//
typedef enum _VMX_RESULT
{
    VmxResultOk = 0,                  //!< Operation succeeded
    VmxResultErrorWithStatus = 1,     //!< Operation failed with extended status available
    VmxResultErrorWithoutStatus = 2,  //!< Operation failed without status available
} VMX_RESULT;
