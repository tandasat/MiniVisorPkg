/*!
    @file Ia32.h

    @brief Intel SDM defined constants and structures.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once

//
// "nonstandard extension used: bit field types other than int"
//
#pragma warning(disable: 4214)

//
// "nonstandard extension used: nameless struct/union"
//
#pragma warning(push)
#pragma warning(disable: 4201)
#include "ia32-doc/out/ia32.h"
#pragma warning(pop)

#if !defined(CHAR_BIT)
#define CHAR_BIT (8)
#endif

//
// The entry count within an EPT page table.
//
#define EPT_PTE_ENTRY_COUNT 512

//
// The entry counts within paging structures.
//
#define PML4_ENTRY_COUNT    512
#define PDPT_ENTRY_COUNT    512
#define PDT_ENTRY_COUNT     512
#define PT_ENTRY_COUNT      512

//
// The entry count within the IDT.
//
#define IDT_ENTRY_COUNT     256

//
// The levels of paging structures.
//
#define PT_LEVEL_PML4E      4
#define PT_LEVEL_PDPTE      3
#define PT_LEVEL_PDE        2
#define PT_LEVEL_PTE        1

//
// Bits useful for working with paging structures and EPTs.
//
#ifndef PAGE_SHIFT
#define PAGE_SHIFT          12
#endif
#define PAGE_SHIFT_2BM      21
#define PAGE_SHIFT_1GB      30
#define PAGE_MASK           (PAGE_SIZE - 1)

//
// See: 11.11.2.2 Fixed Range MTRRs
//
typedef union _IA32_MTRR_FIXED_RANGE_MSR
{
    struct
    {
        UINT8 Types[8];
    } u;
    UINT64 Flags;
} IA32_MTRR_FIXED_RANGE_MSR;

//
// See: Table 11-10. Memory Ranges That Can Be Encoded With PAT
//
typedef UINT32 IA32_MEMORY_TYPE;

typedef UINT64 VMCS_FIELD;

typedef SEGMENT_DESCRIPTOR_REGISTER_64 GDTR, IDTR;

typedef UINT32 IA32_MSR_ADDRESS;

//
// See: Table 30-1. VM-Instruction Error Numbers
//
typedef UINT32 VMX_ERROR_NUMBER;

//
// The helper structure for translating the guest physical address to the
// host physical address.
//
typedef union _ADDRESS_TRANSLATION_HELPER
{
    //
    // Indexes to locate paging-structure entries corresponds to this virtual
    // address.
    //
    struct
    {
        UINT64 Unused : 12;         //< [11:0]
        UINT64 Pt : 9;              //< [20:12]
        UINT64 Pd : 9;              //< [29:21]
        UINT64 Pdpt : 9;            //< [38:30]
        UINT64 Pml4 : 9;            //< [47:39]
    } AsIndex;

    //
    // The page offset for each type of pages. For example, for 4KB pages, bits
    // [11:0] are treated as the page offset and Mapping4Kb can be used for it.
    //
    union
    {
        UINT64 Mapping4Kb : 12;     //< [11:0]
        UINT64 Mapping2Mb : 21;     //< [20:0]
        UINT64 Mapping1Gb : 30;     //< [29:0]
    } AsPageOffset;

    UINT64 AsUInt64;
} ADDRESS_TRANSLATION_HELPER;

//
// See: Figure 7-11. 64-Bit TSS Format
//
#pragma pack(push, 1)
typedef struct _TASK_STATE_SEGMENT_64
{
    UINT32 Reserved0;
    UINT64 Rsp0;
    UINT64 Rsp1;
    UINT64 Rsp2;
    UINT64 Reserved1;
    UINT64 Ist[7];
    UINT64 Reserved3;
    UINT16 Reserved4;
    UINT16 IoMapBaseAddress;
} TASK_STATE_SEGMENT_64;
C_ASSERT(sizeof(TASK_STATE_SEGMENT_64) == 104);
#pragma pack(pop)

//
// The page-aligned, 4KB size region used as a MSR bitmap. The MSR bitmap is
// used to indicate which MSR should cause VM-exit on RDMSR and WRMSR. Each
// bit in this 4KB region represents ON or OFF of VM-exit, where 0 indicates
// not to trigger, and 1 indicates to trigger VM-exit. This hypervisor does
// not intend to handle MSR accesses and so, all bits are left as 0. It is
// important that this bitmap governs VM-exit behavior only for certain sets
// of MSRs. An access to any MSR that is not governed by this bitmap still
// causes VM-exit unconditionally. For this reason, this hypervisor still
// has RDMSR and WRMSR handling logic.
//
// See: 24.6.9 MSR-Bitmap Address
//
typedef struct _MSR_BITMAPS
{
    UINT8 ReadBitmapLow[1024];
    UINT8 ReadBitmapHigh[1024];
    UINT8 WriteBitmapLow[1024];
    UINT8 WriteBitmapHigh[1024];
} MSR_BITMAPS;
C_ASSERT(sizeof(MSR_BITMAPS) == PAGE_SIZE);

//
// ia32.h does not include a EXCEPTION_VECTOR definition for NMI. Add this.
//
#define Nmi     (EXCEPTION_VECTOR)2
