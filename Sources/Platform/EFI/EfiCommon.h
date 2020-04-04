/*!
    @file EfiCommon.h

    @brief EFI specific implementation of common things across the project.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>

//
// "structure was padded due to alignment specifier"
//
#pragma warning(disable: 4324)


/*!
    @brief Freezes execution of the processor by entering infinite busy loop.
 */
#define MV_PANIC()          do { CpuDeadLoop(); } while (TRUE)
#define MV_DEBUG_BREAK()
#define MV_SECTION_INIT
#define MV_SECTION_PAGED

/*!
    @brief Custom ASSERT.

    @details This is a workaround of that the EFI standard ASSERT can cause page
        fault (null pointer access) when it fires in the host code. The author
        has not been able to find out the root cause and a fix.
 */
#if defined(MDEPKG_NDEBUG)
#define MV_ASSERT(x)
#else
#define MV_ASSERT(x) \
    do \
    { \
        if (!(x)) \
        { \
            LOG_ERROR("ASSERT %a(%d): %a", __FILE__, __LINE__, #x); \
            MV_PANIC(); \
        } \
    } while (FALSE)
#endif

#if defined(MDEPKG_NDEBUG)
#define MV_VERIFY(x)        (x)
#else
#define MV_VERIFY(x)        MV_ASSERT(x)
#endif

#define MV_MAX(x, y)        MAX((x), (y))
#define MV_MIN(x, y)        MIN((x), (y))

//
// MSVC compatibility type definitions.
//
typedef CHAR8 CHAR;
typedef CHAR16 WCHAR;
#if !defined(_MSC_VER)
#define __int64 long long
#endif

//
// MSVC intrinsics.
//
unsigned __int64 __readcr0(void);
unsigned __int64 __readcr2(void);
unsigned __int64 __readcr3(void);
unsigned __int64 __readcr4(void);
unsigned __int64 __readcr8(void);
unsigned __int64 __readdr(unsigned int);
unsigned __int64 __readeflags(void);
unsigned __int64 __readmsr(unsigned long);
unsigned char __vmx_on(unsigned __int64 *);
unsigned char __vmx_vmclear(unsigned __int64 *);
unsigned char __vmx_vmlaunch(void);
unsigned char __vmx_vmptrld(unsigned __int64 *);
unsigned char __vmx_vmread(unsigned __int64, unsigned __int64 *);
unsigned char __vmx_vmresume(void);
unsigned char __vmx_vmwrite(unsigned __int64, unsigned __int64);
unsigned long __segmentlimit(unsigned long);
void __cpuid(int[4], int);
void __cpuidex(int[4], int, int);
void __debugbreak(void);
void __invlpg(void *);
void __lidt(void *);
void __sidt(void *);
void __stosq(unsigned __int64 *, unsigned __int64, unsigned __int64);
void __vmx_off(void);
void __vmx_vmptrst(unsigned __int64 *);
void __writecr0(unsigned __int64);
void __writecr2(unsigned __int64);
void __writecr3(unsigned __int64);
void __writecr4(unsigned __int64);
void __writedr(unsigned int, unsigned __int64);
void __writemsr(unsigned long, unsigned __int64);
void _disable(void);
void _enable(void);
void _lgdt(void *);
void _sgdt(void *);
void _xsetbv(unsigned int, unsigned __int64);
unsigned char _BitScanForward64(unsigned long *, unsigned __int64);

//
// Required. Otherwise, link error occurs.
//
#pragma intrinsic(_disable)
#pragma intrinsic(_enable)

//
// MSVC compatibility macro definitions.
//
#define __drv_aliasesMem
#define __drv_allocatesMem(x)
#define __drv_freesMem(x)
#define __drv_strictTypeMatch(x)
#define _Acquires_lock_(x)
#define _In_
#define _In_opt_
#define _In_range_(x, y)
#define _In_reads_bytes_(x)
#define _In_z_
#define _Inout_
#define _IRQL_raises_(x)
#define _IRQL_requires_max_(x)
#define _IRQL_restores_
#define _IRQL_saves_
#define _Must_inspect_result_
#define _Out_
#define _Out_opt_
#define _Out_writes_bytes_(x)
#define _Post_maybenull_
#define _Post_writable_byte_size_(x)
#define _Pre_notnull_
#define _Printf_format_string_
#define _Releases_lock_(x)
#define _Requires_lock_held_(x)
#define _Requires_lock_not_held_(x)
#define _Return_type_success_(x)
#define _Success_(x)
#define _Use_decl_annotations_
#define _When_(x, y)

#define ANSI_NULL                       ((CHAR)0)
#define ANYSIZE_ARRAY                   (1)
#define ARGUMENT_PRESENT(x)             ((x) != NULL)
#define BooleanFlagOn(F,SF)             ((BOOLEAN)(((F) & (SF)) != 0))
#define BYTES_TO_PAGES(x)               EFI_SIZE_TO_PAGES(x)
#define C_ASSERT(x)                     STATIC_ASSERT(x, #x)
#define ClearFlag(_F,_SF)               ((_F) &= ~(_SF))
#define DBG_UNREFERENCED_PARAMETER(x)
#define FlagOn(_F,_SF)                  ((_F) & (_SF))
#define KERNEL_STACK_SIZE               (0x6000)
#define MAXUINT16                       MAX_UINT16
#define MAXUINT32                       MAX_UINT32
#define MAXUINT64                       MAX_UINT64
#define MAXUINT8                        MAX_UINT8
#define NOTHING
#define PAGE_ALIGN(Va)                  ((VOID*)((UINT64)(Va) & ~(PAGE_SIZE - 1)))
#define PAGE_SIZE                       EFI_PAGE_SIZE
#define PAGED_CODE()
#define RTL_NUMBER_OF(x)                ARRAY_SIZE(x)
#define RtlCopyMemory                   CopyMem
#define RtlZeroMemory                   ZeroMem
#define SetFlag(_F,_SF)                 ((_F) |= (_SF))
#define strcmp(x, y)                    AsciiStrCmp((x), (y))
#define UNREFERENCED_PARAMETER(x)
#if defined(_MSC_VER)
#define DECLSPEC_ALIGN(x)               __declspec(align(x))
#elif defined(__GNUC__)
#define DECLSPEC_ALIGN(x)               __attribute__ ((aligned(x)))
#endif
