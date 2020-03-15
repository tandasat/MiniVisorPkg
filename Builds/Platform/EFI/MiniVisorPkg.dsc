[Defines]
  DSC_SPECIFICATION              = 1.28
  PLATFORM_NAME                  = MiniVisor
  PLATFORM_GUID                  = F12E3CB1-C7C0-4EED-9E78-D144A1A09F98
  PLATFORM_VERSION               = 1.00
  OUTPUT_DIRECTORY               = Build/MiniVisor
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLibDevicePathProtocol/UefiDevicePathLibDevicePathProtocol.inf
!if $(TARGET) == RELEASE
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
!else
  !ifdef $(DEBUG_ON_SERIAL_PORT)
    IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsicSev.inf
    SerialPortLib|PcAtChipsetPkg/Library/SerialIoLib/SerialIoLib.inf
    DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
  !else
    DebugLib|MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
  !endif
!endif
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf

[LibraryClasses.common.DXE_RUNTIME_DRIVER]
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibOptDxe/BaseMemoryLibOptDxe.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf

[PcdsFixedAtBuild]
  # Define DEBUG_ERROR | DEBUG_VERBOSE | DEBUG_INFO | DEBUG_WARN to enable
  # logging at those levels. Also, define DEBUG_PROPERTY_ASSERT_DEADLOOP_ENABLED
  # and such. Assertion failure will call CpuDeadLoop.
  # https://github.com/tianocore/tianocore.github.io/wiki/EDK-II-Debugging
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80400042
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x2f

[Components]
  MiniVisorPkg/Builds/Platform/EFI/MiniVisorDxe.inf
