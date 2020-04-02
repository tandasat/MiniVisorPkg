Testing UEFI on Hyper-V
========================

This document provides step-by-step instructions to test the UEFI version of MiniVisor on Hyper-V.

The readers are expected to be able to build MiniVisor already. If not, please go through [Building and Debugging](Building_and_Debugging.md) first.

Prerequisites
--------------

To follow this instruction, the reader must have a 64bit Windows 10 ISO image to set up a new virtual machine on Hyper-V.

Alternatively, the reader can use an existing virtual machine as long as it has the same configurations as specified in this instructions.

Overview
---------

The instructions are largely divided into the following steps:

1. Setting up a new virtual machine
2. Creating a bootable virtual drive to boot into the UEFI shell
3. Testing with the virtual machine

Setting up a New Virtual Machine
---------------------------------

1. From Hyper-V Manager, create a new machine. This instruction assumes the virtual machine is named as "Windows 10 UEFI".
    ![Testing_UEFI_on_HyperV_Setup01.png](Resources/Testing_UEFI_on_HyperV_Setup01.png)

2. Select "Generation 2".
    ![Testing_UEFI_on_HyperV_Setup02.png](Resources/Testing_UEFI_on_HyperV_Setup02.png)

3. Memory configuration can be anything. Click [Next].
    ![Testing_UEFI_on_HyperV_Setup03.png](Resources/Testing_UEFI_on_HyperV_Setup03.png)

4. Network configuration can be anything. Click [Next].
    ![Testing_UEFI_on_HyperV_Setup04.png](Resources/Testing_UEFI_on_HyperV_Setup04.png)

5. Specify the Windows 10 installation ISO file.
    ![Testing_UEFI_on_HyperV_Setup05.png](Resources/Testing_UEFI_on_HyperV_Setup05.png)

6. Click [Finish].
    ![Testing_UEFI_on_HyperV_Setup06.png](Resources/Testing_UEFI_on_HyperV_Setup06.png)

7. Disable Secure Boot before booting the virtual machine.
    ![Testing_UEFI_on_HyperV_Setup07.png](Resources/Testing_UEFI_on_HyperV_Setup07.png)

8. Start the virtual machine and boot from the ISO image.
    ![Testing_UEFI_on_HyperV_Setup08.png](Resources/Testing_UEFI_on_HyperV_Setup08.png)

9. Complete setup. There is no special requirement for Windows installation. No Windows Update is required.

10. Shutdown the virtual machine and open the settings of it.

Creating The Bootable Virtual Drive to Boot Into The UEFI Shell
----------------------------------------------------------------

1. Add a new hard drive.
    ![Testing_UEFI_on_HyperV_Setup09.png](Resources/Testing_UEFI_on_HyperV_Setup09.png)

2. Click [New].
    ![Testing_UEFI_on_HyperV_Setup10.png](Resources/Testing_UEFI_on_HyperV_Setup10.png)

3. The disk type can be anything. Click [Next].
    ![Testing_UEFI_on_HyperV_Setup11.png](Resources/Testing_UEFI_on_HyperV_Setup11.png)

4. Give the name of the disk file. This instruction assume it is named as "FAT.vhdx".
    ![Testing_UEFI_on_HyperV_Setup12.png](Resources/Testing_UEFI_on_HyperV_Setup12.png)

5. Select "Create a new blank virtual hard drive" and specify the size. 1GB is big enough.
    ![Testing_UEFI_on_HyperV_Setup13.png](Resources/Testing_UEFI_on_HyperV_Setup13.png)

6. Click [Finish].
    ![Testing_UEFI_on_HyperV_Setup14.png](Resources/Testing_UEFI_on_HyperV_Setup14.png)

    The settings should look like this.
    ![Testing_UEFI_on_HyperV_Setup15.png](Resources/Testing_UEFI_on_HyperV_Setup15.png)

7. Then, move up the new hard drive at the top of the boot order list.
    ![Testing_UEFI_on_HyperV_Setup16.png](Resources/Testing_UEFI_on_HyperV_Setup16.png)

8. Start PowerShell with the administrators privileges.

9. Run the follow command to mount the new drive.
    ```
    PS> Mount-VHD -Path "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\FAT.vhdx"
    ```

10. Open Disk Management.
    ```
    PS> diskmgmt.msc
    ```

11. It should prompt for initialization of the disk. Select "MBR (Master Boot Record)".
    ![Testing_UEFI_on_HyperV_Setup17.png](Resources/Testing_UEFI_on_HyperV_Setup17.png)

12. On Disk Management, right click the new disk and select "New Simple Volume".
    ![Testing_UEFI_on_HyperV_Setup18.png](Resources/Testing_UEFI_on_HyperV_Setup18.png)

13. Click [Next].
    ![Testing_UEFI_on_HyperV_Setup19.png](Resources/Testing_UEFI_on_HyperV_Setup19.png)

14. Click [Next].
    ![Testing_UEFI_on_HyperV_Setup20.png](Resources/Testing_UEFI_on_HyperV_Setup20.png)

15. Click [Next]. This instruction assumes the drive letter D: is assigned to it.
    ![Testing_UEFI_on_HyperV_Setup21.png](Resources/Testing_UEFI_on_HyperV_Setup21.png)

16. Format the drive with "FAT32" file system.
    ![Testing_UEFI_on_HyperV_Setup22.png](Resources/Testing_UEFI_on_HyperV_Setup22.png)

17. Click [Finish].
    ![Testing_UEFI_on_HyperV_Setup23.png](Resources/Testing_UEFI_on_HyperV_Setup23.png)

    Now, D:\ should be accessible to place files into the new hard drive.

18. Download pre-compiled the UEFI shell from the EDK2 repository ([Download](https://github.com/tianocore/edk2/raw/edk2-stable201903/ShellBinPkg/UefiShell/X64/Shell.efi)). This instruction assumes the file is downloaded as `%USERPROFILE%\Downloads\Shell.efi`

19. Deploy the UEFI shell as `Bootx64.efi`, so it can be started automatically.

    ```
    > cd /d D:\
    > mkdir EFI\Boot
    > copy %USERPROFILE%\Downloads\Shell.efi EFI\Boot\Bootx64.efi
    ```

20. Build MiniVisor and place the compiled file into the D drive.

    ```
    > cd /d C:\edk2
    > edksetup.bat
    > build -w -a X64 -t VS2019 -b NOOPT -p MiniVisorPkg\Builds\Platform\EFI\MiniVisorPkg.dsc
    > copy /y C:\edk2\Build\MiniVisor\NOOPT_VS2019\X64\MiniVisorDxe.efi D:\
    ```

22. Finally, dismount the hard drive and enable nested virtualization by running the following command on PowerShell with administrators privileges.

    ```
    > Dismount-VHD -Path "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\FAT.vhdx"
    > Set-VMProcessor -VMName "Windows 10 UEFI" -ExposeVirtualizationExtensions $true
    ```

    We are going to test MiniVisor on the virtual machine next.

Testing With The Virtual Machine
---------------------------------

1. Start the virtual machine. It should enter to the UEFI shell.
    ![Testing_UEFI_on_HyperV_Testing01.png](Resources/Testing_UEFI_on_HyperV_Testing01.png)

2. Find the file system that contains `MiniVisorDxe.efi`. In this example, it was in `fs2:`. Then load it.
    ```
    > fs2:
    > load MiniVisorDxe.efi
    ```
    ![Testing_UEFI_on_HyperV_Testing02.png](Resources/Testing_UEFI_on_HyperV_Testing02.png)

3. Then, find the file system that has the `EFI\Boot\bootx64.efi` and execute it. In this example, it was in `fs0:`.
    ```
    > fs0:
    > EFI\Boot\bootx64.efi
    ```
    ![Testing_UEFI_on_HyperV_Testing03.png](Resources/Testing_UEFI_on_HyperV_Testing03.png)

    This should boot Windows successfully.

4. Existence of MiniVisor can be confirmed with `CheckHvVendor.exe`.
    ![Testing_UEFI_on_HyperV_Testing04.png](Resources/Testing_UEFI_on_HyperV_Testing04.png)

Testing Iteration
------------------

To iterate testing workflow, build the MiniVisor then run the following command on PowerShell.
```
PS> Mount-VHD -Path "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\FAT.vhdx"
PS> Copy-Item C:\edk2\Build\MiniVisor\NOOPT_VS2019\X64\MiniVisorDxe.efi -Destination D:\
PS> Dismount-VHD -Path "C:\Users\Public\Documents\Hyper-V\Virtual hard disks\FAT.vhdx"
PS> Start-VM -Name "Windows 10 UEFI
```

This copies the newly built MiniVisorDxe.efi into the hard drive and then starts the virtual machine.

Also, to automate commands in the UEFI shell, one can place a file named `startup.nsh` containing commands in the D drive to execute automatically.

Serial Output
--------------

Just like with VMware, serial output can be used.

1. Run the following command on PowerShell with the administrators privileges.
    ```
    PS> Set-VMComPort -VMName "Windows 10 UEFI" -Path \\.\pipe\com_1 -Number 1
    ```

2. Build MiniVisor with the `-D DEBUG_ON_SERIAL_PORT` flag.
    ```
    > build -w -a X64 -t VS2019 -b NOOPT -p MiniVisorPkg\Builds\Platform\EFI\MiniVisorPkg.dsc -D DEBUG_ON_SERIAL_PORT
    ```

3. Open serial connection for `\\.\pipe\com_1` at baudrate 115200. As an example with PuTTY, it should look like this.
    ![Testing_UEFI_on_HyperV_Serial01.png](Resources/Testing_UEFI_on_HyperV_Serial01.png)

    It should show a blank screen.

4. Once the MiniVisor is loaded, serial logs should show up on the PuTTY windows.
    ![Testing_UEFI_on_HyperV_Serial02.png](Resources/Testing_UEFI_on_HyperV_Serial02.png)

Final Notes
------------

* Configure the virtual machine with a single processor. Multi processor system is unsupported.
  * This is partly because the MP protocol is not implemented on Hyper-V UEFI, but even if it were, nested virtualiation on Hyper-V does not support the wait-for-SIPI guest activity state. This is very different from any bare-metal I tested, and MiniVisor does not work on such MP systems.
  * For this reason, I strongly encourage everyone to test on VMware and bare-metal. Not working with MP system is like not working with pointer in the C programing language.

* Debugging is not as easy as the case with QEMU+KVM or VMware due to lack of GDB debugging (ie, emulation of hardware debuggers). The authors recommend using those environment instead for this reason.

* Kudos to Sinaei (@Intel80x86) for [documenting tricks to run a custome hypervisor on Hyper-V](https://rayanfam.com/topics/hypervisor-from-scratch-part-8/).
