current_page_base = idaapi.get_reg_val('rip') & (~0xfff)
offset = 0
while idc.read_dbg_word(current_page_base - offset) != 0x5a4d:
    offset += 0x1000

image_base = current_page_base - offset
print(
    f'Base found at 0x{image_base:02X}. To load symbols, go [File] menu >'
    f' Load file > PDB file..., then set,\n'
    f'  Input file: the PDB file, for example, C:\\edk2\\MiniVisorPkg\\Builds\\x64\\UEFI\\MiniVisorDxe.pdb\n'
    f'  Address: 0x{image_base:02X}\n'
    f'and hit [OK], and then, [Yes].'
)
