import os
import sys
import shutil

def main():
    path = sys.argv[1]
    out_dir = sys.argv[2]

    lib_files = []
    for root, _, files in os.walk(path):
        for file in files:
            if '.lib' in file:
                lib_files.append(os.path.join(root, file))

    if not os.path.exists(out_dir):
        os.mkdir(out_dir)
    for lib_file in lib_files:
        shutil.copy(lib_file, out_dir)

    print(
        'If you see link error, rebuild the project with the EDK2 build command'
        ' and try again. If you still see error, try updating dependencies.\n'
        'To do so, open the project properties, "Linker" > "Input", and update'
        ' "Additional Dependencies" with the following:'
    )
    print('    ' + ';'.join([os.path.basename(lib_file) for lib_file in lib_files]))


if __name__ == '__main__':
    main()
