import os
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def get_exported_symbols(library_path):
    with open(library_path, 'rb') as f:
        elffile = ELFFile(f)
        exported_symbols = set()
        for section in elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    # Filter for GLOBAL symbols, exclude undefined and special linker symbols
                    if (symbol['st_info']['bind'] == 'STB_GLOBAL' and
                        symbol['st_shndx'] != 'SHN_UNDEF' and
                            not symbol.name.startswith(('_', '__'))):
                        exported_symbols.add(symbol.name)
    return exported_symbols


def check_elf_imports(elf_path, exported_symbols):
    with open(elf_path, 'rb') as f:
        elffile = ELFFile(f)
        imported_symbols = []

        dynsym = elffile.get_section_by_name('.dynsym')
        if dynsym:
            for symbol in dynsym.iter_symbols():
                if symbol.name in exported_symbols:
                    imported_symbols.append(symbol.name)
        return imported_symbols


def scan_directory_for_elf_files(directory):
    elf_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if not os.path.islink(os.path.join(root, file)):
                elf_files.append(os.path.join(root, file))
    return elf_files


def main(library_path, directory):
    exported_symbols = get_exported_symbols(library_path)

    print(f"Exported symbols in {library_path}:")
    for symbol in exported_symbols:
        print(f"  - {symbol}")

    print(f"Scanning {directory} for usage of {library_path}...")

    elf_files = scan_directory_for_elf_files(directory)

    for elf_file in elf_files:
        if not elf_file == library_path:
            try:
                imported_symbols = check_elf_imports(elf_file, exported_symbols)
                if imported_symbols:
                    print(f"{elf_file} imported the following symbols:")
                    for symbol in imported_symbols:
                        print(f"  - {symbol}")
            except Exception as e:
                pass


def parse_args():
    parser = argparse.ArgumentParser(description='Scan path for usage of library')
    parser.add_argument('library', type=str, help='library to scan for')
    parser.add_argument('path', type=str, help='The path to scan', default='.')
    args = parser.parse_args()
    if args.library is None or args.path is None:
        parser.print_help()
        exit(1)
    if not os.path.exists(args.library):
        print(f"Library {args.library} does not exist")
        exit(1)
    if not os.path.exists(args.path):
        print(f"Path {args.path} does not exist")
        exit(1)
    return args


if __name__ == '__main__':
    args = parse_args()
    main(args.library, args.path)
