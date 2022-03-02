#!/usr/bin/env python3

'''
Generates header file containing information for syscalls

TODOs: - Improve parsing for ARM (`Some syscalls have missing args`; overview: https://thog.github.io/syscalls-table-aarch64/latest.html)
       - Add exceptions for args which should be pointers (but are of type unsigned long ?), e.g., `mmap`, `mprotect`. ... ??
       - Return values of are always treated as int (e.g., `mmap`)
'''
import os
import sys
import re
import subprocess
from typing import Callable


# --- Globals ---
# - Linux src -
LINUX_SRC_PARSING_ARCH_SPECIFIC = {
    'x86_64': {
        'tbl_file': "./arch/x86/entry/syscalls/syscall_64.tbl",
        'src_dirs': ['arch/x86'],
        'compat_abi': "x32",
        'preprocess_src_callback': None
    },
    'i386': {
        'tbl_file': "./arch/x86/entry/syscalls/syscall_32.tbl",
        'src_dirs': ['arch/x86'],
        'compat_abi': None,              # ??
        'preprocess_src_callback': None
    },
    'aarch64': {
        'tbl_file': "./arch/arm/tools/syscall.tbl",
        'src_dirs': ['arch/arm64'],
        'compat_abi': None,              # ??
        'preprocess_src_callback': lambda code_fragment: code_fragment if "arg_u32p" not in code_fragment else
            re.sub(r"arg_u32p\((.+?)\)", r"u32, \1_lo, u32, \1_hi", code_fragment)   # Little endian seems to be most common ??
    }
}


# - Existing src -
GENERATED_HEADER_INCLUDE_TYPES_HEADER = "trace/internal/syscall_types.h"

class GENERATED_HEADER_STRUCT_ARG_TYPE_ENUM:
    INT = "ARG_INT"
    PTR = "ARG_PTR"
    STR = "ARG_STR"

GENERATED_HEADER_STRUCT_ARG_ARRAY_MAX_SIZE = 6


# - Generated source -
GENERATED_HEADER_SYSCALL_STRUCT_NAME = "syscall_entry"
GENERATED_HEADER_SYSCALL_ARRAY_NAME = "syscalls"

GENERATED_SRC_FILES_DEFAULT_OUTPUT_DIR = "."
GENERATED_SRC_FILENAME = 'syscallents'



# ----------------------------------------- ----------------------------------------- ----------------------------------------- -----------------------------------------
class TBLParsedSyscall:
    def __init__(self, src_file, src_line_nr, src_line,
                        number, abi, name, entry_point=None):
        self.src_file = src_file
        self.src_line_nr = src_line_nr
        self.src_line = src_line.replace("\n", "")
        self.number = int(number)
        self.abi = abi
        self.name = name
        self.entry_point = entry_point

    def __str__(self):
        return f"{self.src_file}:{self.src_line_nr}: {self.src_line}"


class SRCFoundSyscallFragment:
    def __init__(self, src_file, src_line_nr, src_line):
        self.src_file = src_file.decode("utf-8").replace("\n", "")
        self.src_line_nr = src_line_nr
        self.src_line = src_line

    def __str__(self):
        return f"{self.src_file}:{self.src_line_nr}: {self.src_line}"


class SRCParsedFoundSyscallFragment:
    def __init__(self, found_code_fragment: SRCFoundSyscallFragment, parsed_args: list):
        self.found_code_fragment = found_code_fragment
        self.parsed_args = parsed_args



def parse_syscalls_name_and_nr_from_tbl(tbl_file: str) -> dict:
    syscalls = {}
    for line_nr, line in enumerate( open(tbl_file) ):
        m = re.search(r'^(\d+)\t(.+?)\t(.+?)(?:\t+(.+))?$', line)       # <number> <abi> <name> <entry point>
        if m:
            (nr, abi, name, entry_point) = m.groups()
            syscalls[int(nr)] = TBLParsedSyscall(
                tbl_file, line_nr, line,
                nr, abi, name, entry_point)
    return syscalls



def find_and_parse_syscalls_args_from_src(linux_src_dir: str, arch_specific_src_dirs: list, preprocess_src_callback: Callable) -> dict:
    syscalls_args = {}

    found_src_files = subprocess.Popen(["find"] +
                            [os.path.join(linux_src_dir, d) for d in
                                arch_specific_src_dirs + "fs include ipc kernel mm net security".split()] +
                            ["-name", "*.c", "-print"],
                            stdout = subprocess.PIPE).stdout

    for src_file_path in found_src_files:
        src_file = open(src_file_path.strip())

        found_start_of_syscall_code_fragment = False
        syscall_code_fragment = ''
        syscall_code_fragment_line_start = -1
        for line_nr, line in enumerate(src_file):
            line = line.strip()
            if not found_start_of_syscall_code_fragment and bool(re.search(r'SYSCALL_DEFINE\d\(', line)):   # Found new potential syscall fragment ...
                syscall_code_fragment = ''
                syscall_code_fragment_line_start = line_nr +1
                found_start_of_syscall_code_fragment = True
            if found_start_of_syscall_code_fragment:
                syscall_code_fragment += line
                if line.endswith(')'):                                                  # Found END of syscall definition
                    syscall_code_fragment = preprocess_src_callback(syscall_code_fragment) if preprocess_src_callback else syscall_code_fragment
                    (syscall_name, parsed_syscall_args) = parse_found_syscall_code_fragment(syscall_code_fragment)
                    if syscall_name is not None:

                        syscalls_args[syscall_name] = SRCParsedFoundSyscallFragment(
                            SRCFoundSyscallFragment(src_file_path, syscall_code_fragment_line_start, syscall_code_fragment),
                            parsed_syscall_args)
                    found_start_of_syscall_code_fragment = False
                    syscall_code_fragment_line_start = -1
                else:
                    syscall_code_fragment += " "                                # Append space indicating EOL ?
    return syscalls_args

def parse_found_syscall_code_fragment(syscall_code_fragment: str) -> tuple:
    (syscall_name, parsed_syscall_arg_types) = None, None

    if syscall_code_fragment.startswith('SYSCALL_DEFINE('):
        m = re.search(r'^SYSCALL_DEFINE\(([^)]+)\)\(([^)]+)\)$', syscall_code_fragment)
        if not m:
            print("Unable to parse (1):", syscall_code_fragment, file=sys.stderr)
            return (None, None)
        syscall_name, args = m.groups()
        parsed_syscall_arg_types = [s.strip().rsplit(" ", 1)[0] for s in args.split(",")]
    else:
        m = re.search(r'^(?:COMPAT_)?SYSCALL_DEFINE(\d)\(([^,]+)\s*(?:,\s*([^)]+))?\)$', syscall_code_fragment)
        if not m:
            print("Unable to parse (2):", syscall_code_fragment, file=sys.stderr)
            return (None, None)
        nargs, syscall_name, argstr = m.groups()
        if argstr is not None:
            argspec = [s.strip() for s in argstr.split(",")]
            parsed_syscall_arg_types = argspec[0:len(argspec):2]
        else:
            parsed_syscall_arg_types = []

    return (syscall_name, parsed_syscall_arg_types)
# ----------------------------------------- ----------------------------------------- ----------------------------------------- -----------------------------------------


# ----------------------------------------- ----------------------------------------- ----------------------------------------- -----------------------------------------
def generate_src_files(kernel_version: str, cpu_arch: str,
                             arch_compat_abi: str,
                             target_dir: str, src_filename: str,
                             syscalls_parsed_from_tbl: dict, syscalls_parsed_from_scr: dict) -> None:
    print(f"Writing parsed syscalls to {os.path.abspath(target_dir)}")

    generate_syscall_macro_name = lambda name, abi: f"__SNR_{'COMPAT_' if abi == arch_compat_abi else ''}{name}"
    generated_file_disclaimer = f"/*\n * Generated file (for kernel version {kernel_version} on {cpu_arch}). Do not edit manually or check in VCS.\n *\n */"

    with open(os.path.join(target_dir, src_filename + ".h"), 'w') as out_header:
        # - Header of header file -
        header_guard_name = f"{src_filename}.h".replace("-", "_").replace(".", "_").upper()

        print(generated_file_disclaimer, file=out_header)
        print("#ifndef {0}\n#define {0}\n".format(header_guard_name), file=out_header)

        print(f"#include \"{GENERATED_HEADER_INCLUDE_TYPES_HEADER}\"\n", file=out_header)

        print(f"#define TOTAL_NUM_SYSCALLS      {len(syscalls_parsed_from_tbl.keys())}", file=out_header)
        print(f"#define MAX_SYSCALL_NUM         {max(syscalls_parsed_from_tbl.keys())}", file=out_header)
        print("#define SYSCALLS_ARR_SIZE       (MAX_SYSCALL_NUM + 1)\n\n", file=out_header)

        # - Macro constants for indexing syscall array -
        print("/* -- Array index consts (see also header `<arch>-linux-gnu/asm/unistd_64.h`, e.g., for amd64 `/usr/include/x86_64-linux-gnu/asm/unistd_64.h`) -- */", file=out_header)
        for num in sorted(syscalls_parsed_from_tbl.keys()):
            syscall_name = syscalls_parsed_from_tbl[num].name
            syscall_abi = syscalls_parsed_from_tbl[num].abi
            print(f"#define {generate_syscall_macro_name(syscall_name, syscall_abi).ljust(30)} {num}", file=out_header)

        print("\n", file=out_header)

        print(f"extern const {GENERATED_HEADER_SYSCALL_STRUCT_NAME} {GENERATED_HEADER_SYSCALL_ARRAY_NAME}[];", file=out_header)

        print("\n", file=out_header)

        # - End of header file (guard) -
        print(f"#endif /* {header_guard_name} */", file=out_header)

    with open(os.path.join(target_dir, src_filename + ".c"), 'w') as out_cfile:
        print(generated_file_disclaimer, file=out_cfile)

        # - Array containing all syscalls -
        print(f"#include \"{src_filename}.h\"", file=out_cfile)

        print("\n", file=out_cfile)

        print("const %s %s[] = {" % (GENERATED_HEADER_SYSCALL_STRUCT_NAME, GENERATED_HEADER_SYSCALL_ARRAY_NAME), file=out_cfile)
        syscalls_with_no_parsed_args = False
        for num in sorted(syscalls_parsed_from_tbl.keys()):
            syscall_name = syscalls_parsed_from_tbl[num].name
            syscall_abi = syscalls_parsed_from_tbl[num].abi

            print(f"/* {syscalls_parsed_from_tbl[num]} */", file=out_cfile)

            if syscall_name in syscalls_parsed_from_scr:
                syscall_code_fragment = syscalls_parsed_from_scr[syscall_name].found_code_fragment
                parsed_syscall_args = syscalls_parsed_from_scr[syscall_name].parsed_args
                print(f"/* {syscall_code_fragment} */", file=out_cfile)
            else:
                parsed_syscall_args = ["void*"] * GENERATED_HEADER_STRUCT_ARG_ARRAY_MAX_SIZE
                syscalls_with_no_parsed_args = True
                print("/* WARNING: Found no args for syscall \"%s\", using default (all pointers) */" % (syscall_name,), file=out_cfile)

            print("  [%s] = {" % (generate_syscall_macro_name(syscall_name, syscall_abi),), file=out_cfile)
            print("    .name  = \"%s\"," % (syscall_name,), file=out_cfile)
            print("    .nargs = %d," % (len(parsed_syscall_args,)), file=out_cfile)
            out_cfile.write(   "    .args  = {")
            out_cfile.write(", ".join([parse_syscall_arg_type(t) for t in parsed_syscall_args] + ["-1"] * (6 - len(parsed_syscall_args))))  # `-1` means N/A
            out_cfile.write("}},\n")
        print("};", file=out_cfile)

        if syscalls_with_no_parsed_args:
            print("WARNING: Some syscalls have missing args", file=sys.stderr)


def parse_syscall_arg_type(arg_str: str) -> GENERATED_HEADER_STRUCT_ARG_TYPE_ENUM:
    if re.search(r'^(const\s*)?char\s*(__user\s*)?\*\s*$', arg_str):
        return GENERATED_HEADER_STRUCT_ARG_TYPE_ENUM.STR
    if arg_str.endswith('*'):
        return GENERATED_HEADER_STRUCT_ARG_TYPE_ENUM.PTR
    return GENERATED_HEADER_STRUCT_ARG_TYPE_ENUM.INT
# ----------------------------------------- ----------------------------------------- ----------------------------------------- -----------------------------------------


def main(args):
    if not args or len(args) > 2:
        print("Usage: %s /path/to/linux_src_dir [target-dir]" % (sys.argv[0],), file=sys.stderr)
        return 1

    _, _, kernel_version, _, cpu_arch = os.uname()

    arch_spec = None
    try:
        arch_spec = LINUX_SRC_PARSING_ARCH_SPECIFIC[cpu_arch]
    except KeyError:
        print(f"Err: Unsupported CPU arch ({cpu_arch})", file=sys.stderr)
        return 1

    arch_tbl_file = arch_spec['tbl_file']
    arch_specific_src_dirs = arch_spec['src_dirs']
    arch_compat_abi = arch_spec['compat_abi']
    arch_preprocess_src_callback = arch_spec['preprocess_src_callback']


    linux_src_dir = args[0]
    syscalls_parsed_from_tbl = parse_syscalls_name_and_nr_from_tbl(os.path.join(linux_src_dir, arch_tbl_file))
    syscalls_parsed_from_scr = find_and_parse_syscalls_args_from_src(linux_src_dir, arch_specific_src_dirs, arch_preprocess_src_callback)

    target_dir = args[1] if len(args) == 2 else GENERATED_SRC_FILES_DEFAULT_OUTPUT_DIR
    generate_src_files(
            kernel_version, cpu_arch,
            arch_compat_abi,
            target_dir, GENERATED_SRC_FILENAME,
            syscalls_parsed_from_tbl, syscalls_parsed_from_scr)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
