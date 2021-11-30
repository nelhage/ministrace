#!/usr/bin/env python

'''
Generates header file containing information for syscalls

TODOs: - x32 ABI (e.g., COMPAT_SYSCALL_DEFINE3, see https://en.wikipedia.org/wiki/X32_ABI)  ??
       - Add exceptions for args which should be pointers (but are of type unsigned long ?), e.g., `mmap`, `mprotect`. ... ??
'''
import os
import sys
import re
import subprocess


# --- Globals ---
GENERATED_HEADER_FILE = 'syscallents.h'

GENERATED_HEADER_SYSCALL_STRUCT_NAME = "syscall_entry"
GENERATED_HEADER_SYSCALL_ARRAY_NAME = "syscalls"
class GENERATED_HEADER_STRUCT_ARG_TYPE_ENUM:
    INT = "ARG_INT"
    PTR = "ARG_PTR"
    STR = "ARG_STR"
GENERATED_HEADER_STRUCT_ARG_ARRAY_MAX_SIZE = 6



# ----------------------------------------- ----------------------------------------- ----------------------------------------- -----------------------------------------
class TBLParsedSyscall:
    def __init__(self, number, abi, name, entry_point=None):
        self.number = int(number)
        self.abi = abi
        self.name = name
        self.entry_point = entry_point


class SRCFoundSyscallFragment:
    def __init__(self, extracted_code_fragment, line_nr, file):
        self.extracted_code_fragment = extracted_code_fragment
        self.line_nr = line_nr
        self.file = file.decode("utf-8").replace("\n", "")

    def __str__(self):
        return f"{self.file}:{self.line_nr}: {self.extracted_code_fragment}"


class SRCParsedFoundSyscallFragment:
    def __init__(self, found_code_fragment: SRCFoundSyscallFragment, parsed_args: list):
        self.found_code_fragment = found_code_fragment
        self.parsed_args = parsed_args



def parse_syscalls_name_and_nr_from_tbl(tbl_file: str) -> dict:
    syscalls = {}
    for line in open(tbl_file):
        m = re.search(r'^(\d+)\t(.+?)\t(.+?)(?:\t+(.+))?$', line)       # <number> <abi> <name> <entry point>
        if m:
            (nr, abi, name, entry_point) = m.groups()
            syscalls[int(nr)] = TBLParsedSyscall(nr, abi, name, entry_point)
    return syscalls



def find_and_parse_syscalls_args_from_src(linux_src_dir: str) -> dict:
    syscalls_args = {}
    found_src_files = subprocess.Popen(["find"] +
                            [os.path.join(linux_src_dir, d) for d in
                                "arch/x86 fs include ipc kernel mm net security".split()] +
                            ["-name", "*.c", "-print"],
                            stdout = subprocess.PIPE).stdout

    for src_file_path in found_src_files:
        src_file = open(src_file_path.strip())

        found_start_of_syscall_code_fragment = False
        syscall_code_fragment = ''
        syscall_code_fragment_line_start = -1
        for line_nr, line in enumerate(src_file):
            line = line.strip()
            if not found_start_of_syscall_code_fragment and 'SYSCALL_DEFINE' in line:   # Found new potential syscall fragment ...
                syscall_code_fragment = ''
                syscall_code_fragment_line_start = line_nr +1
                found_start_of_syscall_code_fragment = True
            if found_start_of_syscall_code_fragment:
                syscall_code_fragment += line
                if line.endswith(')'):                                                  # Found END of syscall definition
                    (syscall_name, parsed_syscall_args) = parse_found_syscall_code_fragment(syscall_code_fragment)
                    if syscall_name is not None:
                        syscalls_args[syscall_name] = SRCParsedFoundSyscallFragment(
                            SRCFoundSyscallFragment(syscall_code_fragment, syscall_code_fragment_line_start, src_file_path),
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
            print("Unable to parse:", syscall_code_fragment, file=sys.stderr)
            return (None, None)
        syscall_name, args = m.groups()
        parsed_syscall_arg_types = [s.strip().rsplit(" ", 1)[0] for s in args.split(",")]
    else:
        m = re.search(r'^(?:COMPAT_)?SYSCALL_DEFINE(\d)\(([^,]+)\s*(?:,\s*([^)]+))?\)$', syscall_code_fragment)
        if not m:
            print("Unable to parse:", syscall_code_fragment, file=sys.stderr)
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
def generate_syscalls_header(syscall_header_file: str, sys_info: dict,
            syscalls_parsed_from_tbl: dict, syscalls_parsed_from_scr: dict) -> None:
    out = open(syscall_header_file, 'w')


  # - Header of header file -
    header_guard_text = syscall_header_file.replace("-", "_").replace(".", "_").upper()
    print("/*\n * Generated file (don't check in VCS) containing all syscalls\n * MUST MATCH KERNEL VERSION OF SYSTEM IT'S RUNNING ON \n */", file=out)
    print("#ifndef {0}\n#define {0}\n".format(header_guard_text), file=out)
    # print(f"#define SYSCALLS_CPU_ARCH \"{sys_info['arch']}\"\n#define SYSCALLS_KERNEL_VERSION \"{sys_info['kernel']}\"", file=out)
    print(f"#define MAX_SYSCALL_NUM {max(syscalls_parsed_from_tbl.keys())}", file=out)
    print(f"#define TOTAL_NUM_SYSCALLS {len(syscalls_parsed_from_tbl.keys())}\n\n", file=out)

    generate_syscall_macro_name = lambda name, abi: f"__SNR_{'x32_' if abi == 'x32' else ''}{name}"

  # - Macro constants for indexing syscall array -
    print("/* -- Array index consts (see also header file `/usr/include/x86_64-linux-gnu/asm/unistd_64.h`) -- */", file=out)
    for num in sorted(syscalls_parsed_from_tbl.keys()):
        syscall_name = syscalls_parsed_from_tbl[num].name
        syscall_abi = syscalls_parsed_from_tbl[num].abi
        print(f"#define {generate_syscall_macro_name(syscall_name, syscall_abi)} {num}", file=out)

    print("\n\n", file=out)

  # - Array containing all syscalls -
    print("/* -- Parsed syscalls as array -- */", file=out)
    print("const struct %s %s[] = {" % (GENERATED_HEADER_SYSCALL_STRUCT_NAME, GENERATED_HEADER_SYSCALL_ARRAY_NAME), file=out)
    syscalls_with_no_parsed_args = False
    for num in sorted(syscalls_parsed_from_tbl.keys()):
        syscall_name = syscalls_parsed_from_tbl[num].name
        syscall_abi = syscalls_parsed_from_tbl[num].abi

        if syscall_name in syscalls_parsed_from_scr:
            syscall_code_fragment = syscalls_parsed_from_scr[syscall_name].found_code_fragment
            parsed_syscall_args = syscalls_parsed_from_scr[syscall_name].parsed_args
            print(f"/* {syscall_code_fragment} */", file=out)
        else:
            parsed_syscall_args = ["void*"] * GENERATED_HEADER_STRUCT_ARG_ARRAY_MAX_SIZE
            syscalls_with_no_parsed_args = True
            print("/* WARNING: Found no args for syscall \"%s\", using default (all pointers) */" % (syscall_name,), file=out)

        print("  [%s] = {" % (generate_syscall_macro_name(syscall_name, syscall_abi),), file=out)
        print("    .name  = \"%s\"," % (syscall_name,), file=out)
        print("    .nargs = %d," % (len(parsed_syscall_args,)), file=out)
        out.write(   "    .args  = {")
        out.write(", ".join([parse_syscall_arg_type(t) for t in parsed_syscall_args] + ["-1"] * (6 - len(parsed_syscall_args))))  # `-1` means N/A
        out.write("}},\n");
    print("};", file=out)

  # - End of header file (guard) -
    print(f"\n#endif /* {header_guard_text} */", file=out)


    out.close()

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
    if not args or len(args) > 1:
        print("Usage: %s /path/to/linux_src_dir" % (sys.argv[0],), file=sys.stderr)
        return 1

    _, _, kernel_version, _, cpu_arch = os.uname()

    linux_src_dir = args[0]
    tbl_file_basedir = "./arch/x86/entry/syscalls/"
    tbl_file = "syscall_64.tbl" if cpu_arch == 'x86_64' else "syscall_32.tbl"

    syscalls_parsed_from_tbl = parse_syscalls_name_and_nr_from_tbl(os.path.join(linux_src_dir, tbl_file_basedir, tbl_file))
    syscalls_parsed_from_scr = find_and_parse_syscalls_args_from_src(linux_src_dir)

    generate_syscalls_header(GENERATED_HEADER_FILE,
            { "arch": cpu_arch, "kernel": kernel_version },
            syscalls_parsed_from_tbl, syscalls_parsed_from_scr)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
