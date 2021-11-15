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
def parse_syscall_numbers_from_tbl(tbl_file):
    syscalls = {}
    for line in open(tbl_file):
        m = re.search(r'^(\d+)\t.+?\t(.+?)(\t.+)?$', line)
        if m:
            (number, name, _) = m.groups()
            number = int(number)
            syscalls[number] = name
    return syscalls



def find_and_parse_syscalls_args_from_src(linux_src_dir):
    syscalls_args = {}
    found_src_files = subprocess.Popen(["find"] +
                            [os.path.join(linux_src_dir, d) for d in
                                "arch/x86 fs include ipc kernel mm net security".split()] +
                            ["-name", "*.c", "-print"],
                            stdout = subprocess.PIPE).stdout

    for src_file_path in found_src_files:
        src_file = open(src_file_path.strip())

        syscall_code_fragment = ''
        found_start_of_syscall_code_fragment = False
        for line in src_file:
            line = line.strip()
            if not found_start_of_syscall_code_fragment and 'SYSCALL_DEFINE' in line:
                syscall_code_fragment = ''
                found_start_of_syscall_code_fragment = True
            if found_start_of_syscall_code_fragment:
                syscall_code_fragment += line
                if line.endswith(')'):                                          # Found END of syscall definition
                    parse_found_syscall_code_fragment(syscalls_args, syscall_code_fragment)
                    found_start_of_syscall_code_fragment = False
                else:
                    syscall_code_fragment += " "                                # Append space indicating EOL ?
    return syscalls_args

def parse_found_syscall_code_fragment(syscalls_args, syscall_code_fragment):
    (syscall_name, parsed_syscall_arg_types) = None, None

    if syscall_code_fragment.startswith('SYSCALL_DEFINE('):
        m = re.search(r'^SYSCALL_DEFINE\(([^)]+)\)\(([^)]+)\)$', syscall_code_fragment)
        if not m:
            # print("Unable to parse:", syscall_code_fragment)
            return
        syscall_name, args = m.groups()
        parsed_syscall_arg_types = [s.strip().rsplit(" ", 1)[0] for s in args.split(",")]
    else:
        m = re.search(r'^SYSCALL_DEFINE(\d)\(([^,]+)\s*(?:,\s*([^)]+))?\)$', syscall_code_fragment)
        if not m:
            # print("Unable to parse:", syscall_code_fragment)
            return
        nargs, syscall_name, argstr = m.groups()
        if argstr is not None:
            argspec = [s.strip() for s in argstr.split(",")]
            parsed_syscall_arg_types = argspec[0:len(argspec):2]
        else:
            parsed_syscall_arg_types = []

    syscalls_args[syscall_name] = parsed_syscall_arg_types
# ----------------------------------------- ----------------------------------------- ----------------------------------------- -----------------------------------------


# ----------------------------------------- ----------------------------------------- ----------------------------------------- -----------------------------------------
def generate_syscalls_header(syscall_header_file, sys_info, syscalls_numbers, syscalls_args):
    out = open(syscall_header_file, 'w')


  # - Header of header file -
    header_guard_text = syscall_header_file.replace("-", "_").replace(".", "_").upper()
    print("/**\n * Generated file (don't check in VCS) containing all syscalls\n * MUST MATCH KERNEL VERSION OF SYSTEM IT'S RUNNING ON \n */\n", file=out)
    print("#ifndef {0}\n#define {0}\n".format(header_guard_text), file=out)
    print("\n#define SYSCALLS_CPU_ARCH \"%s\"\n#define SYSCALLS_KERNEL_VERSION \"%s\"\n\n#define MAX_SYSCALL_NUM %d\n\n" % (sys_info['arch'], sys_info['kernel'], max(syscalls_numbers.keys())), file=out)

  # - Array containing all syscalls -
    print("struct %s %s[] = {" % (GENERATED_HEADER_SYSCALL_STRUCT_NAME,GENERATED_HEADER_SYSCALL_ARRAY_NAME), file=out)
    syscalls_with_no_parsed_args = False
    for num in sorted(syscalls_numbers.keys()):
        syscall_name = syscalls_numbers[num]

        if syscall_name in syscalls_args:
            syscall_args = syscalls_args[syscall_name]
        else:
            syscall_args = ["void*"] * GENERATED_HEADER_STRUCT_ARG_ARRAY_MAX_SIZE
            syscalls_with_no_parsed_args = True
            print("/* WARNING: Found no args for syscall \"%s\", using default (all pointers) */" % (syscall_name,), file=out)

        print("  [%d] = {" % (num,), file=out)
        print("    .name  = \"%s\"," % (syscall_name,), file=out)
        print("    .nargs = %d," % (len(syscall_args,)), file=out)
        out.write(   "    .args  = {")
        out.write(", ".join([parse_syscall_arg_type(t) for t in syscall_args] + ["-1"] * (6 - len(syscall_args))))  # `-1` means N/A
        out.write("}},\n");
    print("};", file=out)

    print("\n\n#endif /* %s */" % (header_guard_text,), file=out)


    out.close()

    if syscalls_with_no_parsed_args:
        print("WARNING: Some syscalls have missing args", file=sys.stderr)

def parse_syscall_arg_type(arg_str):
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
    parsed_syscalls_name_number = parse_syscall_numbers_from_tbl(os.path.join(linux_src_dir, tbl_file_basedir, tbl_file))
    parsed_syscalls_args = find_and_parse_syscalls_args_from_src(linux_src_dir)

    generate_syscalls_header(GENERATED_HEADER_FILE,
            { "arch": cpu_arch, "kernel": kernel_version },
            parsed_syscalls_name_number, parsed_syscalls_args)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
