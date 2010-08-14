#!/usr/bin/env python
import os
import sys
import re

def do_syscall_numbers(unistd_h, syscalls_h):
    syscalls = {}
    for line in open(unistd_h):
        m = re.search(r'^#define\s*__NR_(\w+)\s*(\d+)', line)
        if m:
            (name, number) = m.groups()
            number = int(number)
            syscalls[number] = name

    out = open(syscalls_h, 'w')

    print >>out, "#define MAX_SYSCALL_NUM %d" % (max(syscalls.keys()),)
    print >>out, "char *syscall_names[] = {"
    for num in sorted(syscalls.keys()):
        print >>out, "  [%d] = \"%s\"," % (num, syscalls[num])
    print >>out, "};"
    out.close()

def main(args):
    if not args:
        print >>sys.stderr, "Usage: %s /path/to/linux-2.6" % (sys.argv[0],)
        return 1
    linux_dir = args[0]
    return do_syscall_numbers(os.path.join(linux_dir, "arch/x86/include/asm/unistd_32.h"),
                              "syscalls.h")

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
