ministrace
==========

ministrace is a small strace implementation by Nelson Elhage
(@nelhage).

ministrace is a minimal implementation of strace originally about 70
lines of C. It isn't nearly as functional as the real thing, but you
can use it to learn most of what you need to know about the core
interfaces it uses.

ministrace was written for a [blog post][1], which explains in some
detail how it works.

[1]: http://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code/

Usage
=====

```ministrace [--stop-nr <syscall nr>|--stop-name <syscall name>] <program> [<args> ...]```

Basic ministrace usage just takes a command line:

```ministrace <program> [<args> ...]```

This will run the program provided with the given arguments, and print
out a sequence of all the system calls which made by the program.

You can also specify a specific system call, using `--stop-name sys_call_name`
or `--stop-nr sys_call_number`, on which execution shall be paused:

```
ministrace --stop-name <syscall name> <program> <program args>
ministrace --stop-nr <syscall nr> <program> <program args>
```

This will print out a sequence of system calls which are made, and
block (waiting for an enter on ministrace's terminal) whenever the
program is about to execute the specified system call.
