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

```ministrace [-n <system call name>|-s <system call int>] <program> <program args>```

Basic ministrace usage just takes a command line:

```ministrace <program> <program args>```

This will run the program provided with the given arguments, and print
out a sequence of all the system calls which made by the program.

You can also specify a specific system call, using `-n sys_call_name`
or `-s sys_call_number`:

```
ministrace -n <system call name> <program> <program args>
ministrace -s <system call int> <program> <program args>
```

This will print out a sequence of system calls which are made, and
block (waiting for an enter on ministrace's terminal) whenever the
program is about to execute the specified system call.

## Additional features

`ministrace` is deliberately minimal, demonstrating only the bare
minimum of features necessary to understand approximately how a
program like `strace` works. If you're interested in seeing a
worked-out version with a few more of the details, @therealthingy has
[created a fork](https://github.com/therealthingy/ministrace) based on
this code base with many additional features.
