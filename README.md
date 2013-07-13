ministrace
==========

ministrace is a small strace implementation by @nelhage .

ministrace is a minimal implementation of strace originally about 70 lines of C. It isn't nearly as functional as the real thing, but you can use it to learn most of what you need to know about the core interfaces it uses.

Usage
=====

```ministrace [-n <system call name>|-s <system call int>] <program> <program args>```

ministrace can be run in 2 ways, simple:

```ministrace <program> <program args>```

This will print out a sequence of system calls which are referenced.


Or hard:

```ministrace -n <system call name> <program> <program args>```
```ministrace -s <system call int> <program> <program args>```

This will print out a sequence of system calls which are referenced, and block on the system call which is referenced.

