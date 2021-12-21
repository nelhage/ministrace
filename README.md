# ministrace v2

## 1. About
ministrace v2 (or rather *medstrace*) is a ~~small~~ medium-sized strace implementation (v1 was originally written by Nelson Elhage
(@nelhage)).

ministrace is a minimal implementation of strace originally about ~~70~~ 700
lines of C. It isn't nearly as functional as the real thing, but you
can use it to learn most of what you need to know about the core
interfaces it uses.

ministrace was written for a [blog post][1], which explains in some
detail how it works.

[1]: http://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code/

### 1.1. Version history 
* v2: Adds support for &mldr;
  * tracing multi-threaded programs
  * attaching to already running processes


## 2. Compile
* Prerequisites:
  * Installed Linux kernel sources
    * Steps for Ubuntu:
      * Add apt-sources: Software & Updates &rarr; Ubuntu Software &rarr; Tick checkbox "Source Code"
      * Install sources: `sudo apt-get source linux`
* Out-of-source build:
  1. `mkdir build && cd build`
  2. `ccmake -DCMAKE_BUILD_TYPE=Release ..` &rarr; press `c` &rarr; set `LINUX_SRC_DIR` &rarr; press `c` &rarr; press `g`
  3. `cmake --build .`
      * Executable will be in `build/src`

## 3. Basic Usage
```ministrace [--pause-snr <syscall nr>|--pause-sname <syscall name>] <program> [<args> ...]```

Basic ministrace usage just takes a command line:

```ministrace <program> [<args> ...]```

This will run the program provided with the given arguments, and print
out a sequence of all the system calls which made by the program.

You can also specify a specific system call, using `--pause-sname sys_call_name`
or `--pause-snr sys_call_number`, on which execution shall be paused:

```
ministrace --pause-sname <syscall name> <program> <program args>
ministrace --pause-snr <syscall nr> <program> <program args>
```

This will print out a sequence of system calls which are made, and
block (waiting for an enter on ministrace's terminal) whenever the
program is about to execute the specified system call.

To see all available options, use `--help`.
