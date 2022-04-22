# ministrace v2

## 1. About
*ministrace* v2 (or rather *medstrace*) is a ~~small~~ medium-sized `strace`(1) implementation (v1 was originally written by Nelson Elhage
(@nelhage)).

*ministrace* is a minimal implementation of `strace`(1) originally about ~~70~~ 700+
lines of C. It isn't nearly as functional as the real thing, but you
can use it to learn most of what you need to know about the core
interfaces it uses.

ministrace was written for a [blog post][1], which explains in some
detail how it works.

[1]: http://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code/

### 1.1. Version history
* v2: Adds support for &mldr;
  * passing signals to tracee(s)
  * daemon mode
  * tracing multi-threaded programs
  * attaching to already running processes
  * stack unwinding

### 1.2. TODOs / Known issues
* See [main.c](src/main.c)


## 2. Build
### 2.1. Prerequisites
* Downloaded ***Linux kernel sources*** (required for parsing syscalls)
  * Steps for Ubuntu:
    * Add apt-sources: Software & Updates &rarr; Ubuntu Software &rarr; Tick checkbox "Source Code" (or uncomment corresponding `#deb-src` in `/etc/apt/sources.list`)
    * Install sources (e.g., in `/usr/src`): `sudo apt source linux`
* Installed ***cmake*** & ccmake (Note: ccmake is optional):
    * Debian/Ubuntu: `sudo apt install -y cmake cmake-curses-gui`
* Requirements based on chosen cmake options:
  * Option `WITH_STACK_UNWINDING`: Requires *libunwind*, *libiberty* and *libdwfl* (for Debian based systems: `sudo apt install -y libunwind-dev libiberty-dev libdw-dev`)


### 2.3. Out-of-source build
1. `mkdir build && cd build`
2. `ccmake -DCMAKE_BUILD_TYPE=Release ..` &rarr; press `c` &rarr; set `LINUX_SRC_DIR` (to downloaded Linux kernel sources) &rarr; press `c` &rarr; press `g`
3. `cmake --build .`
    * Executable will be in `build/src`


## 3. Basic Usage
```ministrace [--pause-snr <syscall nr>|--pause-sname <syscall name>] <program> [<args> ...]```

Basic ministrace usage just takes a command line:

```ministrace <program> [<args> ...]```

This will run the program provided with the given arguments, and print
out a sequence of all the system calls made by the program.

To see all available options, use `--help`.
