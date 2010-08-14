CFLAGS=-Wall
GEN_TABLES=./gen_tables.py
LINUX_SRC=~/code/linux-2.6

all: ministrace

ministrace: ministrace.c syscalls.h

syscalls.h: $(GEN_TABLES)
	$(GEN_TABLES) $(LINUX_SRC)
