CFLAGS=-Wall -m32
GEN_TABLES=./gen_tables.py
LINUX_SRC=~/code/linux-2.6

all: ministrace

ministrace.o: syscalls.h syscallents.h

syscallents.h: $(GEN_TABLES)
	$(GEN_TABLES) $(LINUX_SRC)
