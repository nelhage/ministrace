GEN_SYSCALLS=./gen_syscalls.py
LINUX_SRC=/usr/src/linux


.PHONY: all
all: ministrace

ministrace.o: syscalls.h syscallents.h

syscallents.h: $(GEN_SYSCALLS)
	$(GEN_SYSCALLS) $(LINUX_SRC)

.PHONY: clean
clean:
	@$(RM) ministrace ministrace.o syscallents.h
