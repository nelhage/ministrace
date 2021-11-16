# Disable / Reenable git tracking for this Makefile (recommended when changing `LINUX_SRC`)
#		git update-index --assume-unchanged Makefile
#		git update-index --no-assume-unchanged Makefile

GEN_SYSCALLS=./gen_syscalls.py
LINUX_SRC=/usr/src/linux-5.14.9
EXE=ministrace


.PHONY: all
all: $(EXE)

$(EXE).o: syscalls.h syscallents.h

syscallents.h: $(GEN_SYSCALLS)
	@$(GEN_SYSCALLS) $(LINUX_SRC)


.PHONY: clean
clean:
	@$(RM) $(EXE) $(EXE).o syscallents.h
