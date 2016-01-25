CC=gcc
CFLAGS=-arch i386 -arch x86_64 -O3

all: stripcodesig amd_insn_patcher amd_insn_patcher_ext

amd_insn_patcher: insn_patcher.c
	$(CC) $(CFLAGS) -o $@ $<

amd_insn_patcher_ext: insn_patcher.c
	$(CC) $(CFLAGS) -DEXTENDED_PATCHER -o $@ $<

stripcodesig: insn_patcher.c
	$(CC) $(CFLAGS) -DCODESIGSTRIP -o $@ $<

clean:
	rm -f amd_insn_patcher amd_insn_patcher_ext

install: amd_insn_patcher amd_insn_patcher_ext
	cp -f amd_insn_patcher amd_insn_patcher_ext /usr/bin/

