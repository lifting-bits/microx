CC=clang
ASM=nasm

TARGETS=simplec.elf simpleasm.elf

.PHONY: all clean

all: $(TARGETS)


simplec.elf: simple.c
	$(CC) -m32 -O0 -o $@ $<

simpleasm.elf: simple.asm
	$(ASM) -f elf32 -o $@ $<

clean:
	rm -f $(TARGETS)