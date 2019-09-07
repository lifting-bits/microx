CC=clang

TARGETS=simplec.elf simpleasm.elf

.PHONY: all clean

all: $(TARGETS)


simplec.elf: simple.c
	$(CC) -m32 -O0 -o $@ $<

simpleasm.elf: simple.asm
	$(CC) -m32 -o $@ $<

clean:
	rm -f $(TARGETS)