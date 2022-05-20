CC ?= gcc
CFLAGS ?= -Wall -O2 -D_GNU_SOURCE -static
LDFLAGS ?= -Iinclude/ -luring

SRC := escape.c
TRGT := bin/escape bin/payload

all: $(TRGT)

bin/escape: escape.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

asm/payload.o: asm/payload.s
	nasm -f elf64 $<

bin/payload: asm/payload.o
	ld $< -o $@
	rm -f $<

clean:
	@rm -f $(TRGT)
