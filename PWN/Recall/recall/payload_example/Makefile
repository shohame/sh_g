all:
	gcc -fno-stack-protector -nostartfiles -static -Os main.c syscall.S -o payload.elf
	echo -n "deadbeef" >> ./payload.elf

.PHONY: clean
clean:
	rm -f payload.elf

