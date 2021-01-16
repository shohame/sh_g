# The binary was compiled on ubuntu-20.04 machine.
# (You can "dokcer pull ubuntu:focal-20200606" if you want).
# Notice you need to "apt install clang-7" for the correct toolchain.
all:
	clang-7 -pedantic -Wall -fsanitize=shadow-call-stack -g -O2 src/init.c src/main.c src/instructions.c src/interpreter.c src/parse_instructions.c src/execute_instructions.c -o python4 -Iinc/ -fpie -pie

format:
	clang-format -i -style=file src/*.c inc/*.h

.PHONY: clean
clean:
	rm -f ./python4

