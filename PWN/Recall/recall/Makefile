MAKEFILE_PATH = $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
LIEF_PATH = $(MAKEFILE_PATH)/libs/LIEF-0.10.1-Linux/
LIEF_LIB_PATH = $(LIEF_PATH)/lib
LIEF_INC_PATH = $(LIEF_PATH)/include

# sudo apt install libseccomp-dev
LIBS = -lLIEF -lseccomp
CFLAGS = -I$(LIEF_INC_PATH) -L$(LIEF_LIB_PATH) -Wall -O2

sandbox: sandbox.o
	g++ -o $@ $^ $(CFLAGS) $(LIBS)

sandbox.o : sandbox.c
	gcc -c -o $@ $< $(CFLAGS)

format:
	clang-format -i -style=file sandbox.c

.PHONY: clean

clean:
	rm -f sandbox sandbox.o
