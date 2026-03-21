# This is probably not standardized but WorksForMe
CC = x86_64-w64-mingw32-gcc
# Very generic test file
CFLAGS += -DNDEBUG -Oz -mtune=generic -march=x86-64 -s -Wl,-s -Wl,--gc-sections

all: helloworld.exe

.PHONY: all 

helloworld: helloworld.c

%.exe: %
	mv $@ ../samples/$@

