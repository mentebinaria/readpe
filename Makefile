DEST=/usr/lib
VERSION=1.0
WARN=-W -Wall -Wextra -pedantic -std=c99
SRC=pe.c

all:
	gcc -o libpe.o -c $(WARN) -fPIC $(SRC)
	gcc -shared -Wl,-soname,libpe.so.1 -o libpe.so.$(VERSION) libpe.o

clean:
	rm -f *.so* *.o

install:
	cp libpe.so.1.0 $(DEST)
	ln -sf $(DEST)/libpe.so.$(VERSION) $(DEST)/libpe.so
	ln -sf $(DEST)/libpe.so.$(VERSION) $(DEST)/libpe.so.1

uninstall:
	rm -f $(DEST)/libpe.so.1.0
	rm -f $(DEST)/libpe.so.$(VERSION)
	rm -f $(DEST)/libpe.so.$(VERSION)
