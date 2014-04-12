LIBPE_DIR = lib/libpe
PEV_DIR = src
MAKE = make
VERSION = 0.71
ZIPFILE = pev-$(VERSION)-win32.zip

all:
%:
	cd $(LIBPE_DIR) && $(MAKE) $@
	cd $(PEV_DIR) && $(MAKE) $@

# Cygwin only
zip:
	zip -j $(ZIPFILE) lib/libpe/libpe.dll \
	/usr/bin/cygwin1.dll \
	/usr/bin/cygcrypto-1.0.0.dll /usr/bin/cygz.dll /usr/bin/cyggcc_s-1.dll \
	src/*.exe README.md
