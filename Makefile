LIBPE_DIR = lib/libpe
PEV_DIR = src
VERSION = 0.81
ZIPDIR = pev-$(VERSION)-win
ZIPFILE = $(ZIPDIR).zip

all:
%:
	cd $(LIBPE_DIR) && $(MAKE) $@
	cd $(PEV_DIR) && $(MAKE) $@

# Cygwin only
zip:
	cd $(PEV_DIR)/windows && $(MAKE)
	mkdir -p $(ZIPDIR)/plugins
	cp src/build/plugins/*.dll $(ZIPDIR)/plugins/
	echo -ne "plugins_dir=plugins\r\n" > $(ZIPDIR)/pev.conf
	cp $(PEV_DIR)/userdb.txt $(ZIPDIR)
	cp lib/libpe/libpe.dll $(ZIPDIR)/
	cp /usr/bin/cygwin1.dll $(ZIPDIR)/
	cp /usr/bin/cygcrypto-1*.dll $(ZIPDIR)/
	cp /usr/bin/cygz.dll $(ZIPDIR)/
	cp README.md $(ZIPDIR)/
	cp $(PEV_DIR)/build/*.exe $(ZIPDIR)/
	cp $(PEV_DIR)/windows/run.bat $(ZIPDIR)/
	zip -r $(ZIPFILE) $(ZIPDIR)/*
	rm -rf $(ZIPDIR)
