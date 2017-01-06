# Debian-like: apt-get install docbook docbook-xsl xsltproc fop
# MacPorts: port install docbook-xsl libxslt fop

PLATFORM_OS := $(shell uname | cut -d_ -f1)

NAME=pev-manual
ifeq ($(PLATFORM_OS), Darwin)
	XSL=/opt/local/share/xsl/docbook-xsl/html/chunk.xsl
	FOXSL=/opt/local/share/xsl/docbook-xsl/fo/docbook.xsl
else
	XSL=/usr/share/xml/docbook/stylesheet/nwalsh/html/chunk.xsl
	FOXSL=/usr/share/xml/docbook/stylesheet/nwalsh/fo/docbook.xsl
endif
SRC=manual.docbook
HTML_DIR=html
PDF_DIR=pdf
VERSION=0.80

html:
	mkdir -p $(HTML_DIR)/figures
	cp figures/*.png $(HTML_DIR)/figures/
	xsltproc -o $(HTML_DIR)/ $(XSL) $(SRC)

pdf:
	mkdir -p $(PDF_DIR)
	xsltproc -o $(NAME).fo $(FOXSL) $(SRC)
	fop $(NAME).fo -pdf $(PDF_DIR)/$(NAME)-$(VERSION).pdf

clean:
	rm -rf *.html *.pdf *.fo *~ $(HTML_DIR) $(PDF_DIR) 
