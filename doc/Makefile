# apt-get install docbook docbook-xsl xsltproc fop

NAME=pev-manual
XSL=/usr/share/xml/docbook/stylesheet/nwalsh/html/chunk.xsl
FOXSL=/usr/share/xml/docbook/stylesheet/nwalsh/fo/docbook.xsl
SRC=pev-manual.docbook
HTML_DIR=html-doc
PDF_DIR=pdf-doc
VERSION=0.60

html:
	mkdir -p $(HTML_DIR)
	xsltproc -o $(HTML_DIR)/ $(XSL) $(SRC)

pdf:
	mkdir -p $(PDF_DIR)
	xsltproc -o $(NAME).fo $(FOXSL) $(SRC)
	fop $(NAME).fo -pdf $(PDF_DIR)/pev-$(VERSION)-manual-v1.0.pdf

clean:
	rm -rf *.html *.pdf *.fo *~ $(HTML_DIR) $(PDF_DIR) 
