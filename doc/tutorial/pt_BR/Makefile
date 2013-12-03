# apt-get install docbook docbook-xsl xsltproc fop

NAME=pev-tutorial
XSL=/usr/share/xml/docbook/stylesheet/nwalsh/html/chunk.xsl
FOXSL=/usr/share/xml/docbook/stylesheet/nwalsh/fo/docbook.xsl
SRC=tutorial.docbook
HTML_DIR=html
PDF_DIR=pdf
VERSION=1.0

html:
	mkdir -p $(HTML_DIR)
	xsltproc -o $(HTML_DIR)/ $(XSL) $(SRC)

pdf:
	mkdir -p $(PDF_DIR)
	xsltproc -o $(NAME).fo $(FOXSL) $(SRC)
	fop $(NAME).fo -pdf $(PDF_DIR)/$(NAME)-$(VERSION).pdf

clean:
	rm -rf *.html *.pdf *.fo *~ $(HTML_DIR) $(PDF_DIR) 
