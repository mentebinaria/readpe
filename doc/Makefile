NAME=pev-manual
#XSL=/usr/share/xml/docbook/stylesheet/nwalsh/html/docbook.xsl
XSL=/usr/share/xml/docbook/stylesheet/nwalsh/html/chunk.xsl
FOXSL=/usr/share/xml/docbook/stylesheet/nwalsh/fo/docbook.xsl
SRC=pev-manual.docbook
HTML_DIR=html-doc/
PDF_DIR=pdf-doc

html:
	xsltproc -o $(HTML_DIR) $(XSL) $(SRC)
	#xsltproc -o $(NAME).html $(XSL) $(SRC)

pdf:
	xsltproc -o $(NAME).fo $(FOXSL) $(SRC)
	fop $(NAME).fo -pdf $(PDF_DIR)/pev-0.50-manual-v1.0.pdf

clean:
	rm -f *.html *.pdf *.fo html-doc/* pdf-doc/* *~ .html .fo .pdf
