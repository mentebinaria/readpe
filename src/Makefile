LIBPE=../lib/libpe
LIBUDIS86=../lib/libudis86
WARN=-W -Wall -Wextra -std=c99 -pedantic
COMMON=output.c

all: readpe pedis fakeoep petls rva2ofs

readpe:
	gcc $(WARN) -I$(LIBPE) -L$(LIBPE) readpe.c $(COMMON) -o readpe -lpe
	
pedis:
	gcc $(WARN) -I$(LIBPE) -L$(LIBPE) -I$(LIBUDIS86) $(wildcard $(LIBUDIS86)/libudis86/*.c) pedis.c $(COMMON) -o pedis -lpe
	
fakeoep:
	gcc $(WARN) -I$(LIBPE) -L$(LIBPE) fakeoep.c $(COMMON) -o fakeoep -lpe

petls:
	gcc $(WARN) -I$(LIBPE) -L$(LIBPE) petls.c $(COMMON) -o petls -lpe

strpe:
	gcc $(WARN) -I$(LIBPE) -L$(LIBPE) strpe.c $(COMMON) -o strpe -lpe

rva2ofs:
	gcc $(WARN) -I$(LIBPE) -L$(LIBPE) rva2ofs.c $(COMMON) -o rva2ofs -lpe

clean:
	rm -f readpe pedis fakeoep petls strpe rva2ofs
