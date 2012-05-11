LIBPE=../lib/libpe
LIBUDIS86=../lib/libudis86
WARN=-W -Wall -Wextra -std=c99 -pedantic
COMMON=xmalloc.c output.c

all: readpe pedis fakeoep

readpe:
	gcc $(WARN) -I$(LIBPE) -L$(LIBPE) readpe.c $(COMMON) -o readpe -lpe
	
pedis:
	gcc $(WARN) -I$(LIBPE) -L$(LIBPE) -I$(LIBUDIS86) $(wildcard $(LIBUDIS86)/libudis86/*.c) pedis.c $(COMMON) -o pedis -lpe
	
fakeoep:
	gcc $(WARN) -I$(LIBPE) -L$(LIBPE) fakeoep.c $(COMMON) -o fakeoep -lpe

clean:
	rm -f readpe pedis fakeoep
