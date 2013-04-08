CC = cc
CFLAGS = -g -Wall
GLIB_INCLUDE  = $(shell pkg-config --cflags glib-2.0)
GLIB_LIB      = $(shell pkg-config --libs glib-2.0)
LIBS = -lccn -lcrypto -glib

PROGRAMS = troute publisher

all: $(PROGRAMS)

troute: troute.o
	$(CC) $(CFLAGS) -o $@ troute.o $(LIBS) $(GLIB_LIB)

publisher: publisher.o
	$(CC) $(CFLAGS) -o $@ publisher.o $(LIBS) $(GLIB_LIB)

clean:
	rm -f *.o
	rm -f $(PROGRAMS)

.c.o:
	$(CC) $(CFLAGS) $(GLIB_INCLUDE) -c $<

.PHONY: all clean
