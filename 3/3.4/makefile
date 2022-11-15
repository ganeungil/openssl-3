# Makefile
CC = gcc
CFLAGS = -lssl -lcrypto -pthread

CFILES = client2.c
SFILES = server2.c
AFILES = util.c
HFILES = common.h

CLIENT = client2
SERVER = server2

all : $(CLIENT) $(SERVER)

$(CLIENT) : $(CFILES) $(AFILES) $(HFILES)
	$(CC) -o $(CLIENT) $(CFILES) $(AFILES) $(CFLAGS)

$(SERVER) : $(SFILES) $(AFILES) $(HFILES)
	$(CC) -o $(SERVER) $(SFILES) $(AFILES) $(CFLAGS)

clean : 
	rm -rf $(CLIENT) $(SERVER)
	rm -f *.o core.* a.out
