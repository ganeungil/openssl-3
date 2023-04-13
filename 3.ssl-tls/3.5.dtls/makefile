CC = gcc
CFLAGS = -lssl -lcrypto -pthread

CFILES = dtls-client.c
SFILES = dtls-server.c
AFILES = util.c
HFILES = common.h

CLIENT = client
SERVER = server

all : $(CLIENT) $(SERVER)

$(CLIENT) : $(CFILES) $(AFILES) $(HFILES)
	$(CC) -o $(CLIENT) $(CFILES) $(AFILES) $(CFLAGS)

$(SERVER) : $(SFILES) $(AFILES) $(HFILES)
	$(CC) -o $(SERVER) $(SFILES) $(AFILES) $(CFLAGS)

clean : 
	rm -rf $(CLIENT) $(SERVER)
	rm -f *.o core core.*
