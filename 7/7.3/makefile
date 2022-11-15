.SUFFIXES : .c .o 
CFLAGS = -O2 -g -lcrypto -lssl

OBJS = ecdsa.o eckey.o main.o util.o
SRCS = $(OBJS:.o=.c)
HFILES = common.h
EXE = a.out

exe : $(OBJS) $(HFILES)
		$(CC) -o $(EXE) $(OBJS) $(CFLAGS)

clean : 
	rm -rf $(EXE)
	rm -f privFile pubFile
	rm -f *.o core core.*
