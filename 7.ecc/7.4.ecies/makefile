.SUFFIXES : .c .o 
CFLAGS = -O2 -g -lcrypto -lssl

OBJS = crypto.o util.o main.o
SRCS = $(OBJS:.o=.c)
HFILES = common.h
EXE = a.out

exe : $(OBJS) $(HFILES)
		$(CC) -o $(EXE) $(OBJS) $(CFLAGS)

clean : 
	rm -rf $(EXE)
	rm -f *.o core core.*
