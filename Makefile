CC = gcc
CFLAGS = -Wall -Wextra -std=c99

OBJS = heartbeat.o logger.o

all: heartbeat

heartbeat: $(OBJS)
	$(CC) $(CFLAGS) -o heartbeat $(OBJS)

heartbeat.o: heartbeat.c logger.h
logger.o: logger.c logger.h

clean:
	rm -f *.o heartbeat heartbeat_app_*.log
