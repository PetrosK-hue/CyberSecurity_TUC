CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic 	

TARGET = monitor

all: monitor

monitor: monitor.c
	$(CC) $(CFLAGS) $(DBUG) monitor.c -o monitor -lpcap

run:
	./monitor -r test_pcap_5mins.pcap
clean:
	rm -f $(TARGET) *.o
