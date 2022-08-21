CFLAGS=-g
LDLIBS=-lpcap

all: send-arp-spoofing-packet

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

ip.o: mac.h mac.cpp

iphdr.o : iphdr.h iphdr.cpp

icmphdr.o : icmphdr.h icmphdr.cpp

tcphdr.o : tcphdr.h tcphdr.cpp

udphdr.o : udphdr.h udphdr.cpp

send-arp-spoofing-packet : main.o arphdr.o ethhdr.o ip.o mac.o iphdr.o icmphdr.o tcphdr.o udphdr.o
	$(LINK.cc) -g $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpthread

clean:
	rm -f send-arp-test *.o
