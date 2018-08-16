all : arp_spoof

arp_spoof : main.o
	gcc -o arp_spoof main.o -lpcap

main.o : 
	gcc -c -o main.o main.c

clean :
	rm -f arp_spoof
	rm -f *.o
