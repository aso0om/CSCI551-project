CC = gcc
CFLAGS  = -Wall

default: projc

projc:  main.o misc.o aes.o hash.o
	$(CC) $(CFLAGS) -o projc main.o misc.o aes.o hash.o -lcrypto

main.o:  main.c main.h
	$(CC) $(CFLAGS) -c main.c -lcrypto

misc.o:  misc.c main.h
	$(CC) $(CFLAGS) -c misc.c -lcrypto

aes.o:  aes.c main.h
	$(CC) $(CFLAGS) -c aes.c -lcrypto

hash.o:  hash.c main.h
	$(CC) $(CFLAGS) -c hash.c -lcrypto
clean:
	$(RM) projc *.o *~ *.out
setup:
	sudo ip tuntap add dev tun1 mode tun
	sudo ifconfig tun1 10.5.51.2/24 up
	sudo ip rule add from 192.168.22.148 table 9 priority 8
	sudo ip route add table 9 to 18/8 dev tun1
	sudo ip route add table 9 to 128/8 dev tun1
	sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
	sudo ifconfig eth1 192.168.201.2/24 up
	sudo ifconfig eth2 192.168.202.2/24 up
	sudo ifconfig eth3 192.168.203.2/24 up
	sudo ifconfig eth4 192.168.204.2/24 up
edit:
	sudo gedit main.c 
