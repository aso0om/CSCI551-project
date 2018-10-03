Stage4 is easy and straight forward with just small modification or stage3.

a)Reused Code: I used the UDP communication code from here: (Marked in the code) https://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html - (1)
https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/ - (2)
http://www.binarytides.com/packet-sniffer-code-c-linux/ - (3)
https://stackoverflow.com/questions/13620607/creating-ip-network-packets - (4)
and countless stackoverflow and small forum topics that are to many to mintion, plus I take small hints.

b)Complete: Yes, works as intended. :)

c)Router Selection:
	1- because each router has the same probability to receive traffic since we use mod over them.
	2- yes.
	3- when the pattern of the ip address lead to a router more than the others.

