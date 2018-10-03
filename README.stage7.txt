in stage7, I supported TCP connections along with the rigular ICMP connection, it took me a while to do.

a)Reused Code: I used the UDP communication code from here: (Marked in the code) https://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html - (1)
https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/ - (2)
http://www.binarytides.com/packet-sniffer-code-c-linux/ - (3)
https://stackoverflow.com/questions/13620607/creating-ip-network-packets - (4)
and countless stackoverflow and small forum topics that are to many to mintion, plus I take small hints.

b)Complete: Yes, works as intended. :)

c)What would happen to your TCP connection if the kernel's RST packets were not fltered out?

The connection would be reset since the kernal would think there is no active connection.

d) Why does the Linux kernel generate a RST packet for TCP, while it ignored ICMP and
UDP packets in prior stages?

Because TCP is conection orianted an the reset packet is usually created during the 3-way handshake.

