in stage6, we added onion encyption to the communication between the hops. the hard part of this stage
was since we are dealing with encyption, it was deficult to check if the encryption data is correct.
a)Reused Code: I used the UDP communication code from here: (Marked in the code) https://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html - (1)
https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/ - (2)
http://www.binarytides.com/packet-sniffer-code-c-linux/ - (3)
https://stackoverflow.com/questions/13620607/creating-ip-network-packets - (4)
and countless stackoverflow and small forum topics that are to many to mintion, plus I take small hints.

b)Complete: Yes, works as intended. :)

