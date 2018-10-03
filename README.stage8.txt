in stage8, the code now supports multiple circuits as required from the document.

a)Reused Code: I used the UDP communication code from here: (Marked in the code) https://www.cs.rutgers.edu/~pxk/417/notes/sockets/udp.html - (1)
https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/ - (2)
http://www.binarytides.com/packet-sniffer-code-c-linux/ - (3)
https://stackoverflow.com/questions/13620607/creating-ip-network-packets - (4)
https://gist.github.com/tonious/1377667 - A quick hashtable implementation in c.
and countless stackoverflow and small forum topics that are to many to mintion, plus I take small hints.

b)Complete: Yes, works as intended. :)

c) In this stage we are careful to make sure all packets for a given ow take the same path.
What bad thing might happen if dierent packets from one ow took dierent paths
of dierent lengths?

Packets would arrive out-of-order or maybe parts of it would never arrive.

d) Continuing (c), suppose all paths were the same length and they were sent slowly (say,
one packet every millisecond), but each packet went over a dierent circuit. Would
the problem you identied in (c) be likely to occur in our simple test network on one
machine?

Yes. because maybe a router within one ciruit is down which will cause huge delay for the whole packet + you need to setup tcp connection for each packet.


e) Continuing (d), now suppose paths were the same length and packets were sent every
millisecond, but now Mantitor nodes were anywhere in the Internet, not all one test
machine. Now, would the problem you identied in (c) be likely?

Yes.
